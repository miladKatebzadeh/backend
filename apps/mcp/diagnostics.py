import json
import logging
import os
import re
import threading
import uuid
from contextlib import contextmanager

import requests

from django.db.models import Q
from django.utils import timezone
from django.utils.text import slugify

from apps.collector.models import DockerMetric, JenkinsBuild, PrometheusAlert
from apps.knowledge.retrieval import retrieve_runbooks
from apps.mcp.models import MCPTool, get_setting
from apps.mcp.runtime import MCPSandboxExecutor

logger = logging.getLogger(__name__)

_laya_model = None
_laya_checked = False
_langfuse = None
_langfuse_checked = False
_langfuse_signature = None

_langfuse_lock = threading.Lock()

_laya_lock = threading.Lock()
_laya_loading = False


class _TimedOut:
    pass


def _within(fn, seconds):
    box = {}

    def run():
        try:
            box['value'] = fn()
        except Exception as exc:
            box['error'] = exc

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        return _TimedOut
    if 'error' in box:
        raise box['error']
    return box.get('value')


def get_laya():
    """Return the router loaded at startup. Never imports or checks Laya during a diagnosis."""
    if _laya_checked:
        return _laya_model
    return None


def _laya_timeout():
    try:
        return float(os.getenv('OPSHUB_LAYA_TIMEOUT', '12') or 12)
    except ValueError:
        return 12


def _retire_laya(reason):
    """Drop Laya for the rest of this process. Later messages must not wait on it again."""
    global _laya_model, _laya_checked, _laya_loading
    with _laya_lock:
        _laya_model = None
        _laya_checked = True
        _laya_loading = False
    logger.warning('%s Keyword routing will be used.', reason)


def _probe_laya(model):
    """Warm both English and Persian routing checkpoints before enabling Laya."""
    predict = getattr(model, 'predict', None)
    if not callable(predict):
        return model

    probes = (
        ('English', 'ping'),
        ('Persian', 'این یک پیام آزمایشی برای تشخیص نوع مشکل زیرساختی است.'),
    )
    for language, message in probes:
        state = {'message': message, 'snapshot': ''}
        try:
            result = _within(lambda: predict(state, LAYA_QUESTIONS), _laya_timeout())
        except Exception:
            logger.exception('Laya %s startup probe failed', language)
            return None
        if result is _TimedOut:
            logger.warning('Laya %s startup probe timed out.', language)
            return None
        if not isinstance(result, dict):
            logger.warning('Laya %s startup probe returned an invalid response.', language)
            return None
    return model


def warmup_laya():
    """Load Laya once, when the process starts, and prove it can answer before any user waits."""
    global _laya_model, _laya_checked, _laya_loading
    if os.getenv('OPSHUB_DISABLE_LAYA', '').strip().lower() in ('1', 'true', 'yes', 'on'):
        logger.info('Laya disabled by OPSHUB_DISABLE_LAYA.')
        _laya_checked = True
        _laya_model = None
        return
    with _laya_lock:
        if _laya_checked or _laya_loading:
            return
        _laya_loading = True
    logger.info('Laya warmup started.')
    model = None
    try:
        from laya import Router
        preload = os.getenv('LAYA_PRELOAD', '').strip().lower() in ('1', 'true', 'yes', 'on')
        model = Router(preload=preload)
        model = _probe_laya(model)
        if model is None:
            logger.warning('Laya did not answer during startup; keyword routing will be used.')
        else:
            logger.info('Laya warmup finished.')
    except Exception:
        logger.exception('Laya router is unavailable; keyword routing will be used.')
        model = None
    with _laya_lock:
        _laya_model = model
        _laya_checked = True
        _laya_loading = False


def reset_langfuse():
    global _langfuse, _langfuse_checked, _langfuse_signature
    with _langfuse_lock:
        _langfuse = None
        _langfuse_checked = False
        _langfuse_signature = None


def _langfuse_config():
    public = get_setting('langfuse_public_key', os.getenv('LANGFUSE_PUBLIC_KEY', ''))
    secret = get_setting('langfuse_secret_key', os.getenv('LANGFUSE_SECRET_KEY', ''))
    host = get_setting(
        'langfuse_base_url',
        os.getenv('LANGFUSE_BASE_URL') or os.getenv('LANGFUSE_HOST') or 'http://127.0.0.1:3030',
    )
    return str(public or '').strip(), str(secret or '').strip(), str(host or '').strip().rstrip('/')


def get_langfuse():
    global _langfuse, _langfuse_checked, _langfuse_signature

    signature = _langfuse_config()
    if _langfuse_checked and _langfuse_signature == signature:
        return _langfuse

    with _langfuse_lock:
        signature = _langfuse_config()
        if _langfuse_checked and _langfuse_signature == signature:
            return _langfuse
        _langfuse_signature = signature
        public, secret, host = signature
        if not secret or not public:
            logger.warning('Langfuse credentials missing')
            _langfuse = None
        else:
            _langfuse = _LangfuseTarget(public, secret, host)
            logger.info('Langfuse ingestion target: %s', host)
        _langfuse_checked = True

    return _langfuse


class _LangfuseTarget:
    def __init__(self, public_key, secret_key, base_url):
        self.public_key = public_key
        self.secret_key = secret_key
        self.base_url = base_url.rstrip('/')


class _Observation:
    def __init__(self, name, payload, kind='span', model=None):
        self.id = str(uuid.uuid4())
        self.name = name
        self.input = payload
        self.output = None
        self.kind = kind
        self.model = model
        self.start = timezone.now()
        self.ended_at = None

    def update(self, **kwargs):
        if 'output' in kwargs:
            self.output = kwargs['output']
        if 'input' in kwargs:
            self.input = kwargs['input']

    def update_trace(self, **kwargs):
        self.update(**kwargs)

    def end(self):
        if self.ended_at is None:
            self.ended_at = timezone.now()


class _Trace(_Observation):
    def __init__(self, name, payload):
        super().__init__(name, payload, kind='trace')
        self.children = []


def _open_trace(langfuse, name, payload):
    if langfuse is None:
        return None
    trace = _Trace(name, payload)
    return {'span': trace, 'client': langfuse}


def _iso(value):
    return value.isoformat()


def _ingestion_event(kind, body):
    return {
        'id': str(uuid.uuid4()),
        'type': kind,
        'timestamp': _iso(timezone.now()),
        'body': body,
    }


def _flush_ingestion(client, trace):
    if client is None or trace is None:
        return
    batch = [_ingestion_event('trace-create', {
        'id': trace.id,
        'timestamp': _iso(trace.start),
        'name': trace.name,
        'input': trace.input,
        'output': trace.output,
    })]
    for child in trace.children:
        child.end()
        body = {
            'id': child.id,
            'traceId': trace.id,
            'name': child.name,
            'startTime': _iso(child.start),
            'endTime': _iso(child.ended_at or child.start),
            'input': child.input,
            'output': child.output,
        }
        event_type = 'span-create'
        if child.kind == 'generation':
            event_type = 'generation-create'
            if child.model:
                body['model'] = child.model
        batch.append(_ingestion_event(event_type, body))
    try:
        response = requests.post(
            f'{client.base_url}/api/public/ingestion',
            json={'batch': batch},
            auth=(client.public_key, client.secret_key),
            timeout=4,
            allow_redirects=False,
        )
    except Exception:
        logger.exception('Langfuse ingestion failed')
        return
    if response.status_code in (401, 403):
        logger.warning('Langfuse rejected the trace keys.')
        return
    if response.status_code >= 400:
        logger.warning('Langfuse ingestion failed: %s %s', response.status_code, (response.text or '')[:200])
        return
    try:
        payload = response.json() if response.content else {}
    except ValueError:
        return
    errors = payload.get('errors') if isinstance(payload, dict) else None
    if errors:
        logger.warning('Langfuse ingestion rejected part of the trace: %s', str(errors)[:300])


def _close_trace(handle, output):
    if not handle:
        return
    trace = handle['span']
    try:
        trace.update_trace(output=output)
        trace.end()
    except Exception:
        logger.exception('Langfuse trace update failed')
    _flush_ingestion(handle.get('client'), trace)


def _compact(value, limit=1500):
    if isinstance(value, str):
        return value[:limit]
    try:
        text = json.dumps(value, default=str)
    except TypeError:
        text = str(value)
    if len(text) <= limit:
        return value
    return text[:limit]


@contextmanager
def _child_span(langfuse, name, payload, as_type='span', model=None, parent=None):
    trace = parent if isinstance(parent, _Trace) else None
    if trace is None or langfuse is None:
        yield None
        return
    observation = _Observation(
        name,
        _compact(payload),
        kind='generation' if as_type == 'generation' else 'span',
        model=model,
    )
    trace.children.append(observation)
    try:
        yield observation
    finally:
        try:
            observation.end()
        except Exception:
            logger.exception('Langfuse child span close failed: %s', name)


def _set_output(span, output):
    if span is None:
        return
    payload = _compact(output, 8000)
    try:
        if hasattr(span, 'update'):
            span.update(input=payload, output=payload)
    except TypeError:
        try:
            span.update(output=payload)
        except Exception:
            logger.exception('Langfuse child update failed')
    except Exception:
        logger.exception('Langfuse child update failed')



ROUTING_KEYWORDS = {
    'ci_failure': (
        'jenkins', 'build', 'pipeline', 'compile', 'workflow', 'ci',
        'جنکینز', 'بیلد', 'پایپ لاین', 'خط لوله', 'کامپایل', 'فرایند ساخت',
    ),
    'metric_anomaly': (
        'cpu', 'memory', 'ram', 'prometheus', 'metric', 'disk', 'latency',
        'حافظه', 'رم', 'پردازنده', 'دیسک', 'فضای دیسک', 'پرومتئوس', 'متریک',
    ),
    'container_runtime': (
        'docker', 'container', 'crash', 'restart', 'restarted', 'restarting',
        'exited', 'oom', 'killed', 'کانتینر', 'داکر', 'کرش', 'ریستارت',
        'متوقف شد', 'خارج شد', 'کشته شد',
    ),
    'deployment_regression': (
        'deploy', 'deployed', 'deployment', 'release', 'rollout', 'commit',
        'استقرار', 'انتشار', 'رول اوت', 'نسخه جدید', 'کامیت', 'دیپلوی',
    ),
}

_FAMILY_FLAGS = {
    'ci_failure': 'need_ci_logs',
    'metric_anomaly': 'need_metric_window',
    'container_runtime': 'need_container_events',
    'deployment_regression': 'need_deployment_changes',
}
_FAMILY_ALIASES = {
    'ci': 'ci_failure',
    'jenkins': 'ci_failure',
    'pipeline_failure': 'ci_failure',
    'metric': 'metric_anomaly',
    'metrics': 'metric_anomaly',
    'container': 'container_runtime',
    'docker': 'container_runtime',
    'deployment': 'deployment_regression',
    'deploy': 'deployment_regression',
    'release': 'deployment_regression',
    'rollout': 'deployment_regression',
}


def _normalise_routing_text(value):
    text = str(value or '').lower()
    text = text.replace('ي', 'ی').replace('ك', 'ک').replace('\u200c', ' ')
    return re.sub(r'\s+', ' ', text).strip()


def _contains_routing_keyword(text, keyword):
    if keyword.isascii() and keyword.isalnum():
        return re.search(rf'(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])', text) is not None
    return keyword in text


def _canonical_family(value):
    family = re.sub(r'[\s-]+', '_', str(value or '').strip().lower())
    family = _FAMILY_ALIASES.get(family, family)
    return family if family in (*_FAMILY_FLAGS.keys(), 'unknown') else 'unknown'


def keyword_decisions(user_message: str) -> dict:
    text = _normalise_routing_text(user_message)
    scores = {
        family: sum(1 for keyword in keywords if _contains_routing_keyword(text, keyword))
        for family, keywords in ROUTING_KEYWORDS.items()
    }
    decisions = {
        'incident_family': 'unknown',
        'need_ci_logs': scores['ci_failure'] > 0,
        'need_metric_window': scores['metric_anomaly'] > 0,
        'need_container_events': scores['container_runtime'] > 0,
        'need_deployment_changes': scores['deployment_regression'] > 0,
        'need_runbook_search': True,
    }

    ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    if ranked and ranked[0][1] > 0:
        second_score = ranked[1][1] if len(ranked) > 1 else 0
        if ranked[0][1] > second_score:
            decisions['incident_family'] = ranked[0][0]
    return align_section(decisions)


LAYA_QUESTIONS = {
    'incident_family': {
        'type': 'choice',
        'instructions': (
            'Choose exactly one infrastructure family using the user message and supplied snapshot. '
            'Use unknown when the evidence is insufficient, mixed, or does not fit a listed family. '
            'Do not guess a family merely because one is common.'
        ),
        'criteria': {
            'ci_failure': 'Jenkins, CI job, build, compile, workflow, or pipeline failure; for example بیلد جنکینز شکست خورد',
            'metric_anomaly': 'CPU, memory/RAM, disk, latency, or Prometheus metric anomaly; for example مصرف CPU بالا است',
            'container_runtime': 'Docker/container crash, restart, OOM kill, or exit; for example کانتینر متوقف شد',
            'deployment_regression': 'A regression after deploy, release, rollout, or commit; for example بعد از استقرار نسخه جدید سرویس خراب شد',
            'unknown': 'Insufficient or conflicting evidence, or a problem outside the listed infrastructure families',
        },
    },
    'need_ci_logs': {
        'type': 'noul',
        'instructions': 'Return true only when Jenkins, CI, build, compile, workflow, or pipeline logs are relevant to this incident. Otherwise return false.',
    },
    'need_metric_window': {
        'type': 'noul',
        'instructions': 'Return true only when CPU, memory, disk, latency, Prometheus, or host metric evidence is relevant. Otherwise return false.',
    },
    'need_container_events': {
        'type': 'noul',
        'instructions': 'Return true only when Docker/container state, lifecycle events, restarts, OOM kills, or container logs are relevant. Otherwise return false.',
    },
    'need_deployment_changes': {
        'type': 'noul',
        'instructions': 'Return true only when deploy, release, rollout, commit, or version-change evidence is relevant. Otherwise return false.',
    },
    'need_runbook_search': {
        'type': 'noul',
        'instructions': 'Runbook retrieval is always enabled by the application; return true.',
    },
}


def _laya_confidence_threshold():
    default = 0.35
    try:
        threshold = float(os.getenv('OPSHUB_LAYA_CONFIDENCE_THRESHOLD', str(default)))
    except (TypeError, ValueError):
        return default
    return threshold if 0.0 <= threshold <= 1.0 else default


def _laya_boolean(target, threshold):
    true_values = ('true', 'yes', '1')
    false_values = ('false', 'no', '0', 'none', '')
    if isinstance(target, dict):
        choice = target.get('choice')
        if isinstance(choice, bool):
            return choice
        if choice is not None:
            choice_text = str(choice).strip().lower()
            if choice_text in true_values:
                return True
            if choice_text in false_values:
                return False
        raw = target.get('noul', target.get('probability_true', target.get('probability')))
    else:
        if isinstance(target, bool):
            return target
        raw = target

    if isinstance(raw, str):
        raw_text = raw.strip().lower()
        if raw_text in true_values:
            return True
        if raw_text in false_values:
            return False
    try:
        probability = float(raw)
    except (TypeError, ValueError):
        return False
    return 0.0 <= probability <= 1.0 and probability >= threshold


def route(user_message: str, context: dict) -> dict:
    model = get_laya()
    if model is None:
        decisions = keyword_decisions(user_message)
        decisions['router'] = 'keywords'
        return decisions

    state = {
        'message': user_message,
        'snapshot': context.get('fleet_anomaly_snapshot', '') if isinstance(context, dict) else '',
    }
    try:
        result = _within(lambda: model.predict(state, LAYA_QUESTIONS), _laya_timeout())
    except Exception:
        logger.exception('Laya routing failed')
        result = None
    if result is _TimedOut or not isinstance(result, dict):
        _retire_laya('Laya predict timed out.' if result is _TimedOut else 'Laya routing failed.')
        decisions = keyword_decisions(user_message)
        decisions['router'] = 'keywords'
        return decisions

    answers = result.get('answers')
    if not isinstance(answers, dict):
        answers = result

    family = answers.get('incident_family', {})
    if isinstance(family, dict):
        family = family.get('choice', 'unknown')
    decisions = {
        'router': 'laya',
        'incident_family': _canonical_family(family),
        'need_ci_logs': _laya_boolean(answers.get('need_ci_logs'), _laya_confidence_threshold()),
        'need_metric_window': _laya_boolean(answers.get('need_metric_window'), _laya_confidence_threshold()),
        'need_container_events': _laya_boolean(answers.get('need_container_events'), _laya_confidence_threshold()),
        'need_deployment_changes': _laya_boolean(answers.get('need_deployment_changes'), _laya_confidence_threshold()),
        'need_runbook_search': True,
    }
    routing = result.get('routing')
    if isinstance(routing, dict) and routing.get('model'):
        decisions['laya_model'] = str(routing['model'])
    return align_section(decisions)


def align_section(decisions):
    """Align the selected family with the evidence section that must be gathered."""
    family = _canonical_family(decisions.get('incident_family'))
    decisions['incident_family'] = family
    section_flag = _FAMILY_FLAGS.get(family)
    if section_flag:
        decisions[section_flag] = True
    decisions['need_runbook_search'] = True
    return decisions


def runbook_query(decisions, message):
    family = str(decisions.get('incident_family') or 'unknown').replace('_', ' ')
    return f'{family} {message}'.strip()


def _stamp(value):
    if value is None:
        return ''
    return value.isoformat()


def _log_excerpt(text, limit=1200):
    lines = (text or '').splitlines()
    interesting = [
        line for line in lines
        if any(word in line.lower() for word in ('error', 'exception', 'fatal', 'fail', 'oom', 'traceback'))
    ]
    chosen = interesting[-8:] or lines[-12:]
    return '\n'.join(chosen)[-limit:]


def _recent(queryset, time_field, limit=5):
    from datetime import timedelta
    cutoff = timezone.now() - timedelta(hours=6)
    recent = queryset.filter(**{f'{time_field}__gte': cutoff}).order_by(f'-{time_field}')
    if recent.exists():
        return list(recent[:limit])
    return list(queryset.order_by('-id')[:limit])


def gather(decisions: dict) -> dict:
    payload = {}
    if decisions.get('need_container_events'):
        payload['container_telemetry'] = [
            {
                'container': row.container_name,
                'status': row.status,
                'cpu_percent': row.cpu_percent,
                'mem_usage_mb': row.mem_usage_mb,
                'restart_count': row.restart_count,
                'timestamp': _stamp(row.timestamp),
                'log_excerpt': _log_excerpt(row.container_logs),
            }
            for row in _recent(DockerMetric.objects.all(), 'timestamp')
        ]
    if decisions.get('need_metric_window'):
        rows = _recent(PrometheusAlert.objects.exclude(alert_status='NORMAL'), 'updated_at')
        if not rows:
            rows = _recent(PrometheusAlert.objects.all(), 'updated_at', limit=2)
        payload['metric_window_anomalies'] = [
            {
                'metric': row.metric_name,
                'value': row.value,
                'status': row.alert_status,
                'type': row.metric_type,
                'updated_at': _stamp(row.updated_at),
            }
            for row in rows
        ]
    if decisions.get('need_ci_logs'):
        payload['ci_pipeline_logs'] = [
            {
                'job': row.job_name,
                'build': row.build_number,
                'result': row.result,
                'duration_ms': row.duration_ms,
                'updated_at': _stamp(row.updated_at),
                'log_excerpt': _log_excerpt(row.console_output),
            }
            for row in _recent(JenkinsBuild.objects.all(), 'updated_at', limit=3)
        ]
    if decisions.get('need_deployment_changes'):
        payload['deployment_changes'] = [
            {
                'job': row.job_name,
                'build': row.build_number,
                'result': row.result,
                'updated_at': _stamp(row.updated_at),
            }
            for row in _recent(JenkinsBuild.objects.all(), 'updated_at')
        ]
    return payload


def retrieve(query: str, decisions=None, limit=3) -> dict:
    """Retrieve relevant runbook chunks and report their provenance."""
    decisions = decisions if isinstance(decisions, dict) else {}
    return retrieve_runbooks(
        query,
        incident_family=decisions.get('incident_family'),
        limit=limit,
    )


def _model_evidence(evidence):
    compact = {}
    for key, rows in evidence.items():
        if not isinstance(rows, list):
            compact[key] = rows
            continue
        shortened = []
        for row in rows[:3]:
            if isinstance(row, dict) and 'log_excerpt' in row:
                row = {**row, 'log_excerpt': str(row['log_excerpt'])[:300]}
            shortened.append(row)
        compact[key] = shortened
    return compact


def _chat(host: str, model: str, system_prompt: str, user_message: str) -> str:
    import ollama
    timeout = float(os.getenv('OPSHUB_OLLAMA_TIMEOUT', '180') or 180)
    num_ctx = int(os.getenv('OPSHUB_OLLAMA_NUM_CTX', '4096') or 4096)
    try:
        client = ollama.Client(host=host, timeout=timeout)
    except TypeError:
        client = ollama.Client(host=host)
    result = client.chat(
        model=model,
        format='json',
        options={'temperature': 0, 'num_ctx': num_ctx},
        messages=[
            {'role': 'system', 'content': system_prompt},
            {'role': 'user', 'content': user_message},
        ],
    )
    return result['message']['content']


def _parse_diagnosis(reply_text):
    try:
        payload = json.loads(reply_text)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if not isinstance(payload.get('incident_detected'), bool):
        return None
    if not isinstance(payload.get('error_scope'), str) or not payload['error_scope'].strip():
        return None
    if not isinstance(payload.get('diagnostic_report'), str) or not payload['diagnostic_report'].strip():
        return None
    refs = payload.get('evidence_refs')
    payload['evidence_refs'] = [str(item) for item in refs if str(item).strip()] if isinstance(refs, list) else []
    if 'tool_name' in payload and not isinstance(payload.get('tool_name'), str):
        return None
    if 'tool_target' in payload and not isinstance(payload.get('tool_target'), str):
        return None
    if isinstance(payload.get('tool_name'), str):
        payload['tool_name'] = payload['tool_name'].strip()
    if isinstance(payload.get('tool_target'), str):
        payload['tool_target'] = payload['tool_target'].strip()
    payload['engine_status'] = 'ok'
    return payload


def _invalid_diagnosis():
    return json.dumps({
        'incident_detected': False,
        'error_scope': 'engine',
        'engine_status': 'invalid',
        'diagnostic_report': 'The model did not return a usable diagnosis.',
        'evidence_refs': [],
    })


def active_tool_catalog():
    catalog = []
    try:
        rows = (
            MCPTool.objects.filter(status='active', archived_at__isnull=True)
            .exclude(code='')
            .order_by('name')[:40]
        )
    except Exception:
        logger.exception('tool catalog failed')
        return []
    for tool in rows:
        catalog.append({'name': tool.name, 'description': (tool.description or '').strip()[:400]})
    return catalog


def _active_tools():
    return MCPTool.objects.filter(status='active', archived_at__isnull=True).exclude(code='')


def maybe_execute(reply_text: str, decisions: dict) -> dict:
    meta = {
        'agent_triggered': False,
        'sandbox_output': None,
        'target': '',
        'resolved': False,
        'checked': None,
        'proof': 'not rechecked',
    }
    try:
        parsed = json.loads(reply_text)
    except (TypeError, json.JSONDecodeError):
        meta['error'] = 'reply was not json'
        return meta
    if not isinstance(parsed, dict) or parsed.get('engine_status') == 'offline' or not parsed.get('incident_detected'):
        return meta
    scope = str(parsed.get('error_scope') or '').strip()
    target = str(parsed.get('tool_target') or '').strip() or scope
    meta['target'] = target
    tools = _active_tools()
    if 'tool_name' in parsed:
        chosen = str(parsed.get('tool_name') or '').strip()
        meta['chosen_tool'] = chosen
        if not chosen:
            meta['error'] = 'model chose no tool'
            return meta
        tool = tools.filter(name=chosen).first()
        if tool is None:
            meta['error'] = 'model chose a tool that is not active'
            return meta
    else:
        if not scope or scope.lower() in ('none', 'engine'):
            return meta
        needle = slugify(scope).replace('-', '_')
        tool = tools.filter(name__iexact=needle).first() if needle else None
        if tool is None and len(needle) >= 3:
            tool = tools.filter(name__icontains=needle).first()
        if tool is None and decisions.get('incident_family') == 'container_runtime':
            tool = tools.filter(Q(name='docker_container_restarter') | Q(name='restart_container')).first()
        if tool is None:
            meta['error'] = 'no matching active tool'
            return meta
    if not target or target.lower() in ('none', 'engine'):
        meta['error'] = 'no target'
        return meta
    meta['agent_triggered'] = True
    meta['matched_tool'] = tool.name
    meta['sandbox_output'] = MCPSandboxExecutor.execute_tool_safe(tool.code, {'TARGET_RESOURCE': target})
    return meta


def _confirm_recovery(agent, decisions):
    agent['resolved'] = False
    agent['proof'] = 'not rechecked'
    if not agent.get('agent_triggered'):
        return
    output = agent.get('sandbox_output') or {}
    if not output.get('success'):
        agent['proof'] = 'tool failed'
        return
    tool_name = str(agent.get('matched_tool') or '')
    containerish = decisions.get('incident_family') == 'container_runtime' or any(
        word in tool_name for word in ('container', 'docker', 'restart')
    )
    if not containerish:
        return
    from apps.collector.tasks import container_state
    state = container_state(agent.get('target') or '')
    agent['checked'] = state
    agent['proof'] = 'container state'
    agent['resolved'] = state == 'running'


def diagnose(user_message: str, allow_remediation: bool = False) -> dict:
    user_message = (user_message or '').strip()
    if not user_message:
        return {'reply': '', 'engine_status': 'error', 'agent_automation': {'agent_triggered': False}, 'detail': 'empty'}

    ollama_host = get_setting('ollama_host', os.getenv('OLLAMA_HOST', 'http://localhost:11434'))
    target_model = get_setting('ollama_model', os.getenv('OLLAMA_MODEL', 'qwen2.5-coder:7b'))
    container_summary = 'All Running'
    try:
        crashed = list(DockerMetric.objects.exclude(status='running').order_by('-id')[:2])
        if crashed:
            container_summary = ', '.join(f'{row.container_name}:{row.status}' for row in crashed)
    except Exception:
        logger.exception('container summary failed')

    context = {
        'error_raw_prompt': user_message,
        'timestamp': str(timezone.now()),
        'fleet_anomaly_snapshot': container_summary,
    }
    langfuse = get_langfuse()
    handle = _open_trace(langfuse, 'hierarchical_diagnostic_routing', {'incident_raw': user_message})
    parent = handle['span'] if handle else None
    decisions = {}
    evidence = {}
    documents = []
    retrieval = {'results': [], 'source': 'none', 'candidate_count': 0, 'filters': []}
    query = ''
    route_view = {}
    engine_status = 'ok'
    reply_text = ''
    agent = {'agent_triggered': False, 'sandbox_output': None}
    try:
        with _child_span(langfuse, 'laya', {'message': user_message, 'snapshot': container_summary}, parent=parent) as laya_span:
            decisions = route(user_message, context)
            route_view = {
                'router': decisions.get('router', 'keywords'),
                'laya_model': decisions.get('laya_model', ''),
                'incident_family': decisions.get('incident_family', 'unknown'),
                'need_ci_logs': bool(decisions.get('need_ci_logs')),
                'need_metric_window': bool(decisions.get('need_metric_window')),
                'need_container_events': bool(decisions.get('need_container_events')),
                'need_deployment_changes': bool(decisions.get('need_deployment_changes')),
                'need_runbook_search': bool(decisions.get('need_runbook_search')),
            }
            _set_output(laya_span, route_view)
        query = runbook_query(decisions, user_message)
        with _child_span(langfuse, 'runbook_retrieval', {
            'query': query,
            'section': decisions.get('incident_family', 'unknown'),
        }, parent=parent) as retrieval_span:
            retrieval = retrieve(query, decisions)
            hits = retrieval.get('results', [])
            documents = [hit['text'] for hit in hits]
            _set_output(retrieval_span, {
                'section': decisions.get('incident_family', 'unknown'),
                'query': query,
                'retrieval_source': retrieval.get('source'),
                'candidate_count': retrieval.get('candidate_count'),
                'filters': retrieval.get('filters'),
                'hits': [
                    {
                        'title': hit.get('title'),
                        'document_id': hit.get('document_id'),
                        'section': hit.get('section'),
                        'component': hit.get('component'),
                        'chunk': hit.get('chunk'),
                        'distance': hit.get('distance'),
                        'lexical_score': hit.get('lexical_score'),
                        'relevance_score': hit.get('relevance_score'),
                        'matched_terms': hit.get('matched_terms'),
                        'retrieval_source': hit.get('retrieval_source'),
                    }
                    for hit in hits
                ],
                'runbooks': [_compact(document, 1000) for document in documents[:3]],
            })
        try:
            with _child_span(langfuse, 'telemetry', {'route': route_view}, parent=parent) as telemetry_span:
                evidence = gather(decisions)
                _set_output(telemetry_span, {
                    key: len(value) for key, value in evidence.items() if isinstance(value, list)
                })
        except Exception:
            logger.exception('evidence query failed')
            evidence = {}
        catalog = active_tool_catalog()
        packet = _compact(f"""ERROR:
{user_message}

ERROR DETAILS:
{json.dumps(_model_evidence(evidence))}

LAYA:
{json.dumps(route_view)}

RUNBOOK:
{chr(10).join(documents) if documents else 'No runbook found.'}

TOOLS:
{json.dumps(catalog) if catalog else 'No active tools.'}
""", 5000)
        packet += "\n\nReturn only JSON with keys incident_detected, error_scope, diagnostic_report, evidence_refs, engine_status, tool_name, tool_target."
        system_prompt = """
You are the Revive diagnostics engine.
The user message has the error, the section chosen by routing, the runbook, and the active tools.
Use only those. If a claim is not supported by them, say you do not know.
RUNBOOK entries are ranked candidates, not proof by themselves. Use a runbook only when its actual symptom, component, and failure mechanism match this incident. A shared platform name such as Docker is not enough to make a runbook relevant. If no retrieved runbook addresses the reported symptom, state that runbook evidence is insufficient.
Choose at most one tool. tool_name must be an exact name from TOOLS, or an empty string if none should run.
tool_target is the resource that tool should act on, copied from the error, or an empty string.
Do not invent a tool name. Do not claim a tool has already run.
Return only JSON with keys incident_detected (boolean), error_scope (string), diagnostic_report (string), evidence_refs (array of short strings copied from the error or runbook labels), engine_status (string, use "ok"), tool_name (string), tool_target (string).
"""
        retry_prompt = system_prompt + '\nThe previous reply was rejected. Return only the JSON object.'
        try:
            with _child_span(langfuse, 'llm', {'packet': _compact(packet, 1500)}, as_type='generation', model=target_model, parent=parent) as llm_span:
                reply_text = _chat(ollama_host, target_model, system_prompt, packet)
                _set_output(llm_span, {'reply': reply_text})
        except Exception as exc:
            engine_status = 'offline'
            reply_text = json.dumps({
                'incident_detected': False,
                'error_scope': 'engine',
                'engine_status': 'offline',
                'diagnostic_report': f'Ollama at {ollama_host} did not return a diagnosis ({exc.__class__.__name__}).',
                'evidence_refs': [],
            })
        if engine_status == 'ok':
            parsed = _parse_diagnosis(reply_text)
            if parsed is None:
                try:
                    with _child_span(langfuse, 'llm_retry', {'packet': _compact(packet, 1500)}, as_type='generation', model=target_model, parent=parent) as retry_span:
                        reply_text = _chat(ollama_host, target_model, retry_prompt, packet)
                        _set_output(retry_span, {'reply': reply_text})
                    parsed = _parse_diagnosis(reply_text)
                except Exception:
                    logger.exception('diagnosis retry failed')
                    parsed = None
            if parsed is None:
                engine_status = 'invalid'
                reply_text = _invalid_diagnosis()
            else:
                reply_text = json.dumps(parsed)
        if allow_remediation and engine_status == 'ok':
            agent = maybe_execute(reply_text, decisions)
            _confirm_recovery(agent, decisions)
    finally:
        _close_trace(handle, {
            'engine_status': engine_status,
            'laya': route_view,
            'runbook_retrieval': {
                'query': query,
                'retrieval_source': retrieval.get('source'),
                'candidate_count': retrieval.get('candidate_count'),
                'filters': retrieval.get('filters'),
                'hits': [
                    {
                        'title': hit.get('title'),
                        'document_id': hit.get('document_id'),
                        'section': hit.get('section'),
                        'component': hit.get('component'),
                        'distance': hit.get('distance'),
                        'lexical_score': hit.get('lexical_score'),
                        'relevance_score': hit.get('relevance_score'),
                        'matched_terms': hit.get('matched_terms'),
                        'retrieval_source': hit.get('retrieval_source'),
                    }
                    for hit in retrieval.get('results', [])
                ],
                'runbooks': [_compact(document, 1000) for document in documents[:3]],
            },
            'reply': _compact(reply_text, 4000),
        })
    return {'reply': reply_text, 'engine_status': engine_status, 'agent_automation': agent, 'decisions': decisions}


def monitor_incident_daemon():
    from datetime import timedelta

    auto = str(get_setting('auto_remediate', '0')).lower() in ('1', 'true', 'yes', 'on')
    cutoff = timezone.now() - timedelta(minutes=10)
    docker_row = None
    jenkins_row = None
    try:
        recent = DockerMetric.objects.filter(last_attempt_at__gte=cutoff)
        docker_row = (
            DockerMetric.objects.exclude(status='running')
            .filter(remediation_attempted=False)
            .exclude(pk__in=recent.values('pk'))
            .order_by('-id')
            .first()
        )
        if docker_row is None:
            jenkins_recent = JenkinsBuild.objects.filter(last_attempt_at__gte=cutoff)
            jenkins_row = (
                JenkinsBuild.objects.filter(result__in=('FAILURE', 'UNSTABLE', 'ABORTED'), remediation_attempted=False)
                .exclude(pk__in=jenkins_recent.values('pk'))
                .order_by('-id')
                .first()
            )
    except Exception:
        logger.exception('incident query failed')
        return None
    if docker_row is None and jenkins_row is None:
        return None
    if docker_row is not None:
        message = f"System Alert: Container '{docker_row.container_name}' status is '{docker_row.status}'."
    else:
        message = (
            f"System Alert: Jenkins job '{jenkins_row.job_name}' build #{jenkins_row.build_number} "
            f"terminated with status '{jenkins_row.result}'."
        )
    result = diagnose(message, allow_remediation=auto)
    now = timezone.now()
    agent = result.get('agent_automation') or {}
    if docker_row is not None:
        docker_row.last_attempt_at = now
        if result.get('engine_status') == 'ok':
            docker_row.remediation_attempted = True
        state = None
        if agent.get('agent_triggered'):
            from apps.collector.tasks import container_state
            state = container_state(docker_row.container_name)
        docker_row.resolved = state == 'running'
        docker_row.save(update_fields=['last_attempt_at', 'remediation_attempted', 'resolved'])
    if jenkins_row is not None:
        jenkins_row.last_attempt_at = now
        if result.get('engine_status') == 'ok':
            jenkins_row.remediation_attempted = True
        jenkins_row.save(update_fields=['last_attempt_at', 'remediation_attempted'])
    return result
