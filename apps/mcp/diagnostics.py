import json
import logging
import os
import threading
from contextlib import contextmanager

from django.db.models import Q
from django.utils import timezone
from django.utils.text import slugify

from apps.collector.models import DockerMetric, JenkinsBuild, PrometheusAlert
from apps.knowledge.chroma import get_chroma_collection
from apps.mcp.models import MCPTool, get_setting
from apps.mcp.runtime import MCPSandboxExecutor

logger = logging.getLogger(__name__)

_laya_model = None
_laya_checked = False
_langfuse = None
_langfuse_checked = False

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


def warmup_laya():
    """Load Laya once, when the process starts."""
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
        logger.info('Laya warmup finished.')
    except Exception:
        logger.exception('Laya router is unavailable; keyword routing will be used.')
    with _laya_lock:
        _laya_model = model
        _laya_checked = True
        _laya_loading = False


def get_langfuse():
    global _langfuse, _langfuse_checked

    if _langfuse_checked:
        return _langfuse

    with _langfuse_lock:
        if _langfuse_checked:
            return _langfuse

        secret = os.getenv('LANGFUSE_SECRET_KEY', '').strip()
        public = os.getenv('LANGFUSE_PUBLIC_KEY', '').strip()

        if not secret or not public:
            logger.warning("Langfuse credentials missing")
            _langfuse_checked = True
            return None

        host = (
            os.getenv('LANGFUSE_HOST')
            or os.getenv('LANGFUSE_BASE_URL')
            or 'http://127.0.0.1:3030'
        ).rstrip('/')

        try:
            from langfuse import Langfuse
            try:
                _langfuse = Langfuse(secret_key=secret, public_key=public, base_url=host)
            except TypeError:
                _langfuse = Langfuse(secret_key=secret, public_key=public, host=host)
            logger.info('Langfuse initialized: %s', host)

        except Exception:
            logger.exception("Langfuse initialization failed")
            _langfuse = None

        finally:
            _langfuse_checked = True

    return _langfuse


def _open_trace(langfuse, name, payload):
    if langfuse is None:
        return None
    try:
        if hasattr(langfuse, 'start_as_current_observation'):
            manager = langfuse.start_as_current_observation(as_type='span', name=name, input=payload)
            return {'span': manager.__enter__(), 'manager': manager, 'manual': False}
        if hasattr(langfuse, 'start_span'):
            return {'span': langfuse.start_span(name=name, input=payload), 'manager': None, 'manual': True}
        if hasattr(langfuse, 'trace'):
            return {'span': langfuse.trace(name=name, input=payload), 'manager': None, 'manual': False}
        logger.warning('Installed Langfuse client has no span API.')
    except Exception:
        logger.exception('Langfuse trace was not started')
    return None


def _close_trace(handle, output):
    if not handle:
        return
    span = handle['span']
    try:
        if hasattr(span, 'update_trace'):
            span.update_trace(output=output)
        if hasattr(span, 'update'):
            span.update(output=output)
    except Exception:
        logger.exception('Langfuse trace update failed')
    try:
        if handle['manager'] is not None:
            handle['manager'].__exit__(None, None, None)
        elif handle['manual'] and hasattr(span, 'end'):
            span.end()
    except Exception:
        logger.exception('Langfuse trace close failed')


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


def _v2_parent(parent):
    return parent is not None and callable(getattr(parent, 'span', None)) and callable(getattr(parent, 'generation', None))


@contextmanager
def _child_span(langfuse, name, payload, as_type='span', model=None, parent=None):
    observation = None
    manager = None
    started = True
    try:
        if _v2_parent(parent):
            kwargs = {'name': name, 'input': payload}
            if as_type == 'generation' and model:
                kwargs['model'] = model
            if as_type == 'generation':
                observation = parent.generation(**kwargs)
            else:
                observation = parent.span(**kwargs)
        elif langfuse is not None and hasattr(langfuse, 'start_as_current_observation'):
            kwargs = {'as_type': as_type, 'name': name, 'input': _compact(payload)}
            if model:
                kwargs['model'] = model
            try:
                manager = langfuse.start_as_current_observation(**kwargs)
            except TypeError:
                manager = langfuse.start_as_current_observation(name=name, input=_compact(payload))
            observation = manager.__enter__()
        elif langfuse is not None and hasattr(langfuse, 'start_observation'):
            kwargs = {'name': name, 'as_type': as_type, 'input': _compact(payload)}
            if model:
                kwargs['model'] = model
            try:
                observation = langfuse.start_observation(**kwargs)
            except TypeError:
                observation = langfuse.start_observation(name=name, input=_compact(payload))
        else:
            started = False
    except Exception:
        logger.exception('Langfuse child span was not started: %s', name)
        started = False
    if not started:
        yield None
        return
    try:
        yield observation
    finally:
        try:
            if manager is not None:
                manager.__exit__(None, None, None)
            elif observation is not None and hasattr(observation, 'end'):
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



def keyword_decisions(user_message: str) -> dict:
    text = (user_message or '').lower()
    decisions = {
        'incident_family': 'unknown',
        'need_ci_logs': any(word in text for word in ('jenkins', 'build', 'pipeline', 'compile')),
        'need_metric_window': any(word in text for word in ('cpu', 'memory', 'prometheus', 'metric', 'disk')),
        'need_container_events': any(word in text for word in ('docker', 'container', 'crash', 'restart', 'exited')),
        'need_deployment_changes': any(word in text for word in ('deploy', 'commit', 'release', 'rollout')),
        'need_runbook_search': True,
    }
    if not any((decisions['need_ci_logs'], decisions['need_metric_window'], decisions['need_container_events'])):
        decisions['need_container_events'] = True
    if decisions['need_container_events']:
        decisions['incident_family'] = 'container_runtime'
    elif decisions['need_ci_logs']:
        decisions['incident_family'] = 'ci_failure'
    elif decisions['need_metric_window']:
        decisions['incident_family'] = 'metric_anomaly'
    return align_section(decisions)


LAYA_QUESTIONS = {
    'incident_family': {
        'type': 'choice',
        'instructions': 'Which infrastructure family does this anomaly belong to?',
        'criteria': {
            'ci_failure': 'Jenkins or CI build, compile, or pipeline failure',
            'metric_anomaly': 'CPU, memory, disk, or Prometheus metric problem',
            'container_runtime': 'Docker container crash, restart, or exit',
            'deployment_regression': 'Deploy, release, or rollout regression',
            'unknown': 'None of the above',
        },
    },
    'need_ci_logs': {'type': 'noul', 'instructions': 'Are CI or Jenkins logs required to diagnose this?'},
    'need_metric_window': {'type': 'noul', 'instructions': 'Are Prometheus or host metrics required?'},
    'need_container_events': {'type': 'noul', 'instructions': 'Are Docker container events required?'},
    'need_deployment_changes': {'type': 'noul', 'instructions': 'Are deployment or release changes required?'},
    'need_runbook_search': {'type': 'noul', 'instructions': 'Should a runbook be searched?'},
}


def route(user_message: str, context: dict) -> dict:
    model = get_laya()
    if model is None:
        decisions = keyword_decisions(user_message)
        decisions['router'] = 'keywords'
        return decisions
    state = {'message': user_message, 'snapshot': context.get('fleet_anomaly_snapshot', '')}
    try:
        timeout = float(os.getenv('OPSHUB_LAYA_TIMEOUT', '12') or 12)
        result = _within(lambda: model.predict(state, LAYA_QUESTIONS), timeout)
    except Exception:
        logger.exception('Laya routing failed')
        result = None
    if result is _TimedOut or not isinstance(result, dict):
        if result is _TimedOut:
            logger.warning('Laya predict timed out; keyword routing will be used.')
        decisions = keyword_decisions(user_message)
        decisions['router'] = 'keywords'
        return decisions

    answers = result.get('answers') if isinstance(result, dict) else None
    if not isinstance(answers, dict):
        answers = result if isinstance(result, dict) else {}

    def as_bool(key):
        target = answers.get(key, {})
        if isinstance(target, dict):
            raw = target.get('noul', target.get('probability_true', target.get('probability', 0)))
            try:
                probability = float(raw or 0)
            except (TypeError, ValueError):
                probability = 0
            return probability > 0.15 or str(target.get('choice', '')).lower() in ('true', 'yes', '1')
        return str(target).lower() in ('true', 'yes', '1')

    family = answers.get('incident_family', {})
    if isinstance(family, dict):
        family = family.get('choice', 'unknown')
    decisions = {
        'router': 'laya',
        'incident_family': str(family or 'unknown'),
        'need_ci_logs': as_bool('need_ci_logs'),
        'need_metric_window': as_bool('need_metric_window'),
        'need_container_events': as_bool('need_container_events'),
        'need_deployment_changes': as_bool('need_deployment_changes'),
        'need_runbook_search': as_bool('need_runbook_search'),
    }
    routing = result.get('routing') if isinstance(result, dict) else None
    if isinstance(routing, dict) and routing.get('model'):
        decisions['laya_model'] = str(routing['model'])
    if not any((decisions['need_ci_logs'], decisions['need_metric_window'], decisions['need_container_events'])):
        decisions['need_container_events'] = True
    return align_section(decisions)


def align_section(decisions):
    """The section Laya picked decides which error data and which runbook to load."""
    family = str(decisions.get('incident_family') or 'unknown')
    section_flag = {
        'ci_failure': 'need_ci_logs',
        'metric_anomaly': 'need_metric_window',
        'container_runtime': 'need_container_events',
        'deployment_regression': 'need_deployment_changes',
    }.get(family)
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


def _chroma_hits(collection, query):
    try:
        return collection.query(query_texts=[query], n_results=3)
    except Exception:
        logger.exception('Chroma query failed')
        return None


def _format_hits(results):
    documents = []
    groups = results.get('documents') or []
    distances = results.get('distances') or []
    metadatas = results.get('metadatas') or []
    ids = results.get('ids') or []
    for index, group in enumerate(groups):
        dist_group = distances[index] if index < len(distances) else []
        meta_group = metadatas[index] if index < len(metadatas) else []
        id_group = ids[index] if index < len(ids) else []
        for item_index, doc in enumerate(group or []):
            if not isinstance(doc, str) or not doc.strip():
                continue
            distance = dist_group[item_index] if item_index < len(dist_group) else None
            try:
                too_far = distance is not None and float(distance) > 1.5
            except (TypeError, ValueError):
                too_far = False
            if too_far:
                continue
            meta = meta_group[item_index] if item_index < len(meta_group) and isinstance(meta_group[item_index], dict) else {}
            label = meta.get('title') or (id_group[item_index] if item_index < len(id_group) else 'runbook')
            documents.append(f'[{label}] {doc[:1500]}')
    return documents


def _postgres_hits(query):
    from apps.knowledge.models import KnowledgeDocument
    words = []
    for word in (query or '').replace('_', ' ').split():
        cleaned = ''.join(character for character in word if character.isalnum())
        if len(cleaned) >= 4 and cleaned.lower() not in words:
            words.append(cleaned.lower())
        if len(words) == 6:
            break
    if not words:
        return []
    condition = Q()
    for word in words:
        condition |= Q(title__icontains=word) | Q(content__icontains=word)
    rows = KnowledgeDocument.objects.filter(archived_at__isnull=True).filter(condition).order_by('-updated_at')[:3]
    return [f'[{row.title}] {row.content[:1500]}' for row in rows]


def retrieve(query: str) -> list:
    collection = get_chroma_collection()
    if collection is not None:
        results = _chroma_hits(collection, query)
        if results:
            documents = _format_hits(results)
            if documents:
                return documents
    return _postgres_hits(query)


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


def maybe_execute(reply_text: str, decisions: dict) -> dict:
    meta = {'agent_triggered': False, 'sandbox_output': None}
    try:
        parsed = json.loads(reply_text)
    except (TypeError, json.JSONDecodeError):
        meta['error'] = 'reply was not json'
        return meta
    if not isinstance(parsed, dict) or parsed.get('engine_status') == 'offline' or not parsed.get('incident_detected'):
        return meta
    scope = str(parsed.get('error_scope') or '').strip()
    if not scope or scope.lower() in ('none', 'engine'):
        return meta
    needle = slugify(scope).replace('-', '_')
    tools = MCPTool.objects.filter(status='active', archived_at__isnull=True)
    tool = tools.filter(name__iexact=needle).first() if needle else None
    if tool is None and len(needle) >= 3:
        tool = tools.filter(name__icontains=needle).first()
    if tool is None and decisions.get('incident_family') == 'container_runtime':
        tool = tools.filter(Q(name='docker_container_restarter') | Q(name='restart_container')).first()
    if tool is None or not tool.code:
        meta['error'] = 'no matching active tool'
        return meta
    meta['agent_triggered'] = True
    meta['matched_tool'] = tool.name
    meta['sandbox_output'] = MCPSandboxExecutor.execute_tool_safe(tool.code, {'TARGET_RESOURCE': scope})
    return meta


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
        with _child_span(langfuse, 'chromadb', {
            'query': query,
            'section': decisions.get('incident_family', 'unknown'),
        }, parent=parent) as chroma_span:
            documents = retrieve(query)
            _set_output(chroma_span, {
                'section': decisions.get('incident_family', 'unknown'),
                'query': query,
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
        packet = _compact(f"""ERROR:
{user_message}

ERROR DETAILS:
{json.dumps(_model_evidence(evidence))}

LAYA:
{json.dumps(route_view)}

RUNBOOK:
{chr(10).join(documents) if documents else 'No runbook found.'}
""", 5000)
        packet += "\n\nReturn only JSON with keys incident_detected, error_scope, diagnostic_report, evidence_refs, engine_status."
        system_prompt = """
You are the OpsHub diagnostics engine.
The user message has the error, the section chosen by Laya, and the runbook.
Use only those. If a claim is not supported by them, say you do not know.
Do not claim an action was executed.
Return only JSON with keys incident_detected (boolean), error_scope (string), diagnostic_report (string), evidence_refs (array of short strings copied from the error or runbook labels), engine_status (string, use "ok").
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
    finally:
        _close_trace(handle, {
            'engine_status': engine_status,
            'laya': route_view,
            'chromadb': {
                'query': query,
                'runbooks': [_compact(document, 1000) for document in documents[:3]],
            },
            'reply': _compact(reply_text, 4000),
        })
        if langfuse is not None:
            try:
                langfuse.flush()
            except Exception:
                logger.exception('Langfuse flush failed')
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
    success = ((result.get('agent_automation') or {}).get('sandbox_output') or {}).get('success')
    if docker_row is not None:
        docker_row.last_attempt_at = now
        if result.get('engine_status') == 'ok':
            docker_row.remediation_attempted = True
        if success:
            docker_row.resolved = True
        docker_row.save(update_fields=['last_attempt_at', 'remediation_attempted', 'resolved'])
    if jenkins_row is not None:
        jenkins_row.last_attempt_at = now
        if result.get('engine_status') == 'ok':
            jenkins_row.remediation_attempted = True
        jenkins_row.save(update_fields=['last_attempt_at', 'remediation_attempted'])
    return result
