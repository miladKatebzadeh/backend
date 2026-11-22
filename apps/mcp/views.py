import ipaddress
import os
import re
import time
import uuid
from urllib.parse import urlparse

import requests
from django.utils import timezone
from rest_framework import decorators, response, status, viewsets

from apps.audit.models import AuditEvent
from apps.mcp.diagnostics import diagnose, reset_langfuse
from apps.mcp.models import MCPTool, MCPToolVersion, SystemSetting, get_setting, set_setting
from apps.mcp.runtime import MCPSandboxExecutor
from apps.mcp.serializers import MCPToolSerializer

PUBLIC_SETTINGS = (
    'ollama_host',
    'ollama_model',
    'prometheus_url',
    'alertmanager_url',
    'jenkins_url',
    'docker_host',
    'jenkins_user',
    'jenkins_token',
    'scrape_interval',
    'memory_min_mb',
    'disk_min_gb',
    'cpu_max_percent',
    'tool_timeout',
    'chroma_host',
    'chroma_port',
    'embedding_engine',
    'auto_remediate',
    'langfuse_base_url',
    'langfuse_public_key',
    'langfuse_secret_key',
)
SECRET_SETTINGS = {'jenkins_token', 'langfuse_secret_key'}
URL_SETTINGS = {'ollama_host', 'prometheus_url', 'alertmanager_url', 'jenkins_url', 'docker_host', 'langfuse_base_url'}
CLEARABLE_SETTINGS = {'jenkins_user', 'docker_host', 'alertmanager_url'}
INTEGER_SETTINGS = {
    'memory_min_mb': (64, 1_048_576),
    'disk_min_gb': (1, 100_000),
    'cpu_max_percent': (1, 100),
    'tool_timeout': (5, 180),
}
CONTROL_KEYS = {'confirm_reindex'}
BLOCKED_HOSTS = {'169.254.169.254', 'metadata.google.internal'}


def _defaults():
    return {
        'ollama_host': os.getenv('OLLAMA_HOST', 'http://localhost:11434'),
        'ollama_model': os.getenv('OLLAMA_MODEL', 'qwen2.5-coder:7b'),
        'prometheus_url': os.getenv('PROMETHEUS_URL', 'http://127.0.0.1:9090'),
        'alertmanager_url': os.getenv('ALERTMANAGER_URL', ''),
        'jenkins_url': os.getenv('JENKINS_URL', 'http://127.0.0.1:8080'),
        'docker_host': os.getenv('DOCKER_API_URL', ''),
        'jenkins_user': os.getenv('JENKINS_USER', ''),
        'jenkins_token': '',
        'scrape_interval': os.getenv('SCRAPE_INTERVAL', '15'),
        'memory_min_mb': '1024',
        'disk_min_gb': '5',
        'cpu_max_percent': '85',
        'tool_timeout': os.getenv('OPSHUB_TOOL_TIMEOUT', '60'),
        'chroma_host': os.getenv('CHROMA_HOST', 'localhost'),
        'chroma_port': os.getenv('CHROMA_PORT', '8001'),
        'embedding_engine': 'all-MiniLM-L6-v2',
        'auto_remediate': '0',
        'langfuse_base_url': os.getenv('LANGFUSE_BASE_URL') or os.getenv('LANGFUSE_HOST') or 'http://127.0.0.1:3030',
        'langfuse_public_key': os.getenv('LANGFUSE_PUBLIC_KEY', ''),
        'langfuse_secret_key': '',
    }


def _blocked_host(host):
    name = host.lower().rstrip('.')
    if name in BLOCKED_HOSTS:
        return True
    try:
        return ipaddress.ip_address(name) == ipaddress.ip_address('169.254.169.254')
    except ValueError:
        return False


def _normalize_http_url(key, value):
    parsed = urlparse(value)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError(f'{key} must be an http(s) URL')
    if parsed.username or parsed.password:
        raise ValueError(f'{key} must not include a username or password')
    if _blocked_host(parsed.hostname):
        raise ValueError(f'{key} points at a blocked metadata address')
    host = parsed.hostname.lower().rstrip('.')
    host_text = f'[{host}]' if ':' in host else host
    port = f':{parsed.port}' if parsed.port else ''
    path = parsed.path.rstrip('/')
    return f'{parsed.scheme}://{host_text}{port}{path}'


def _clean_setting(key, value):
    if key in URL_SETTINGS:
        return _normalize_http_url(key, value)
    if key == 'chroma_port':
        port = int(value)
        if not 1 <= port <= 65535:
            raise ValueError('chroma_port must be between 1 and 65535')
        return str(port)
    if key == 'scrape_interval':
        seconds = int(value)
        if not 5 <= seconds <= 3600:
            raise ValueError('scrape_interval must be between 5 and 3600 seconds')
        return str(seconds)
    if key in INTEGER_SETTINGS:
        low, high = INTEGER_SETTINGS[key]
        number = int(value)
        if not low <= number <= high:
            raise ValueError(f'{key} must be between {low} and {high}')
        return str(number)
    if key == 'auto_remediate':
        return '1' if value.lower() in ('1', 'true', 'yes', 'on') else '0'
    if key == 'chroma_host':
        if '://' in value or any(char.isspace() for char in value) or not value:
            raise ValueError('chroma_host must be a hostname or IP')
        if _blocked_host(value):
            raise ValueError('chroma_host points at a blocked metadata address')
        return value.lower().rstrip('.')
    if key == 'ollama_model' and not re.fullmatch(r'[\w.\-:]{1,120}', value):
        raise ValueError('ollama_model contains unsupported characters')
    if key == 'embedding_engine' and not re.fullmatch(r'[\w.\-:/]{1,200}', value):
        raise ValueError('embedding_engine contains unsupported characters')
    if key == 'jenkins_user' and any(char.isspace() for char in value):
        raise ValueError('jenkins_user cannot contain spaces')
    if key in ('langfuse_public_key', 'langfuse_secret_key'):
        if not 8 <= len(value) <= 300 or any(char.isspace() or ord(char) < 32 for char in value):
            raise ValueError(f'{key} contains unsupported characters')
        return value
    return value


def _stored_settings():
    defaults = _defaults()
    stored = {row.key: row.value for row in SystemSetting.objects.all()}
    payload = {}
    for key, default in defaults.items():
        if key in stored:
            payload[key] = stored[key]
        else:
            payload[key] = default
    payload['jenkins_token'] = ''
    payload['jenkins_token_set'] = bool(stored.get('jenkins_token'))
    payload['langfuse_secret_key'] = ''
    payload['langfuse_secret_set'] = bool(stored.get('langfuse_secret_key') or os.getenv('LANGFUSE_SECRET_KEY', '').strip())
    return payload


def _confirmed(value):
    return str(value).lower() in ('1', 'true', 'yes', 'on')


class MCPToolViewSet(viewsets.ModelViewSet):
    serializer_class = MCPToolSerializer

    def get_queryset(self):
        queryset = MCPTool.objects.all().order_by('-updated_at')
        if self.request.query_params.get('include_archived') != 'true':
            queryset = queryset.filter(archived_at__isnull=True)
        return queryset

    def create(self, request, *args, **kwargs):
        data = request.data.copy()
        if not data.get('status'):
            data['status'] = 'active'
        if data.get('name'):
            data['name'] = data['name'].strip().replace(' ', '_')
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return response.Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        tool = serializer.save()
        MCPToolVersion.objects.create(
            tool=tool,
            version=1,
            description=tool.description or 'Initial tool',
            code=tool.code or '',
        )
        AuditEvent.objects.create(action='create', resource_type='mcp_tool', resource_id=str(tool.pk), payload={'name': tool.name})

    def update(self, request, *args, **kwargs):
        kwargs.pop('partial', True)
        instance = self.get_object()
        data = request.data.copy()
        if data.get('name'):
            data['name'] = data['name'].strip().replace(' ', '_')
        serializer = self.get_serializer(instance, data=data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return response.Response(serializer.data)

    def perform_update(self, serializer):
        tool = serializer.save()
        last_version = tool.versions.order_by('-version').first()
        next_version = (last_version.version if last_version else 0) + 1
        MCPToolVersion.objects.create(tool=tool, version=next_version, description=tool.description, code=tool.code)
        AuditEvent.objects.create(
            action='update',
            resource_type='mcp_tool',
            resource_id=str(tool.pk),
            payload={'version': next_version},
        )

    def destroy(self, request, *args, **kwargs):
        tool = self.get_object()
        if request.query_params.get('confirm') != 'true':
            return response.Response({'detail': 'Deletion requires confirm=true.'}, status=status.HTTP_400_BAD_REQUEST)
        tool.archived_at = timezone.now()
        tool.status = 'archived'
        tool.save(update_fields=['archived_at', 'status', 'updated_at'])
        AuditEvent.objects.create(action='delete', resource_type='mcp_tool', resource_id=str(tool.pk), payload={'mode': 'soft_delete'})
        return response.Response(status=status.HTTP_204_NO_CONTENT)

    @decorators.action(detail=True, methods=['post'])
    def run(self, request, pk=None):
        tool = self.get_object()
        if tool.archived_at or tool.status == 'archived':
            return response.Response({'detail': 'Archived tools cannot run.'}, status=status.HTTP_400_BAD_REQUEST)
        target = str(request.data.get('target') or '')
        return response.Response(MCPSandboxExecutor.execute_tool_safe(tool.code, {'TARGET_RESOURCE': target}))


def _wants_remediation(value):
    return str(value).lower() in ('1', 'true', 'yes', 'on')


def _action_payload(result):
    agent = result.get('agent_automation') or {}
    sandbox = agent.get('sandbox_output') or {}
    if not agent.get('agent_triggered'):
        return {
            'triggered': False,
            'tool': '',
            'success': False,
            'sandbox': sandbox.get('sandbox') or '',
            'resolved': False,
            'message': agent.get('error') or '',
        }
    parts = []
    if sandbox.get('stdout'):
        parts.append(str(sandbox['stdout']))
    if sandbox.get('error'):
        parts.append(str(sandbox['error']))
    if sandbox.get('warning'):
        parts.append(str(sandbox['warning']))
    if agent.get('checked') not in (None, 'running') and sandbox.get('success'):
        parts.append(f"Container is {agent.get('checked')}, so this is not marked resolved.")
    elif agent.get('resolved'):
        parts.append('Container is running.')
    return {
        'triggered': True,
        'tool': agent.get('matched_tool') or '',
        'success': bool(sandbox.get('success')),
        'sandbox': sandbox.get('sandbox') or '',
        'resolved': bool(agent.get('resolved')),
        'message': '\n'.join(parts),
    }


@decorators.api_view(['POST'])
def mcp_ai_chat(request):
    user_message = (request.data.get('message') or '').strip()
    if not user_message:
        return response.Response({'detail': 'Message payload cannot be empty.'}, status=400)
    auto = _wants_remediation(get_setting('auto_remediate', '0'))
    requested = _wants_remediation(request.data.get('remediate', ''))
    result = diagnose(user_message, allow_remediation=auto or requested)
    decisions = result.get('decisions') or {}
    return response.Response({
        'reply': result['reply'],
        'engine_status': result['engine_status'],
        'router': decisions.get('router', 'keywords'),
        'laya_model': decisions.get('laya_model', ''),
        'action': _action_payload(result),
    })


@decorators.api_view(['GET', 'POST'])
def save_system_settings(request):
    if request.method == 'GET':
        return response.Response(_stored_settings())

    if not request.data:
        return response.Response({'detail': 'No configuration payload provided.'}, status=400)
    cleaned = {}
    errors = {}
    for key, raw_value in request.data.items():
        if key in CONTROL_KEYS:
            continue
        if key not in PUBLIC_SETTINGS:
            errors[key] = 'unknown setting'
            continue
        value = str(raw_value).strip()
        if value == '':
            if key in ('jenkins_token', 'langfuse_secret_key'):
                continue
            if key in CLEARABLE_SETTINGS:
                cleaned[key] = ''
                continue
            errors[key] = 'This field cannot be empty.'
            continue
        try:
            cleaned[key] = _clean_setting(key, value)
        except ValueError as exc:
            errors[key] = str(exc)
    if errors:
        return response.Response({'detail': 'Invalid settings.', 'errors': errors}, status=400)
    if not cleaned:
        return response.Response({'status': 'success', 'saved': [], 'notes': []})

    reindex = False
    if 'embedding_engine' in cleaned:
        current = get_setting('embedding_engine', _defaults()['embedding_engine'])
        if cleaned['embedding_engine'] != current:
            if not _confirmed(request.data.get('confirm_reindex', '')):
                return response.Response({
                    'detail': 'Changing the embedding model rebuilds the knowledge index.',
                    'code': 'reindex_required',
                    'errors': {'embedding_engine': 'Confirm reindex before saving a new embedding model.'},
                }, status=409)
            reindex = True

    for key, value in cleaned.items():
        set_setting(key, value)

    audit_payload = {key: value for key, value in cleaned.items() if key not in SECRET_SETTINGS}
    if 'jenkins_token' in cleaned:
        audit_payload['jenkins_token'] = 'updated'
    if 'langfuse_secret_key' in cleaned:
        audit_payload['langfuse_secret_key'] = 'updated'
    AuditEvent.objects.create(
        action='update',
        resource_type='system_setting',
        resource_id=','.join(sorted(cleaned)),
        payload=audit_payload,
    )
    notes = []
    if 'scrape_interval' in cleaned:
        notes.append('scrape_interval applies on the next collector cycle')
    if any(key.startswith('langfuse_') for key in cleaned):
        reset_langfuse()
        notes.append('langfuse settings apply on the next diagnosis')
    body = {'status': 'success', 'saved': sorted(cleaned), 'notes': notes}
    if reindex:
        from apps.knowledge.chroma import rebuild_knowledge_index
        body['reindex'] = rebuild_knowledge_index()
    return response.Response(body)


def _probe_value(data, key):
    if key in data:
        return str(data.get(key) or '').strip()
    defaults = _defaults()
    return get_setting(key, defaults.get(key, ''))


def _langfuse_target(data):
    url = _clean_setting('langfuse_base_url', _probe_value(data, 'langfuse_base_url'))
    public = _probe_value(data, 'langfuse_public_key') or os.getenv('LANGFUSE_PUBLIC_KEY', '')
    secret = str(data.get('langfuse_secret_key') or '').strip() or get_setting(
        'langfuse_secret_key', os.getenv('LANGFUSE_SECRET_KEY', ''),
    )
    if not str(public).strip() or not str(secret).strip():
        raise ValueError('Langfuse public key and secret key are required.')
    return url, _clean_setting('langfuse_public_key', str(public).strip()), _clean_setting('langfuse_secret_key', str(secret).strip())


def _project_names(payload):
    rows = payload if isinstance(payload, list) else []
    if isinstance(payload, dict):
        rows = payload.get('data') or payload.get('projects') or []
    names = []
    if isinstance(rows, list):
        for item in rows:
            if isinstance(item, dict) and item.get('name'):
                names.append(str(item['name']))
    return names


@decorators.api_view(['POST'])
def test_system_settings(request):
    service = str(request.data.get('service') or '').strip()
    started = time.perf_counter()
    try:
        if service == 'ollama':
            host = _clean_setting('ollama_host', _probe_value(request.data, 'ollama_host'))
            probed = requests.get(f'{host}/api/tags', timeout=3, allow_redirects=False)
            probed.raise_for_status()
            models = []
            for item in probed.json().get('models') or []:
                name = item.get('name') or item.get('model')
                if name:
                    models.append(name)
            message = f'{len(models)} model(s)'
            extra = {'models': models}
        elif service == 'prometheus':
            url = _clean_setting('prometheus_url', _probe_value(request.data, 'prometheus_url'))
            probed = requests.get(f'{url}/-/ready', timeout=3, allow_redirects=False)
            probed.raise_for_status()
            message = 'ready'
            extra = {}
        elif service == 'jenkins':
            url = _clean_setting('jenkins_url', _probe_value(request.data, 'jenkins_url'))
            user = _probe_value(request.data, 'jenkins_user')
            token = str(request.data.get('jenkins_token') or '').strip() or get_setting('jenkins_token', os.getenv('JENKINS_TOKEN', ''))
            auth = (user, token) if user and token else None
            probed = requests.get(f'{url}/whoAmI/api/json', auth=auth, timeout=3, allow_redirects=False)
            probed.raise_for_status()
            message = probed.json().get('name') or 'reachable'
            extra = {}
        elif service == 'docker':
            raw = _probe_value(request.data, 'docker_host')
            if not str(raw).strip():
                raise ValueError('docker_host must be an http(s) URL')
            url = _clean_setting('docker_host', raw)
            probed = requests.get(f'{url}/version', timeout=3, allow_redirects=False)
            probed.raise_for_status()
            message = str((probed.json() or {}).get('Version') or 'reachable')
            extra = {}
        elif service == 'alertmanager':
            raw = _probe_value(request.data, 'alertmanager_url')
            if not str(raw).strip():
                raise ValueError('alertmanager_url must be an http(s) URL')
            url = _clean_setting('alertmanager_url', raw)
            probed = requests.get(f'{url}/api/v2/status', timeout=3, allow_redirects=False)
            probed.raise_for_status()
            message = 'ready'
            extra = {}
        elif service == 'chroma':
            host = _clean_setting('chroma_host', _probe_value(request.data, 'chroma_host'))
            port = _clean_setting('chroma_port', _probe_value(request.data, 'chroma_port'))
            probed = requests.get(f'http://{host}:{port}/api/v2/heartbeat', timeout=3, allow_redirects=False)
            if probed.status_code == 404:
                probed = requests.get(f'http://{host}:{port}/api/v1/heartbeat', timeout=3, allow_redirects=False)
            probed.raise_for_status()
            message = 'heartbeat'
            extra = {}
        elif service == 'langfuse':
            url, public, secret = _langfuse_target(request.data)
            probed = requests.get(f'{url}/api/public/projects', auth=(public, secret), timeout=4, allow_redirects=False)
            if probed.status_code in (401, 403):
                raise PermissionError('The keys were rejected.')
            probed.raise_for_status()
            names = _project_names(probed.json() if probed.content else [])
            message = names[0] if names else 'keys accepted'
            extra = {}
        elif service == 'langfuse_trace':
            url, public, secret = _langfuse_target(request.data)
            trace_id = str(uuid.uuid4())
            stamp = timezone.now().isoformat()
            event = {
                'id': str(uuid.uuid4()),
                'type': 'trace-create',
                'timestamp': stamp,
                'body': {
                    'id': trace_id,
                    'timestamp': stamp,
                    'name': 'revive-settings-test',
                    'input': {'source': 'settings'},
                    'output': {'ok': True},
                },
            }
            probed = requests.post(
                f'{url}/api/public/ingestion',
                json={'batch': [event]},
                auth=(public, secret),
                timeout=5,
                allow_redirects=False,
            )
            if probed.status_code in (401, 403):
                raise PermissionError('The keys were rejected.')
            probed.raise_for_status()
            payload = probed.json() if probed.content else {}
            errors = payload.get('errors') if isinstance(payload, dict) else None
            if errors:
                first = errors[0] if isinstance(errors, list) and errors else {}
                detail = str(first.get('message') or first.get('error') or '') if isinstance(first, dict) else ''
                raise ValueError(detail[:200] or 'Langfuse rejected the sample trace.')
            message = f'revive-settings-test {trace_id}'
            extra = {'trace_id': trace_id}
        else:
            return response.Response({'detail': 'Unknown service.', 'errors': {'service': 'unknown service'}}, status=400)
    except ValueError as exc:
        return response.Response({'status': 'invalid', 'latency_ms': 0, 'message': str(exc)})
    except PermissionError as exc:
        latency = int((time.perf_counter() - started) * 1000)
        return response.Response({'status': 'invalid', 'latency_ms': latency, 'message': str(exc)})
    except Exception as exc:
        latency = int((time.perf_counter() - started) * 1000)
        return response.Response({'status': 'offline', 'latency_ms': latency, 'message': exc.__class__.__name__})
    latency = int((time.perf_counter() - started) * 1000)
    return response.Response({'status': 'connected', 'latency_ms': latency, 'message': message, **extra})


@decorators.api_view(['GET'])
def list_local_ollama_models(request):
    override = str(request.GET.get('host') or '').strip()
    if override:
        try:
            ollama_host = _clean_setting('ollama_host', override)
        except ValueError as exc:
            return response.Response({'status': 'invalid', 'models': [], 'message': str(exc)}, status=400)
    else:
        ollama_host = get_setting('ollama_host', os.getenv('OLLAMA_HOST', 'http://localhost:11434'))
    try:
        import ollama
        client = ollama.Client(host=ollama_host)
        local_models = client.list().get('models', [])
        model_tags = [item.get('model') for item in local_models if item.get('model')]
        return response.Response({'status': 'success', 'models': model_tags})
    except Exception as exc:
        return response.Response({'status': 'offline', 'models': [], 'message': exc.__class__.__name__})
