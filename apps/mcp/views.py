import ipaddress
import os
import re
import time
from urllib.parse import urlparse

import requests
from django.utils import timezone
from rest_framework import decorators, response, status, viewsets

from apps.audit.models import AuditEvent
from apps.mcp.diagnostics import diagnose
from apps.mcp.models import MCPTool, MCPToolVersion, SystemSetting, get_setting, set_setting
from apps.mcp.runtime import MCPSandboxExecutor
from apps.mcp.serializers import MCPToolSerializer

PUBLIC_SETTINGS = (
    'ollama_host',
    'ollama_model',
    'prometheus_url',
    'jenkins_url',
    'docker_host',
    'jenkins_user',
    'jenkins_token',
    'scrape_interval',
    'chroma_host',
    'chroma_port',
    'embedding_engine',
    'auto_remediate',
)
SECRET_SETTINGS = {'jenkins_token'}
URL_SETTINGS = {'ollama_host', 'prometheus_url', 'jenkins_url', 'docker_host'}
CLEARABLE_SETTINGS = {'jenkins_user', 'docker_host'}
CONTROL_KEYS = {'confirm_reindex'}
BLOCKED_HOSTS = {'169.254.169.254', 'metadata.google.internal'}


def _defaults():
    return {
        'ollama_host': os.getenv('OLLAMA_HOST', 'http://localhost:11434'),
        'ollama_model': os.getenv('OLLAMA_MODEL', 'qwen2.5-coder:7b'),
        'prometheus_url': os.getenv('PROMETHEUS_URL', 'http://127.0.0.1:9090'),
        'jenkins_url': os.getenv('JENKINS_URL', 'http://127.0.0.1:8080'),
        'docker_host': os.getenv('DOCKER_API_URL', ''),
        'jenkins_user': os.getenv('JENKINS_USER', ''),
        'jenkins_token': '',
        'scrape_interval': os.getenv('SCRAPE_INTERVAL', '15'),
        'chroma_host': os.getenv('CHROMA_HOST', 'localhost'),
        'chroma_port': os.getenv('CHROMA_PORT', '8001'),
        'embedding_engine': 'all-MiniLM-L6-v2',
        'auto_remediate': '0',
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
    return value
