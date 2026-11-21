import io
import os
import subprocess
import sys
import tarfile
import tempfile
import uuid
from urllib.parse import urlparse

import requests

RUNNER = r'''
import ast
import importlib.util
import inspect
import os
import sys
import traceback
import types

target = os.environ.get("TARGET_RESOURCE", "")
script = os.environ["TOOL_SCRIPT"]

mcp_mod = types.ModuleType("mcp")

def tool(fn=None, **kwargs):
    if callable(fn):
        return fn
    def deco(func):
        return func
    return deco

mcp_mod.tool = tool
sys.modules["mcp"] = mcp_mod

source = open(script, encoding="utf-8").read()
try:
    tree = ast.parse(source)
except SyntaxError:
    traceback.print_exc()
    sys.exit(1)

nodes = list(tree.body)
if nodes and isinstance(nodes[0], ast.Expr) and isinstance(getattr(nodes[0], "value", None), ast.Constant) and isinstance(nodes[0].value.value, str):
    nodes = nodes[1:]
runtime_statement = False
for node in nodes:
    if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Pass)):
        continue
    runtime_statement = True
    break

if "if __name__" in source or runtime_statement:
    namespace = {"__name__": "__main__"}
    try:
        exec(compile(source, script, "exec"), namespace)
    except Exception:
        traceback.print_exc()
        sys.exit(1)
    sys.exit(0)

spec = importlib.util.spec_from_file_location("user_tool", script)
module = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(module)
except Exception:
    traceback.print_exc()
    sys.exit(1)

functions = []
for name in dir(module):
    if name.startswith("_"):
        continue
    obj = getattr(module, name)
    if inspect.isfunction(obj) and getattr(obj, "__module__", None) == "user_tool":
        functions.append(obj)
if not functions:
    sys.exit(0)

fn = None
for preferred in ("main", "run", "handle"):
    for item in functions:
        if item.__name__ == preferred:
            fn = item
            break
    if fn:
        break
if fn is None:
    fn = functions[0]

try:
    signature = inspect.signature(fn)
    names = list(signature.parameters)
    if not names:
        result = fn()
    elif "name" in names:
        result = fn(name=target)
    elif "target" in names:
        result = fn(target=target)
    elif "container" in names:
        result = fn(container=target)
    elif len(names) == 1:
        result = fn(target)
    else:
        result = fn()
except Exception:
    traceback.print_exc()
    sys.exit(1)

if result is not None:
    print(result)
'''


DOCKER_SHIM = r'''
import json
import os
import urllib.request

def _base():
    return os.environ.get("DOCKER_API_URL", "").rstrip("/")

def _request(method, path, timeout=30):
    base = _base()
    if not base:
        raise RuntimeError("DOCKER_API_URL is not set")
    request = urllib.request.Request(base + path, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read()
    if not raw:
        return None
    return json.loads(raw)

class Container:
    def __init__(self, container_id, name):
        self.id = container_id
        self.name = name
    def restart(self, timeout=10):
        _request("POST", "/containers/" + self.id + "/restart?t=" + str(int(timeout)), timeout=int(timeout) + 5)
        return self

class Containers:
    def get(self, name):
        wanted = str(name or "").lstrip("/")
        listing = _request("GET", "/containers/json?all=1", timeout=10) or []
        for item in listing:
            names = [str(entry).lstrip("/") for entry in item.get("Names") or []]
            ident = str(item.get("Id") or "")
            if wanted and (wanted in names or ident.startswith(wanted)):
                return Container(ident, names[0] if names else wanted)
        raise RuntimeError("container not found: " + wanted)

class DockerClient:
    def __init__(self):
        self.containers = Containers()
    def close(self):
        return None

def from_env():
    return DockerClient()
'''


def tool_timeout():
    from apps.mcp.models import get_setting
    try:
        value = int(get_setting('tool_timeout', os.getenv('OPSHUB_TOOL_TIMEOUT', '60')))
    except (TypeError, ValueError):
        value = 60
    return max(5, min(value, 180))


def _docker_api_url():
    from apps.mcp.models import get_setting
    host = get_setting('docker_host', os.getenv('DOCKER_API_URL', '')).strip().rstrip('/')
    if host.startswith(('http://', 'https://')):
        return host
    return ''


def _docker_env(api_url, inside_container):
    parsed = urlparse(api_url)
    host = parsed.hostname or ''
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    if inside_container and host in {'127.0.0.1', 'localhost', '::1'}:
        host = 'host.docker.internal'
    return {
        'DOCKER_HOST': f'tcp://{host}:{port}',
        'DOCKER_API_URL': f'{parsed.scheme}://{host}:{port}',
    }


def _tool_child_env(env_vars, api_url, inside_container):
    env = {
        'PATH': '/usr/local/bin:/usr/bin:/bin',
        'HOME': '/tmp',
        'LANG': 'C.UTF-8',
        'LC_ALL': 'C.UTF-8',
        'PYTHONUNBUFFERED': '1',
        'PYTHONIOENCODING': 'utf-8',
        'PYTHONDONTWRITEBYTECODE': '1',
        'TARGET_RESOURCE': str((env_vars or {}).get('TARGET_RESOURCE', '')),
    }
    if api_url:
        env.update(_docker_env(api_url, inside_container))
    return env


def _decode_docker_logs(raw: bytes) -> str:
    if len(raw) >= 8 and raw[0] in (1, 2) and raw[1:4] == b'\x00\x00\x00':
        parts = []
        index = 0
        while index + 8 <= len(raw):
            size = int.from_bytes(raw[index + 4:index + 8], 'big')
            index += 8
            parts.append(raw[index:index + size])
            index += size
        raw = b''.join(parts)
    return raw.decode('utf-8', errors='replace')


def _tar_bytes(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w') as archive:
        for name, content in files.items():
            data = content.encode('utf-8')
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class MCPSandboxExecutor:
    @staticmethod
    def execute_tool_safe(tool_code: str, env_vars: dict | None = None) -> dict:
        env_vars = env_vars or {}
        code = tool_code or ""
        if not code.strip():
            return _failure("Tool code is empty.")
        if "@mcp.tool" in code and "import mcp" not in code:
            code = "import mcp\n" + code
        api_url = _docker_api_url()
        if api_url and env_vars.get('SANDBOX') != 'local':
            container_result = MCPSandboxExecutor._execute_in_container(code, env_vars, api_url)
            if container_result is not None:
                return container_result
        result = MCPSandboxExecutor._execute_local(code, env_vars, api_url)
        if api_url and result.get('sandbox') == 'local' and not result.get('warning'):
            result['warning'] = 'Docker sandbox was unavailable, so the tool ran on the Django machine.'
        return result

    @staticmethod
    def _execute_local(code, env_vars, api_url):
        script_path = None
        runner_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".py", mode="w", encoding="utf-8", delete=False) as script_file:
                script_file.write(code)
                script_path = script_file.name
            with tempfile.NamedTemporaryFile(suffix=".py", mode="w", encoding="utf-8", delete=False) as runner_file:
                runner_file.write(RUNNER)
                runner_path = runner_file.name
            child_env = _tool_child_env(env_vars, api_url, inside_container=False)
            child_env['TOOL_SCRIPT'] = script_path
            seconds = tool_timeout()
            try:
                completed = subprocess.run(
                    [sys.executable, runner_path],
                    capture_output=True,
                    text=True,
                    env=child_env,
                    timeout=seconds,
                )
            except subprocess.TimeoutExpired as exc:
                return {
                    "success": False,
                    "exit_code": -1,
                    "stdout": _clip(exc.stdout),
                    "stderr": _clip(exc.stderr),
                    "error": f"Execution timed out after {seconds} seconds.",
                    "sandbox": "local",
                }
            return {
                "success": completed.returncode == 0,
                "exit_code": completed.returncode,
                "stdout": _clip(completed.stdout).strip(),
                "stderr": _clip(completed.stderr).strip(),
                "error": None if completed.returncode == 0 else "Tool process exited with an error.",
                "sandbox": "local",
            }
        except Exception as exc:
            return _failure(f"Internal execution failure: {exc}")
        finally:
            for path in (script_path, runner_path):
                if path and os.path.exists(path):
                    os.remove(path)

    @staticmethod
    def _execute_in_container(code, env_vars, api_url):
        image = os.getenv('OPSHUB_TOOL_IMAGE', 'python:3.12-slim')
        seconds = tool_timeout()
        child_env = _tool_child_env(env_vars, api_url, inside_container=True)
        child_env['TOOL_SCRIPT'] = '/opt/tool/tool.py'
        child_env['PYTHONPATH'] = '/opt/tool'
        container_id = ''
        try:
            created = requests.post(
                f'{api_url}/containers/create',
                params={'name': f'opshub-tool-{uuid.uuid4().hex[:12]}'},
                json={
                    'Image': image,
                    'Cmd': ['python', '/opt/tool/runner.py'],
                    'Env': [f'{key}={value}' for key, value in child_env.items()],
                    'WorkingDir': '/opt/tool',
                    'HostConfig': {
                        'Memory': 268435456,
                        'MemorySwap': 268435456,
                        'PidsLimit': 64,
                        'CapDrop': ['ALL'],
                        'SecurityOpt': ['no-new-privileges:true'],
                        'NetworkMode': 'bridge',
                        'AutoRemove': False,
                    },
                },
                timeout=5,
            )
            if created.status_code == 404:
                return None
            created.raise_for_status()
            container_id = str((created.json() or {}).get('Id') or '')
            if not container_id:
                return None
            archive = _tar_bytes({
                'tool/runner.py': RUNNER,
                'tool/tool.py': code,
                'tool/docker.py': DOCKER_SHIM,
            })
            uploaded = requests.put(
                f'{api_url}/containers/{container_id}/archive',
                params={'path': '/opt'},
                data=archive,
                headers={'Content-Type': 'application/x-tar'},
                timeout=10,
            )
            uploaded.raise_for_status()
            started = requests.post(f'{api_url}/containers/{container_id}/start', timeout=5)
            started.raise_for_status()
            try:
                waited = requests.post(f'{api_url}/containers/{container_id}/wait', timeout=seconds + 5)
                waited.raise_for_status()
                exit_code = int((waited.json() or {}).get('StatusCode') or 0)
            except requests.Timeout:
                requests.post(f'{api_url}/containers/{container_id}/kill', timeout=5)
                return {
                    'success': False,
                    'exit_code': -1,
                    'stdout': '',
                    'stderr': '',
                    'error': f'Execution timed out after {seconds} seconds.',
                    'sandbox': 'docker',
                }
            logs = requests.get(
                f'{api_url}/containers/{container_id}/logs',
                params={'stdout': 1, 'stderr': 1},
                timeout=5,
            )
            logs.raise_for_status()
            output = _decode_docker_logs(logs.content).strip()
            return {
                'success': exit_code == 0,
                'exit_code': exit_code,
                'stdout': _clip(output).strip(),
                'stderr': '',
                'error': None if exit_code == 0 else 'Tool process exited with an error.',
                'sandbox': 'docker',
            }
        except requests.RequestException:
            if not container_id:
                return None
            return _failure('Docker sandbox could not run the tool.')
        finally:
            if container_id:
                try:
                    requests.delete(f'{api_url}/containers/{container_id}', params={'force': 1}, timeout=5)
                except requests.RequestException:
                    pass


def _clip(value, limit=8000):
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return value[:limit]


def _failure(message):
    return {"success": False, "exit_code": -1, "stdout": "", "stderr": message, "error": message}
