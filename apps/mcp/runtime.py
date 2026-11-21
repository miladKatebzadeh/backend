import os
import subprocess
import sys
import tempfile

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


class MCPSandboxExecutor:
    @staticmethod
    def execute_tool_safe(tool_code: str, env_vars: dict | None = None) -> dict:
        env_vars = env_vars or {}
        code = tool_code or ""
        if not code.strip():
            return _failure("Tool code is empty.")
        if "@mcp.tool" in code and "import mcp" not in code:
            code = "import mcp\n" + code

        script_path = None
        runner_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".py", mode="w", encoding="utf-8", delete=False) as script_file:
                script_file.write(code)
                script_path = script_file.name
            with tempfile.NamedTemporaryFile(suffix=".py", mode="w", encoding="utf-8", delete=False) as runner_file:
                runner_file.write(RUNNER)
                runner_path = runner_file.name

            child_env = {
                "PATH": os.environ.get("PATH", ""),
                "HOME": os.environ.get("HOME", "/tmp"),
                "LANG": os.environ.get("LANG", "C.UTF-8"),
                "LC_ALL": "C.UTF-8",
                "PYTHONUNBUFFERED": "1",
                "PYTHONIOENCODING": "utf-8",
                "TARGET_RESOURCE": str(env_vars.get("TARGET_RESOURCE", "")),
                "TOOL_SCRIPT": script_path,
            }
            docker_host = env_vars.get("DOCKER_HOST") or os.environ.get("DOCKER_HOST")
            if docker_host:
                child_env["DOCKER_HOST"] = docker_host

            try:
                completed = subprocess.run(
                    [sys.executable, runner_path],
                    capture_output=True,
                    text=True,
                    env=child_env,
                    timeout=15,
                )
            except subprocess.TimeoutExpired as exc:
                return {
                    "success": False,
                    "exit_code": -1,
                    "stdout": _clip(exc.stdout),
                    "stderr": _clip(exc.stderr),
                    "error": "Execution timed out after 15 seconds.",
                }
            return {
                "success": completed.returncode == 0,
                "exit_code": completed.returncode,
                "stdout": _clip(completed.stdout).strip(),
                "stderr": _clip(completed.stderr).strip(),
                "error": None if completed.returncode == 0 else "Tool process exited with an error.",
            }
        except Exception as exc:
            return _failure(f"Internal execution failure: {exc}")
        finally:
            for path in (script_path, runner_path):
                if path and os.path.exists(path):
                    os.remove(path)


def _clip(value, limit=8000):
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return value[:limit]


def _failure(message):
    return {"success": False, "exit_code": -1, "stdout": "", "stderr": message, "error": message}
