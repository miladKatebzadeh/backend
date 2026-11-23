"""Find meaningful CI failures instead of Jenkins and npm help/footer messages.

The selected lines are observations, not a verified root cause. Keep evidence
bounded, scrub common credentials and do not infer commands or stage ownership.
"""
import re
from urllib.parse import quote

import requests

from apps.mcp.trace_presentation import safe_text

_MAX_SOURCE_CHARS = 500_000
_MAX_ERROR_LINES = 4
_STAGE = re.compile(r"^\[Pipeline\]\s*\{\s*\(([^)]+)\)\s*$")
_COMMAND = re.compile(r"^\+\s+(.+)$")
_EXIT = re.compile(r"script returned exit code\s+(\d+)", re.IGNORECASE)
_WRAPPER = re.compile(
    r"^(?:\[Pipeline\](?:\s|$)|Finished:\s*(?:FAILURE|UNSTABLE|ABORTED|SUCCESS)"
    r"|ERROR:\s*script returned exit code\s+\d+"
    r"|org\.jenkinsci\.plugins\.workflow\.steps\.FlowInterruptedException"
    r"|hudson\.AbortException:\s*script returned exit code\s+\d+)",
    re.IGNORECASE,
)
_NPM_FOOTER = re.compile(
    r"^npm\s+(?:ERR!|error)\s*(?:"
    r"A complete log of this run|A complete log of this run can be found"
    r"|Run [\"']?npm help|aliases:|Usage:|Options:|For more info"
    r"|npm ci\s*$|$|\s*$|\S+\s*\([^)]*\)\s*$)",
    re.IGNORECASE,
)
_NPM_HELP = re.compile(
    r"^npm\s+(?:ERR!|error)\s*(?:"
    r"Clean install a project|Install a project with a clean slate"
    r"|Run [\"']?npm help|aliases:|Usage:|Options:"
    r"|A complete log|npm ci\s*$|$)",
    re.IGNORECASE,
)
_NPM_CODE = re.compile(r"^npm\s+(?:ERR!|error)\s+code\s+([A-Z][A-Z0-9_]+)\b", re.IGNORECASE)
_NPM_CAUSE = re.compile(
    r"(?:\b(?:EUSAGE|ERESOLVE|ENOENT|EACCES|EINTEGRITY|ETARGET|ENOTFOUND)\b"
    r"|\b(?:Missing|Invalid):\s|package-lock\.json|npm-shrinkwrap\.json"
    r"|(?:package\.json\s+and\s+package-lock\.json)"
    r"|\bcannot\s+(?:install|resolve|find|read)|\bunable to resolve"
    r"|\bdependency tree\b|\bconflicting peer dependency\b)",
    re.IGNORECASE,
)
_STRONG = re.compile(
    r"(?:ModuleNotFoundError|ImportError|FileNotFoundError|PermissionError"
    r"|NameError|SyntaxError|TypeError|AssertionError|Traceback \(most recent call last\)"
    r"|OCI runtime create failed|runc create failed|executable file not found"
    r"|no such file or directory|not found in \$PATH|command not found"
    r"|permission denied|access denied|no space left on device"
    r"|out of memory|OOMKilled|cannot find module|Could not resolve"
    r"|failed to (?:build|create|connect|start|pull|load|install|compile|resolve)"
    r"|connection refused|cannot connect|Error response from daemon"
    r"|error TS\d+|\b(?:pytest|test)\s+failed\b"
    r"|(?:fatal|error):\s*\S)",
    re.IGNORECASE,
)
_ERROR = re.compile(
    r"(?:\b(?:exception|fatal|error|failed|failure|timed out|timeout|denied|refused)"
    r"\b|(?:^|\s)ERROR(?:\s|:))",
    re.IGNORECASE,
)
_IGNORE = re.compile(
    r"^\s*(?:\[Pipeline\]|Finished:|Pipeline failed!?|"
    r"ERROR:\s*script returned exit code|\+\s*echo\b)",
    re.IGNORECASE,
)


def _sanitized(line, limit=260):
    return safe_text(line, limit)


def _score(line):
    """Actionable descriptions outrank error codes; npm help text scores zero."""
    stripped = line.strip()
    if not stripped or _WRAPPER.search(stripped) or _IGNORE.search(stripped):
        return 0
    if _NPM_FOOTER.search(stripped) or _NPM_HELP.search(stripped):
        return 0
    if stripped.lower().startswith(("npm error", "npm err!")):
        if _NPM_CODE.search(stripped):
            return 2
        if _NPM_CAUSE.search(stripped):
            return 6
        if _STRONG.search(stripped) and len(stripped) > 23:
            return 5
        if len(stripped) >= 36 and _ERROR.search(stripped):
            return 3
        return 0
    if _STRONG.search(stripped):
        return 5
    if _ERROR.search(stripped) and not stripped.lstrip().startswith(("+ ", "> ")):
        return 3
    return 0


def _command_matches_error(command, error):
    """A nearby git rev-parse is NOT an npm install command."""
    if not command:
        return False
    c = command.lower()
    e = error.lower()
    if e.startswith(("npm error", "npm err!")):
        return bool(re.search(r"\b(npm|npx|pnpm|yarn)\b", c))
    if "error ts" in e or "cannot find module" in e:
        return bool(re.search(r"\b(npm|npx|pnpm|yarn|node|tsc)\b", c))
    return True


def _analyze_lines(lines):
    records = []
    stage = None
    commands = []
    exit_code = None
    for index, raw in enumerate(lines):
        stripped = raw.strip()
        if stripped.startswith("[Pipeline] // stage"):
            stage = None
            commands = []
            continue
        match = _STAGE.match(stripped)
        if match:
            stage = _sanitized(match.group(1), 100)
            commands = []
        shell = _COMMAND.match(stripped)
        if shell:
            commands.append((index, _sanitized(shell.group(1), 230)))
            commands = commands[-12:]
        returned = _EXIT.search(stripped)
        if returned:
            exit_code = int(returned.group(1))
        score = _score(stripped)
        if score:
            linked_command = next((
                previous for position, previous in reversed(commands)
                if 0 <= index - position <= 50
                and _command_matches_error(previous, stripped)
            ), None)
            records.append({
                "index": index,
                "score": score,
                "message": _sanitized(stripped),
                "stage": stage,
                "command": linked_command,
            })

    ranked = sorted(records, key=lambda item: (item["score"], item["index"]), reverse=True)
    selected = []
    seen = set()
    for item in ranked:
        if item["message"] in seen:
            continue
        selected.append(item)
        seen.add(item["message"])
        if len(selected) >= _MAX_ERROR_LINES:
            break

    primary = selected[0] if selected else None
    window = []
    if primary:
        start = max(0, primary["index"] - 4)
        end = min(len(lines), primary["index"] + 6)
        window = [_sanitized(line) for line in lines[start:end] if line.strip()]
    npm_failure = any(
        line.strip().lower().startswith(("npm error", "npm err!"))
        for line in lines
    )
    if primary:
        diagnostic_status = "specific_error_found"
    elif npm_failure:
        diagnostic_status = "insufficient_console_detail"
    else:
        diagnostic_status = "only_generic_build_failure"
    return {
        "diagnostic_status": diagnostic_status,
        "primary_error": primary["message"] if primary else None,
        "failing_stage": primary["stage"] if primary else None,
        "failing_command": primary["command"] if primary else None,
        "error_lines": [item["message"] for item in selected],
        "error_context": window[:9],
        "execution_exit_code": exit_code,
        "original_line_count": len(lines),
        "source": "jenkins_console",
        "root_cause_confirmed": False,
    }


def analyze_jenkins_console(text):
    source = str(text or "")
    truncated = len(source) > _MAX_SOURCE_CHARS
    result = _analyze_lines(source[-_MAX_SOURCE_CHARS:].splitlines())
    result["source_truncated"] = truncated
    return result


def select_jenkins_console(text, limit_chars=14000):
    """Retain critical windows from the fetched console, not just footer lines."""
    source = str(text or "")[-_MAX_SOURCE_CHARS:]
    lines = source.splitlines()
    analysis = _analyze_lines(lines)
    indices = set(range(max(0, len(lines) - 18), len(lines)))
    for message in analysis["error_lines"][:3]:
        matches = [i for i, line in enumerate(lines) if _sanitized(line.strip()) == message]
        if not matches:
            continue
        center = matches[-1]
        indices.update(range(max(0, center - 6), min(len(lines), center + 6)))
        for j in range(center, max(-1, center - 70), -1):
            if _STAGE.match(lines[j].strip()):
                indices.add(j)
                break
        for j in range(center, max(-1, center - 30), -1):
            shell = _COMMAND.match(lines[j].strip())
            if shell and _command_matches_error(shell.group(1), message):
                indices.add(j)
                break
    selected = [_sanitized(lines[i], 330) for i in sorted(indices) if lines[i].strip()]
    joined = "\n".join(selected)
    if len(joined) > limit_chars:
        # Keep actual failure evidence before generic end-of-build output.
        evidence_lines = []
        for message in analysis["error_lines"][:3]:
            evidence_lines.extend([message, *analysis["error_context"]])
        prefix = "\n".join(dict.fromkeys(evidence_lines))
        if len(prefix) < limit_chars:
            joined = prefix + "\n" + joined[-(limit_chars - len(prefix) - 1):]
    return joined[:limit_chars]


def fetch_jenkins_build_console(job_name, build_number):
    """Bounded read-only fetch of the *exact* Jenkins Build console.

    Used only by Incident-linked diagnoses when existing evidence contains no
    substantive error. Credentials and URL are never included in trace output.
    """
    from apps.mcp.models import get_setting
    import os

    job_name = str(job_name or "").strip()
    if not job_name or len(job_name) > 255:
        return None
    try:
        number = int(build_number)
    except (TypeError, ValueError):
        return None
    if number < 1:
        return None

    base = get_setting("jenkins_url", os.getenv("JENKINS_URL", "")).rstrip("/")
    if not base.startswith(("http://", "https://")):
        return None
    username = get_setting("jenkins_user", os.getenv("JENKINS_USER", ""))
    token = get_setting("jenkins_token", os.getenv("JENKINS_TOKEN", ""))
    auth = (username, token) if username and token else None
    try:
        # Jenkins fullName may contain nested folder jobs.
        parts = [quote(item, safe="") for item in job_name.split("/") if item]
        path = "/job/".join(parts)
        url = f"{base}/job/{path}/{number}/consoleText"
        response = requests.get(url, auth=auth, timeout=(3, 8))
        response.raise_for_status()
        if not response.text:
            return None
        return response.text[-_MAX_SOURCE_CHARS:]
    except requests.RequestException:
        return None
