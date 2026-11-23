"""Extract actionable Jenkins failure evidence from the full console output.

Jenkins pipeline wrappers (e.g. "script returned exit code 1", "Finished:
FAILURE", "[Pipeline] // timeout") indicate a failed run but do not identify a
root cause. The analyzer keeps a bounded surrounding window and provenance
for genuine error messages. No command is executed or inferred as successful.
"""
import re

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
_STRONG = re.compile(
    r"(?:ModuleNotFoundError|ImportError|FileNotFoundError|PermissionError"
    r"|NameError|SyntaxError|TypeError|AssertionError|Traceback \(most recent call last\)"
    r"|OCI runtime create failed|runc create failed|executable file not found"
    r"|no such file or directory|not found in \$PATH|command not found"
    r"|permission denied|access denied|no space left on device"
    r"|out of memory|OOMKilled|cannot find module|Could not resolve"
    r"|failed to (?:build|create|connect|start|pull|load|install|compile|resolve)"
    r"|connection refused|cannot connect|Error response from daemon"
    r"|npm ERR!|npm error|error TS\d+|\b(?:pytest|test)\s+failed\b"
    r"|(?:fatal|error):\s*\S)",
    re.IGNORECASE,
)
_ERROR = re.compile(
    r"(?:\b(?:exception|fatal|error|failed|failure|timed out|timeout|denied|refused)"
    r"\b|(?:^|\s)ERROR(?:\s|:))",
    re.IGNORECASE,
)
_IGNORE = re.compile(
    r"^(?:\s*(?:\[Pipeline\]|Finished:|Pipeline failed!?|"
    r"ERROR:\s*script returned exit code|\+\s*echo\b))",
    re.IGNORECASE,
)


def _score(line):
    """Only substantive error messages count as possible causal evidence."""
    if not line or _WRAPPER.search(line) or _IGNORE.search(line):
        return 0
    if _STRONG.search(line):
        return 3
    if _ERROR.search(line) and not line.lstrip().startswith(("+ ", "> ")):
        return 2
    return 0


def _sanitized(line, limit=260):
    return safe_text(line, limit)


def _analyze_lines(lines):
    records = []
    stage = None
    command = None
    command_line = -1000
    exit_code = None
    for index, raw in enumerate(lines):
        stripped = raw.strip()
        match = _STAGE.match(stripped)
        if match:
            stage = _sanitized(match.group(1), 100)
        shell = _COMMAND.match(stripped)
        if shell:
            command = _sanitized(shell.group(1), 230)
            command_line = index
        returned = _EXIT.search(stripped)
        if returned:
            exit_code = int(returned.group(1))
        score = _score(stripped)
        if score:
            records.append({
                "index": index,
                "score": score,
                "message": _sanitized(stripped),
                "stage": stage,
                "command": command if index - command_line <= 75 else None,
            })

    # Prefer exact failures over status text; break ties by the latest event.
    ranked = sorted(records, key=lambda item: (item["score"], item["index"]), reverse=True)
    selected = []
    seen = set()
    for item in ranked:
        if item["message"] in seen:
            continue
        seen.add(item["message"])
        selected.append(item)
        if len(selected) >= _MAX_ERROR_LINES:
            break

    primary = selected[0] if selected else None
    window = []
    if primary:
        start = max(0, primary["index"] - 3)
        end = min(len(lines), primary["index"] + 4)
        window = [_sanitized(line) for line in lines[start:end] if line.strip()]
    return {
        "diagnostic_status": "specific_error_found" if primary else "only_generic_build_failure",
        "primary_error": primary["message"] if primary else None,
        "failing_stage": primary["stage"] if primary else None,
        "failing_command": primary["command"] if primary else None,
        "error_lines": [item["message"] for item in selected],
        "error_context": window[:8],
        "execution_exit_code": exit_code,
        "original_line_count": len(lines),
        "source": "jenkins_console",
        "root_cause_confirmed": False,
    }


def analyze_jenkins_console(text):
    """Summarize a bounded source window without treating wrappers as causes."""
    source = str(text or "")
    if len(source) > _MAX_SOURCE_CHARS:
        source = source[-_MAX_SOURCE_CHARS:]
        truncated = True
    else:
        truncated = False
    result = _analyze_lines(source.splitlines())
    result["source_truncated"] = truncated
    return result


def select_jenkins_console(text, limit_chars=14000):
    """Save high-signal failure windows, not just the last 100 Jenkins lines.

    Include stage/command provenance and a short tail. The stored selection is
    bounded and sanitized; the full raw console is never persisted here.
    """
    source = str(text or "")[-_MAX_SOURCE_CHARS:]
    lines = source.splitlines()
    analysis = _analyze_lines(lines)
    indices = set(range(max(0, len(lines) - 22), len(lines)))
    for message in analysis["error_lines"][:3]:
        # Match using the exact sanitized form that was scored above.
        matches = [i for i, line in enumerate(lines) if _sanitized(line.strip()) == message]
        if not matches:
            continue
        center = matches[-1]
        indices.update(range(max(0, center - 4), min(len(lines), center + 4)))
        for j in range(center, max(-1, center - 85), -1):
            if _STAGE.match(lines[j].strip()):
                indices.add(j)
                break
        for j in range(center, max(-1, center - 75), -1):
            if _COMMAND.match(lines[j].strip()):
                indices.add(j)
                break
    selected = [_sanitized(lines[i], 330) for i in sorted(indices) if lines[i].strip()]
    # Favor the error windows: cut nonessential trailing output before actual
    # error evidence if the selected result exceeds the storage budget.
    joined = "\n".join(selected)
    return joined[:limit_chars]
