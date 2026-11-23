"""Read-only, resource-scoped diagnostics for Docker and Prometheus incidents.

The returned observations are bounded and sanitized. An observed error is not
automatically a verified root cause, and live checks never rewrite old events.
"""
import logging
import math
import os
import re
from datetime import timedelta
import requests
from django.utils import timezone

from apps.mcp.trace_presentation import safe_text

logger = logging.getLogger(__name__)

_MAX_LOG_CHARS = 40000
_MAX_SAMPLES = 32
_METRIC_NAME = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")
_CONTAINER_ID = re.compile(r"^[a-fA-F0-9]{12,64}$")
_DOCKER_FAILURES = (
    ("out_of_memory", r"\b(?:out of memory|oomkilled|cannot allocate memory|memory cgroup out of memory)\b"),
    ("disk_full", r"\b(?:no space left on device|ENOSPC)\b"),
    ("port_conflict", r"\b(?:address already in use|port is already allocated|bind: address already in use)\b"),
    ("missing_executable", r"\b(?:executable file not found|command not found|no such file or directory|ModuleNotFoundError|Cannot find module)\b"),
    ("permission_denied", r"\b(?:permission denied|EACCES|operation not permitted)\b"),
    ("database_connection", r"\b(?:database.*connection refused|could not connect to server|connection to .*5432.*failed)\b"),
    ("network_connection", r"\b(?:connection refused|connection timed out|name or service not known|temporary failure in name resolution|ENOTFOUND|EAI_AGAIN)\b"),
    ("configuration_error", r"\b(?:configuration error|invalid configuration|missing required environment variable|KeyError:)\b"),
    ("startup_failure", r"\b(?:failed to start|failed to initialize|fatal error|panic:|Traceback \(most recent call last\))\b"),
)
_DOCKER_COMPILED = [(name, re.compile(pattern, re.IGNORECASE)) for name, pattern in _DOCKER_FAILURES]
_GENERIC_LOG = re.compile(r"^(?:\s*\[Pipeline\]|\s*Finished:|\s*\[INFO\]|\s*INFO\b)", re.IGNORECASE)


def _safe(value, limit=260):
    return safe_text(value, limit) if value is not None else ""


def _positive_number(value):
    try:
        number = float(value)
        return number if math.isfinite(number) else None
    except (TypeError, ValueError):
        return None


def analyze_docker_observation(observation):
    """Classify the strongest *observed* failure, never infer OOM from exit 137."""
    row = observation if isinstance(observation, dict) else {}
    logs = str(row.get("logs") or row.get("container_logs") or "")[-_MAX_LOG_CHARS:]
    records = []
    for index, line in enumerate(logs.splitlines()[-140:]):
        if _GENERIC_LOG.match(line) or not line.strip():
            continue
        for rank, (code, pattern) in enumerate(_DOCKER_COMPILED):
            if pattern.search(line):
                records.append((len(_DOCKER_COMPILED) - rank, index, code, _safe(line)))
                break
    records.sort(reverse=True)
    primary = records[0] if records else None
    oom = row.get("oom_killed") is True
    state_error = _safe(row.get("state_error"))
    if oom:
        category, issue, diagnostic_status = (
            "oom_killed",
            "Docker explicitly recorded an out-of-memory (OOMKilled) termination.",
            "confirmed_termination_mechanism",
        )
        primary_message = "Docker inspect: OOMKilled=true"
    elif state_error:
        category, issue, diagnostic_status = (
            "docker_state_error", "Docker reported a runtime state error.", "specific_error_found"
        )
        primary_message = state_error
    elif primary:
        _, _, category, primary_message = primary
        issue = "The container emitted a specific failure message."
        diagnostic_status = "specific_error_found"
    else:
        category = "unclassified"
        diagnostic_status = "insufficient_evidence"
        primary_message = None
        issue = (
            "Docker reported a stopped or unhealthy container, but no specific error was captured."
            if str(row.get("status") or "").lower() in ("exited", "dead", "restarting", "unhealthy")
            else "No specific container failure could be established from the available sample."
        )
    return {
        "diagnostic_status": diagnostic_status,
        "category": category,
        "issue": issue,
        "primary_error": primary_message,
        "exit_code": row.get("exit_code"),
        "oom_killed": oom,
        "container_status": _safe(row.get("status"), 50) or None,
        "restart_count": row.get("restart_count"),
        "health_status": _safe(row.get("health_status"), 50) or None,
        "evidence_origin": _safe(row.get("evidence_origin") or "stored_docker_sample", 60),
        "root_cause_confirmed": bool(oom),
        "observed_errors": [item[3] for item in records[:4]],
    }


def _decode_docker_logs(data):
    """Decode multiplexed Docker stdout/stderr frames when present."""
    raw = bytes(data or b"")[:_MAX_LOG_CHARS * 2]
    if len(raw) >= 8 and raw[0] in (1, 2) and raw[1:4] == b"\0\0\0":
        index, output = 0, []
        while index + 8 <= len(raw):
            size = int.from_bytes(raw[index + 4:index + 8], "big")
            index += 8
            if size > len(raw) - index:
                break
            output.append(raw[index:index + size])
            index += size
        raw = b"".join(output)
    return raw.decode("utf-8", errors="replace")[-_MAX_LOG_CHARS:]


def fetch_docker_evidence(container_name):
    """Read Docker list, exact container inspect and bounded logs; no mutations."""
    from apps.collector.tasks import _docker_api
    wanted = str(container_name or "").strip().lstrip("/")
    if not wanted or len(wanted) > 255:
        return None
    base = _docker_api()
    if not base:
        return None
    try:
        listed = requests.get(f"{base}/containers/json", params={"all": 1}, timeout=(2, 4))
        listed.raise_for_status()
        containers = listed.json()
        if not isinstance(containers, list):
            return None
        match = next((
            row for row in containers if isinstance(row, dict)
            and wanted in [str(n).lstrip("/") for n in (row.get("Names") or [])]
        ), None)
        if match is None:
            return {"status": "not_found", "evidence_origin": "live_docker_read_only"}
        identifier = str(match.get("Id") or "")
        if not _CONTAINER_ID.fullmatch(identifier):
            return None
        inspected = requests.get(f"{base}/containers/{identifier}/json", timeout=(2, 4))
        inspected.raise_for_status()
        details = inspected.json()
        if not isinstance(details, dict):
            return None
        state = details.get("State") or {}
        try:
            logs = requests.get(
                f"{base}/containers/{identifier}/logs",
                params={"stdout": 1, "stderr": 1, "tail": 120, "timestamps": 0},
                timeout=(2, 4),
            )
            logs.raise_for_status()
            log_text = _decode_docker_logs(logs.content)
        except requests.RequestException:
            # Docker inspect and OOMKilled remain useful when the log endpoint fails.
            log_text = ""
        return {
            "status": _safe(state.get("Status") or match.get("State"), 50),
            "oom_killed": state.get("OOMKilled") is True,
            "exit_code": state.get("ExitCode"),
            "state_error": _safe(state.get("Error")),
            "restart_count": details.get("RestartCount"),
            "health_status": _safe((state.get("Health") or {}).get("Status"), 50),
            "image": _safe((details.get("Config") or {}).get("Image"), 140),
            "logs": log_text,
            "evidence_origin": "live_docker_read_only",
            "checked_at": timezone.now().isoformat(),
        }
    except (requests.RequestException, ValueError, TypeError, KeyError):
        logger.info("Read-only Docker diagnostic lookup failed for scoped container", exc_info=True)
        return None


def analyze_metric_observation(metric, window=None):
    """Explain what a metric/alert *measures*, not a made-up process-level cause."""
    row = metric if isinstance(metric, dict) else {}
    name = _safe(row.get("metric"), 180)
    metric_type = str(row.get("type") or "generic").lower()
    status = str(row.get("status") or "unknown").upper()
    value = _positive_number(row.get("value"))
    labels = row.get("labels") if isinstance(row.get("labels"), dict) else {}
    if metric_type == "host_memory_bounds" and value is not None:
        issue = f"Available host memory measured {value / (1024**3):.2f} GiB."
        category = "low_available_memory"
        steps = "Reduce verified memory pressure or increase available host memory."
    elif metric_type == "host_disk_space" and value is not None:
        issue = f"Available filesystem space measured {value / (1024**3):.2f} GiB."
        category = "low_disk_space"
        steps = "Free space on the affected filesystem or expand its capacity."
    elif metric_type == "host_cpu_utilization" and value is not None:
        issue = f"Host CPU utilization measured {value:.1f}%."
        category = "high_cpu_utilization"
        steps = "Reduce confirmed high CPU demand or scale capacity for the affected workload."
    elif name.startswith("alert:"):
        alertname = _safe(labels.get("alertname") or name.removeprefix("alert:"), 110)
        issue = f"The {alertname} alert is recorded as {status}."
        detail = row.get("alert_detail") if isinstance(row.get("alert_detail"), dict) else {}
        if detail.get("status") == "observed":
            description = _safe(detail.get("summary") or detail.get("description"), 240)
            if description:
                issue += f" Monitoring provider details: {description}"
        category = "firing_alert"
        steps = "Apply the resolution specific to the alert's verified condition and affected resource."
    else:
        issue = f"Monitoring recorded {name} with state {status}."
        category = "unclassified_metric"
        steps = "Investigate the monitored condition using its validated thresholds and labels."
    range_data = window if isinstance(window, dict) else {}
    return {
        "diagnostic_status": "observed_alert" if status != "NORMAL" else "observed_metric",
        "category": category,
        "issue": issue,
        "metric": name,
        "metric_type": metric_type,
        "status": status,
        "value": value,
        "labels": {str(k)[:60]: _safe(v, 100) for k, v in list(labels.items())[:12]},
        "recommended_direction": steps,
        "time_window": range_data,
        "evidence_origin": (
            "collector_and_prometheus_range" if range_data.get("status") == "observed"
            else "collector_and_active_alert" if isinstance(row.get("alert_detail"), dict)
            and row["alert_detail"].get("status") == "observed"
            else "stored_metric_sample"
        ),
        "root_cause_confirmed": False,
    }


def fetch_prometheus_window(metric_name, labels, observed_at):
    """Query an allowlisted metric identifier for a bounded time window.

    No arbitrary PromQL is accepted from Incident text. If multiple unlabeled
    series are returned, the measurement is explicitly marked ambiguous.
    """
    from apps.mcp.models import get_setting
    metric_name = str(metric_name or "").strip()
    if not _METRIC_NAME.fullmatch(metric_name) or len(metric_name) > 200:
        return None
    base = (get_setting("prometheus_url", os.getenv("PROMETHEUS_URL", "http://127.0.0.1:9090")) or "").rstrip("/")
    if not base.startswith(("http://", "https://")):
        return None
    anchor = observed_at or timezone.now()
    start = anchor - timedelta(minutes=15)
    end = min(timezone.now(), anchor + timedelta(minutes=2))
    if end <= start:
        return None
    try:
        response = requests.get(
            f"{base}/api/v1/query_range",
            params={"query": metric_name, "start": start.timestamp(), "end": end.timestamp(), "step": "60s"},
            timeout=(2, 5),
        )
        response.raise_for_status()
        data = response.json()
        if data.get("status") != "success":
            return None
        series = (data.get("data") or {}).get("result") or []
        if not isinstance(series, list):
            return None
        known = {
            key: str(value)
            for key, value in (labels if isinstance(labels, dict) else {}).items()
            if key in ("instance", "job", "device", "mountpoint", "cpu", "mode") and value is not None
        }
        if known:
            series = [s for s in series if isinstance(s, dict) and all(
                str((s.get("metric") or {}).get(k)) == v for k, v in known.items()
            )]
        if len(series) != 1:
            return {"status": "ambiguous_series" if len(series) > 1 else "no_samples", "samples": 0}
        values = []
        for point in (series[0].get("values") or [])[-_MAX_SAMPLES:]:
            if isinstance(point, list) and len(point) >= 2:
                number = _positive_number(point[1])
                if number is not None:
                    values.append(number)
        if not values:
            return {"status": "no_samples", "samples": 0}
        return {
            "status": "observed", "samples": len(values),
            "first": values[0], "last": values[-1],
            "minimum": min(values), "maximum": max(values),
            "start": start.isoformat(), "end": end.isoformat(),
            "source": "prometheus_query_range",
        }
    except (requests.RequestException, ValueError, TypeError, KeyError):
        logger.info("Read-only Prometheus range query failed", exc_info=True)
        return None


def fetch_active_alert(alert_name, source="prometheus", labels=None):
    """Read the corresponding alert definition without exposing provider URLs."""
    from apps.mcp.models import get_setting
    name = str(alert_name or "").removeprefix("alert:").strip()
    known = {
        k: str(v) for k, v in (labels if isinstance(labels, dict) else {}).items()
        if k in ("instance", "job", "device", "mountpoint") and v is not None
    }
    if not name or len(name) > 180:
        return None
    if source == "alertmanager":
        base = (get_setting("alertmanager_url", os.getenv("ALERTMANAGER_URL", "")) or "").rstrip("/")
        path, params = "/api/v2/alerts", {"active": "true"}
    else:
        base = (get_setting("prometheus_url", os.getenv("PROMETHEUS_URL", "http://127.0.0.1:9090")) or "").rstrip("/")
        path, params = "/api/v1/alerts", None
    if not base.startswith(("http://", "https://")):
        return None
    try:
        response = requests.get(f"{base}{path}", params=params, timeout=(2, 5))
        response.raise_for_status()
        body = response.json()
        alerts = body if isinstance(body, list) else (body.get("data") or {}).get("alerts") or []
        if not isinstance(alerts, list):
            return None
        for row in alerts[:100]:
            if not isinstance(row, dict):
                continue
            labels = row.get("labels") or {}
            if str(labels.get("alertname")) != name:
                continue
            if known and not all(str(labels.get(k)) == v for k, v in known.items()):
                continue
            annotations = row.get("annotations") or {}
            state = row.get("state") or (row.get("status") or {}).get("state")
            return {
                "status": "observed",
                "alertname": _safe(name, 120),
                "state": _safe(state, 35),
                "summary": _safe(annotations.get("summary"), 220),
                "description": _safe(annotations.get("description"), 340),
                "instance": _safe(labels.get("instance"), 100),
                "severity": _safe(labels.get("severity"), 35),
                "source": "live_alert_read_only",
                "checked_at": timezone.now().isoformat(),
            }
        return {"status": "not_active_or_unavailable", "source": "live_alert_read_only"}
    except (requests.RequestException, ValueError, TypeError, KeyError):
        logger.info("Read-only monitoring alert lookup failed", exc_info=True)
        return None
