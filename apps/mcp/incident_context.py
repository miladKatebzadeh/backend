"""Build time-correlated Alert + Error evidence before routing or retrieval.

Only a known source/resource pair is used for scoped lookups. Do not persist raw
alerts as Chroma documents: Chroma holds runbooks, not transient observations.
"""
import re
from datetime import timedelta

from django.utils import timezone

from apps.collector.models import DockerMetric, JenkinsBuild, PrometheusAlert


_ERROR_LINE = re.compile(
    r"\b(error|exception|fatal|failed|failure|oom|out of memory|killed|panic|traceback|"
    r"denied|refused|timeout|no space left|unhealthy|back.off)\b",
    re.IGNORECASE,
)
_CREDENTIAL = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*[^\s,;]+"
)
_BEARER = re.compile(r"(?i)\bBearer\s+[^\s,;]+")


def _redact(value, limit=240):
    value = str(value or "").replace("\x00", "")
    value = _BEARER.sub("Bearer [REDACTED]", value)
    value = _CREDENTIAL.sub(lambda m: m.group(1) + "=[REDACTED]", value)
    return re.sub(r"\s+", " ", value).strip()[:limit]


def _error_lines(text, limit=3):
    lines = []
    for line in str(text or "").splitlines():
        if _ERROR_LINE.search(line):
            cleaned = _redact(line)
            if cleaned and cleaned not in lines:
                lines.append(cleaned)
            if len(lines) == limit:
                break
    return lines


def _timestamp(value):
    return value.isoformat() if value else None


def _source_family(source):
    return {
        "docker": "container_runtime",
        "jenkins": "ci_failure",
        "prometheus": "metric_anomaly",
        "alertmanager": "metric_anomaly",
    }.get(source or "", "unknown")


def _scope_window(observed_at, window_minutes=15):
    """Bound samples around the alert timestamp; never use unrelated old rows."""
    anchor = observed_at or timezone.now()
    return anchor - timedelta(minutes=window_minutes), min(
        timezone.now(), anchor + timedelta(minutes=window_minutes)
    )


def build_incident_context(message, resource_scope=None, observed_at=None):
    """Return one structured, source-scoped diagnosis input.

    All error indicators are observations, not presumed root causes.
    An empty evidence block means telemetry for the window was unavailable.
    """
    resource_scope = resource_scope if isinstance(resource_scope, dict) else {}
    source = str(resource_scope.get("source") or "").strip().lower()
    resource = str(resource_scope.get("resource") or "").strip()
    start, end = _scope_window(observed_at)
    alert = {
        "message": _redact(message, 350),
        "source": source or None,
        "resource": resource or None,
        "family": _source_family(source),
        "status": resource_scope.get("status"),
        "severity": resource_scope.get("severity"),
        "observed_at": _timestamp(observed_at),
        "incident_id": resource_scope.get("incident_id"),
    }
    errors = []
    evidence = {}

    def add_error(kind, text, origin, timestamp):
        if len(errors) < 6:
            errors.append({
                "kind": kind,
                "message": _redact(text),
                "source": origin,
                "observed_at": _timestamp(timestamp),
            })

    if resource and start <= end and source == "docker":
        rows = list(
            DockerMetric.objects.filter(
                container_name=resource, timestamp__gte=start, timestamp__lte=end
            ).order_by("-timestamp", "-id")[:2]
        )
        evidence["container_telemetry"] = []
        for row in rows:
            stats = row.raw_stats if isinstance(row.raw_stats, dict) else {}
            state_error = _redact(stats.get("state_error"))
            exit_code = stats.get("exit_code")
            entry = {
                "container": row.container_name,
                "status": row.status,
                "oom_killed": bool(row.oom_killed),
                "restart_count": row.restart_count,
                "exit_code": exit_code,
                "state_error": state_error,
                "image": _redact(stats.get("image"), 150),
                "finished_at": stats.get("finished_at"),
                "cpu_percent": row.cpu_percent,
                "mem_usage_mb": row.mem_usage_mb,
                "timestamp": _timestamp(row.timestamp),
                "log_errors": _error_lines(row.container_logs),
            }
            evidence["container_telemetry"].append(entry)
            if row.oom_killed:
                add_error("oom_killed", "Docker reports OOMKilled=true", "docker_inspect", row.timestamp)
            if exit_code not in (None, "", 0, "0"):
                add_error("exit_code", f"Container exit code {exit_code}", "docker_inspect", row.timestamp)
            if state_error:
                add_error("state_error", state_error, "docker_inspect", row.timestamp)
            for line in entry["log_errors"]:
                add_error("log_error", line, "docker_logs", row.timestamp)
    elif resource and start <= end and source == "jenkins":
        rows = list(
            JenkinsBuild.objects.filter(
                job_name=resource, updated_at__gte=start, updated_at__lte=end
            ).order_by("-updated_at", "-build_number", "-id")[:2]
        )
        evidence["ci_pipeline_logs"] = []
        for row in rows:
            entry = {
                "job": row.job_name,
                "build_number": row.build_number,
                "result": row.result,
                "updated_at": _timestamp(row.updated_at),
                "log_errors": _error_lines(row.console_output),
            }
            evidence["ci_pipeline_logs"].append(entry)
            if row.result in ("FAILURE", "UNSTABLE", "ABORTED"):
                add_error("build_result", f"Build #{row.build_number} result: {row.result}", "jenkins", row.updated_at)
            for line in entry["log_errors"]:
                add_error("log_error", line, "jenkins_console", row.updated_at)
    elif resource and start <= end and source in ("prometheus", "alertmanager"):
        rows = list(
            PrometheusAlert.objects.filter(
                metric_name=resource, updated_at__gte=start, updated_at__lte=end
            ).order_by("-updated_at", "-id")[:2]
        )
        evidence["metric_window_anomalies"] = []
        for row in rows:
            entry = {
                "metric": row.metric_name,
                "status": row.alert_status,
                "value": row.value,
                "type": row.metric_type,
                "updated_at": _timestamp(row.updated_at),
            }
            evidence["metric_window_anomalies"].append(entry)
            if str(row.alert_status).upper() != "NORMAL":
                add_error(
                    "metric_alert",
                    f"{row.metric_name}: {row.alert_status} (value={row.value})",
                    row.metric_type,
                    row.updated_at,
                )

    return {
        "alert": alert,
        "errors": errors,
        "evidence": evidence,
        "evidence_status": "observed" if any(evidence.values()) else "alert_only",
        "window_minutes": 15,
    }


def routing_context_text(incident_context, fallback_message):
    """Compact alert + true error indicators for Laya, without full raw logs."""
    if not incident_context:
        return str(fallback_message or "")
    alert = incident_context["alert"]
    pieces = [alert.get("family") or "", alert.get("message") or ""]
    pieces.extend(error["message"] for error in incident_context["errors"][:3])
    return _redact(" | ".join(filter(None, pieces)), 850)


def retrieval_query_text(decisions, incident_context, fallback_message):
    """Use the observed failure mechanism in Chroma search, not only alert text."""
    family = str(decisions.get("incident_family") or "unknown").replace("_", " ")
    if not incident_context:
        return f"{family} {fallback_message}".strip()
    alert = incident_context["alert"]
    parts = [family, str(alert.get("message") or "")[:220]]
    for error in incident_context["errors"][:3]:
        parts.append(error["message"])
        if error["kind"] == "oom_killed":
            parts.append("out of memory container OOM")
    return _redact(" ".join(part for part in parts if part), 900)
