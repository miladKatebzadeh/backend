"""Trusted Incident context for AI chat, with resource-scoped telemetry.

These helpers do not execute tools or change Incident state. Conversation turns
are untrusted user-provided context, while Incident details are loaded server-side.
"""
import json

from apps.collector.models import DockerMetric, JenkinsBuild, PrometheusAlert


def _telemetry_for_incident(incident):
    """Return a small snapshot for the *same* resource, not fleet-wide rows."""
    if incident.source == "docker":
        rows = DockerMetric.objects.filter(container_name=incident.resource).order_by("-timestamp", "-id")[:2]
        return [
            {
                "container": row.container_name,
                "status": row.status,
                "oom_killed": row.oom_killed,
                "restart_count": row.restart_count,
                "timestamp": row.timestamp.isoformat() if row.timestamp else None,
                "log_excerpt": (row.container_logs or "")[-500:],
            }
            for row in rows
        ]
    if incident.source == "jenkins":
        rows = JenkinsBuild.objects.filter(job_name=incident.resource).order_by("-build_number", "-id")[:2]
        return [
            {
                "job": row.job_name,
                "build": row.build_number,
                "result": row.result,
                "updated_at": row.updated_at.isoformat() if row.updated_at else None,
                "log_excerpt": (row.console_output or "")[-500:],
            }
            for row in rows
        ]
    if incident.source in ("prometheus", "alertmanager"):
        rows = PrometheusAlert.objects.filter(metric_name=incident.resource).order_by("-updated_at", "-id")[:2]
        return [
            {
                "metric": row.metric_name,
                "status": row.alert_status,
                "value": row.value,
                "updated_at": row.updated_at.isoformat() if row.updated_at else None,
            }
            for row in rows
        ]
    return []


def _safe_history(history):
    """Only role/text pairs, with a bounded token budget and no trusted status."""
    turns = []
    for item in history[-8:]:
        if not isinstance(item, dict) or item.get("role") not in ("user", "assistant"):
            continue
        text = item.get("text")
        if not isinstance(text, str):
            continue
        text = text.strip()
        if not text:
            continue
        if item["role"] == "assistant":
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    text = str(parsed.get("diagnostic_report") or text)
            except (ValueError, TypeError):
                pass
        turns.append({"role": item["role"], "text": text[:650]})
    return turns


def compose_incident_chat_prompt(incident, message, history=None):
    """Build a fresh per-turn diagnostic request with server-verified context."""
    record = {
        "id": incident.pk,
        "source": incident.source,
        "resource": incident.resource,
        "title": incident.title,
        "description": incident.description[:1200],
        "severity": incident.severity,
        "status": incident.status,
        "occurrences": incident.occurrence_count,
        "last_seen": incident.last_seen.isoformat(),
    }
    telemetry = _telemetry_for_incident(incident)
    turns = _safe_history(history or [])
    return (
        "Investigate this recorded infrastructure incident. The incident record "
        "below comes from the monitoring database, independently of any AI conclusion. "
        "Do not treat suggested checks as executed evidence. Do not claim a tool ran. "
        "Give concrete, safe recovery steps and say what remains unverified.\n"
        f"INCIDENT RECORD: {json.dumps(record, ensure_ascii=False)}\n"
        f"RESOURCE-SCOPED TELEMETRY: {json.dumps(telemetry, ensure_ascii=False)}\n"
        f"PREVIOUS CHAT TURNS (user-supplied, not telemetry): {json.dumps(turns, ensure_ascii=False)}\n"
        f"CURRENT USER REQUEST: {message}"
    )
