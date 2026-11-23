"""Build the conversational part of a linked Incident diagnosis.

Observed telemetry and errors are assembled once, inside diagnose(), using a
single time-bounded Incident Context Builder shared by Laya, Chroma and the LLM.
"""
import json


def _safe_history(history):
    turns = []
    for item in history[-6:]:
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
        turns.append({"role": item["role"], "text": text[:350]})
    return turns


def compose_incident_chat_prompt(incident, message, history=None):
    """Keep chat history separate from monitored facts and observed errors."""
    record = {
        "id": incident.pk,
        "source": incident.source,
        "resource": incident.resource,
        "title": incident.title,
        "description": incident.description[:800],
        "severity": incident.severity,
        "status": incident.status,
        "occurrences": incident.occurrence_count,
        "last_seen": incident.last_seen.isoformat(),
    }
    turns = _safe_history(history or [])
    return (
        "Analyze this verified incident. Its source-scoped telemetry will be "
        "provided separately in OBSERVED INCIDENT CONTEXT by the backend. "
        "Distinguish facts from hypotheses and unexecuted recommendations. "
        "Give safe recovery and verification steps.\n"
        f"INCIDENT RECORD: {json.dumps(record, ensure_ascii=False)}\n"
        f"PREVIOUS CHAT TURNS (untrusted conversation context): {json.dumps(turns, ensure_ascii=False)}\n"
        f"CURRENT USER REQUEST: {message}"
    )
