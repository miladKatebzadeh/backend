"""Human-readable and bounded Langfuse presentation of Incident diagnostics.

This module only formats telemetry and AI results for observability. It never
affects diagnostic routing, runbook retrieval, model prompts or tool execution.
Trace data is a summary, not an audit-grade copy of raw logs.
"""
import json
import re

TRACE_SCHEMA = "revive.incident.v2"

STAGES = {
    "context": "01 | Alert and evidence",
    "routing": "02 | Laya routing",
    "retrieval": "03 | Runbook retrieval",
    "telemetry": "04 | Telemetry checked",
    "llm": "05 | AI diagnosis",
    "llm_retry": "05b | AI diagnosis retry",
    "remediation": "06 | Remediation and verification",
}

_SECRET_FIELD = re.compile(r"(password|passwd|secret|token|api[_-]?key|authorization|credential|private[_-]?key)", re.I)
_SECRET_VALUE = re.compile(
    r"(?i)\b([a-z0-9_-]*(?:password|passwd|secret(?:[_-]?key)?|token|api[_-]?key|authorization|private[_-]?key))\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_BEARER = re.compile(r"(?i)\bBearer\s+[^\s,;]+")
_URL_PASSWORD = re.compile(r"(https?://[^:/\s]+:)[^@\s/]+(@)", re.I)


def safe_text(value, max_chars=350):
    """Redact common credential patterns and explicitly mark shortened strings."""
    if value is None:
        return ""
    text = str(value).replace("\x00", "")
    text = _BEARER.sub("Bearer [REDACTED]", text)
    text = _URL_PASSWORD.sub(r"\1[REDACTED]\2", text)
    text = _SECRET_VALUE.sub(lambda m: m.group(1) + "=[REDACTED]", text)
    text = " ".join(text.split())
    if len(text) > max_chars:
        return text[:max_chars] + "… [truncated]"
    return text


def trace_data(value, depth=0):
    """Keep JSON structure intact, even when its fields are very large."""
    if depth >= 7 and isinstance(value, (dict, list, tuple)):
        return "[nested data omitted]"
    if isinstance(value, dict):
        items = list(value.items())
        result = {}
        for key, item in items[:30]:
            clean_key = str(key)[:80]
            result[clean_key] = (
                "[REDACTED]" if _SECRET_FIELD.search(clean_key)
                else trace_data(item, depth + 1)
            )
        if len(items) > 30:
            result["_omitted_fields"] = len(items) - 30
        return result
    if isinstance(value, (list, tuple)):
        result = [trace_data(item, depth + 1) for item in value[:8]]
        if len(value) > 8:
            result.append({"_omitted_items": len(value) - 8})
        return result
    if isinstance(value, str):
        return safe_text(value, 850)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return safe_text(value)


def trace_input(message, incident_context, resource_scope=None):
    alert = (incident_context or {}).get("alert") or {}
    scope = resource_scope if isinstance(resource_scope, dict) else {}
    source = alert.get("source") or scope.get("source") or "unspecified"
    resource = alert.get("resource") or scope.get("resource") or "unspecified"
    return {
        "schema_version": TRACE_SCHEMA,
        "title": f"{safe_text(source, 45)} / {safe_text(resource, 110)}",
        "alert_or_question": safe_text(alert.get("message") or message, 380),
        "source": safe_text(source, 60),
        "resource": safe_text(resource, 160),
        "incident_id": alert.get("incident_id") or scope.get("incident_id"),
        "reported_status": safe_text(alert.get("status"), 70) or None,
        "note": "Trace summaries distinguish observed evidence from AI suggestions.",
    }


def context_view(context):
    context = context or {}
    alert = context.get("alert") or {}
    errors = context.get("errors") or []
    evidence = context.get("evidence") or {}
    status = context.get("evidence_status") or "unavailable"
    names = {
        "observed": "Matching source telemetry was found.",
        "incident_snapshot": "Using a stored Incident snapshot; live samples were unavailable.",
        "alert_only": "Only the Alert is available; the root cause is not established.",
    }
    return {
        "status": status,
        "summary": names.get(status, "Telemetry could not be correlated."),
        "alert": {
            "source": alert.get("source"),
            "resource": alert.get("resource"),
            "message": safe_text(alert.get("message"), 380),
            "reported_status": alert.get("status"),
            "observed_at": alert.get("observed_at"),
        },
        "observed_errors": [
            {
                "kind": e.get("kind"),
                "message": safe_text(e.get("message"), 260),
                "source": e.get("source"),
                "observed_at": e.get("observed_at"),
            }
            for e in errors[:6] if isinstance(e, dict)
        ],
        "telemetry_samples": {
            name: len(rows) for name, rows in evidence.items() if isinstance(rows, list)
        },
        "correlation_window_minutes": context.get("window_minutes"),
    }


def routing_view(route):
    route = route or {}
    router = route.get("router") or "keywords"
    family = route.get("incident_family") or "unknown"
    flags = {
        "need_ci_logs": "CI logs",
        "need_metric_window": "Metric window",
        "need_container_events": "Container evidence",
        "need_deployment_changes": "Deployment changes",
        "need_runbook_search": "Runbooks",
    }
    requested = [label for flag, label in flags.items() if route.get(flag)]
    return {
        "status": "fallback" if router == "keywords" else "routed",
        "summary": (
            f"Keyword fallback selected {family}."
            if router == "keywords" else f"Laya selected {family}."
        ),
        "router": router,
        "laya_model": route.get("laya_model") or None,
        "incident_family": family,
        "family_source": route.get("family_source") or "router",
        "requested_evidence": requested,
    }


def retrieval_view(query, retrieval):
    retrieval = retrieval or {}
    hits = retrieval.get("results") or []
    backend = retrieval.get("source") or "none"
    matched = len(hits)
    if matched == 0:
        summary = "No relevant runbook was retrieved; do not assume a cause from documentation."
    elif backend == "postgres_fallback":
        summary = f"{matched} runbook(s) retrieved using PostgreSQL fallback, not ChromaDB."
    else:
        summary = f"{matched} runbook(s) retrieved from {backend} search."
    return {
        "status": "matches_found" if matched else "no_relevant_runbook",
        "summary": summary,
        "query": safe_text(query, 900),
        "retrieval_backend": backend,
        "candidate_count": retrieval.get("candidate_count") or 0,
        "matched_count": matched,
        "filters": trace_data(retrieval.get("filters") or {}),
        "top_matches": [
            {
                "rank": rank,
                "title": safe_text(hit.get("title"), 180),
                "document_id": hit.get("document_id"),
                "section": hit.get("section"),
                "component": hit.get("component"),
                "chunk": hit.get("chunk"),
                "source": hit.get("retrieval_source"),
                "matched_terms": trace_data(hit.get("matched_terms") or []),
                "ranking_score": hit.get("relevance_score"),
                "vector_distance": hit.get("distance"),
            }
            for rank, hit in enumerate(hits[:3], start=1)
            if isinstance(hit, dict)
        ],
        "score_note": "Ranking scores/distances are not calibrated confidence percentages.",
    }


def diagnosis_view(reply_text, engine_status, monitoring_override=False):
    try:
        parsed = json.loads(reply_text)
    except (TypeError, ValueError):
        parsed = None
    if not isinstance(parsed, dict):
        parsed = {}
    engine_status = engine_status or parsed.get("engine_status") or "invalid"
    return {
        "status": engine_status,
        "summary": (
            "Model unavailable; no diagnosis was established." if engine_status == "offline"
            else "Model response could not be validated." if engine_status == "invalid"
            else "Diagnostic pipeline failed before a reliable assessment." if engine_status == "error"
            else "The model returned a diagnostic assessment, not proof of recovery."
        ),
        "incident_detected_in_response": parsed.get("incident_detected") if isinstance(parsed.get("incident_detected"), bool) else None,
        "detection_basis": "monitoring_record" if monitoring_override else "model_response",
        "error_scope": safe_text(parsed.get("error_scope"), 100),
        "assessment": safe_text(parsed.get("diagnostic_report"), 900),
        "evidence_references": [
            safe_text(ref, 160) for ref in (parsed.get("evidence_refs") or [])[:6]
        ] if isinstance(parsed.get("evidence_refs"), list) else [],
        "suggested_tool": safe_text(parsed.get("tool_name"), 120) or None,
        "suggested_target": safe_text(parsed.get("tool_target"), 120) or None,
    }


def remediation_view(requested, agent):
    agent = agent or {}
    executed = bool(agent.get("agent_triggered"))
    sandbox = agent.get("sandbox_output") or {}
    success = executed and bool(sandbox.get("success"))
    verified = executed and bool(agent.get("resolved"))
    if not requested:
        status, summary = "not_requested", "Diagnosis only. No remediation tool was authorized or executed."
    elif not executed:
        status, summary = "not_executed", (
            "Remediation was authorized, but no tool ran."
            + (" Reason: " + safe_text(agent.get("error"), 220) if agent.get("error") else "")
        )
    elif verified:
        status, summary = "verified_recovery", "A remediation tool ran and resource recovery was verified."
    elif success:
        status, summary = "executed_unverified", "Tool execution completed; resource recovery was not verified."
    else:
        status, summary = "failed", "A remediation tool was attempted but did not succeed."
    return {
        "status": status,
        "summary": summary,
        "authorized": bool(requested),
        "tool_executed": executed,
        "tool_name": safe_text(agent.get("matched_tool"), 120) or None,
        "target": safe_text(agent.get("target"), 160) or None,
        "tool_success": success,
        "recovery_verified": verified,
        "verification": safe_text(agent.get("proof"), 120) or "not rechecked",
        "checked_state": safe_text(agent.get("checked"), 70) or None,
    }


def trace_summary(context, message, route, retrieval, reply_text, engine_status, agent, allow_remediation, query="", monitoring_override=False):
    observed = context_view(context)
    routed = routing_view(route)
    searched = retrieval_view(query, retrieval)
    diagnosis = diagnosis_view(reply_text, engine_status, monitoring_override=monitoring_override)
    remediation = remediation_view(allow_remediation, agent)
    return {
        "schema_version": TRACE_SCHEMA,
        "engine_status": diagnosis["status"],
        "incident_detected": diagnosis["incident_detected_in_response"],
        "recovery_verified": remediation["recovery_verified"],
        "overview": {
            "what_happened": observed["alert"]["message"] or safe_text(message, 300),
            "evidence_status": observed["status"],
            "observed_errors": [error["message"] for error in observed["observed_errors"]],
            "routing": routed["summary"],
            "runbooks": searched["summary"],
            "ai_assessment": diagnosis["assessment"] or diagnosis["summary"],
            "ai_status": diagnosis["status"],
            "action": remediation["summary"],
            "recovery_verified": remediation["recovery_verified"],
        },
        "incident_evidence": observed,
        "routing": routed,
        "runbook_search": searched,
        "ai_diagnosis": diagnosis,
        "remediation": remediation,
        "interpretation": "engine_status=ok means diagnosis completed; it does not mean the incident was resolved.",
    }
