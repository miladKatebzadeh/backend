"""User-facing Incident reports and safe Ollama diagnostics.

Monitoring evidence is authoritative about observed failures, while model
hypotheses are only suggestions. A missing LLM must never erase an Incident.
"""
import json
import re

from apps.mcp.trace_presentation import safe_text


ACTIVE_STATUSES = {
    "open", "acknowledged", "investigating", "exited", "dead", "firing",
    "critical", "warning", "failure", "failed", "unstable", "aborted",
}


def observed_incident(context):
    alert = (context or {}).get("alert") or {}
    return (
        bool(alert.get("source") and alert.get("resource"))
        and str(alert.get("status") or "").lower() in ACTIVE_STATUSES
    )


def ollama_error_details(exc, model):
    """Keep useful provider diagnostics without exposing raw request/stack/keys."""
    status = getattr(exc, "status_code", None)
    if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
        status = None

    error_type = exc.__class__.__name__
    if status == 404:
        category = "not_found"
        hint = "Verify the configured Ollama model name and API endpoint."
    elif status in (401, 403):
        category = "unauthorized"
        hint = "Verify Ollama authorization and connection settings."
    elif status == 400:
        category = "invalid_request"
        hint = "Verify the model, JSON response format and request parameters."
    elif status == 429:
        category = "capacity"
        hint = "Review model capacity and request concurrency."
    elif status in (408, 504) or "timeout" in error_type.lower():
        category = "timeout"
        hint = "Review model latency, server load and timeout settings."
    elif status is not None and status >= 500:
        category = "server_error"
        hint = "Inspect Ollama service health, available RAM/GPU and model loading status."
    elif "connection" in error_type.lower() or "connect" in error_type.lower():
        category = "connection"
        hint = "Check network connectivity from the Backend container to Ollama."
    else:
        category = "unknown"
        hint = "Check Ollama availability, configured model and provider diagnostics."

    # The SDK may include a provider response body. Truncate and redact it;
    # never include raw exception repr, credentials, traceback or whole prompt.
    raw = getattr(exc, "error", None)
    if raw is None and status is not None:
        raw = str(exc)
    if raw is None:
        raw = error_type
    return {
        "error_type": safe_text(error_type, 80),
        "http_status": status,
        "category": category,
        "message": safe_text(raw, 280),
        "model": safe_text(model, 110),
        "hint": hint,
    }


def offline_diagnosis(context, error):
    """Backward-compatible JSON reply with monitoring truth, not a false negative."""
    alert = (context or {}).get("alert") or {}
    confirmed = observed_incident(context)
    resource = safe_text(alert.get("resource") or "the monitored resource", 100)
    source = safe_text(alert.get("source") or "monitoring", 80)
    report = (
        f"Monitoring confirmed a failure affecting {resource} in {source}. "
        "The AI model did not respond; the underlying cause has not been established. "
        "Revive will explain any failure evidence it already collected, without requiring manual log inspection."
        if confirmed
        else "The AI service is unavailable. Without independent monitoring evidence, the system state remains unverified."
    )
    return json.dumps({
        "incident_detected": confirmed,
        "error_scope": safe_text(alert.get("family") or "engine", 100),
        "engine_status": "offline",
        "diagnostic_report": report,
        "evidence_refs": [
            safe_text(item.get("source"), 80)
            for item in ((context or {}).get("errors") or [])[:4]
            if isinstance(item, dict) and item.get("source")
        ],
        "ollama_error": error,
        "tool_name": "",
        "tool_target": "",
    }, ensure_ascii=False)


def _list_of_text(value, limit=4, max_chars=230):
    if not isinstance(value, list):
        return []
    return [
        safe_text(item, max_chars) for item in value[:limit]
        if isinstance(item, str) and item.strip()
    ]


def _default_steps(source, status):
    """Operator actions are based on observed facts, not manual log-reading tasks."""
    if source == "jenkins":
        return (
            [
                "Address the failing CI stage once Revive identifies the specific error.",
                "Retry the failed build after a targeted correction; Revive will evaluate the new result.",
            ],
            ["Confirm the next Jenkins build finishes with SUCCESS."],
        )
    if source == "docker":
        return (
            [
                "Use the observed exit code, OOMKilled state, and container status to choose a targeted correction.",
                "Apply configuration or resource changes only when the monitoring evidence supports them.",
            ],
            ["Confirm the container is running and remains stable."],
        )
    if source in ("prometheus", "alertmanager"):
        return (
            [
                "Identify the resource and threshold associated with the failing metric.",
                "Apply a correction only when the observed metric identifies a specific issue.",
            ],
            ["Confirm the metric returns to its expected range and the alert clears."],
        )
    return (
        ["Use the observed symptoms to determine a safe, targeted correction."],
        ["Confirm the service is healthy after any change."],
    )


def _english(text):
    """Do not surface untranslated model-generated prose in English reports."""
    return isinstance(text, str) and bool(text.strip()) and not any(
        "\u0600" <= ch <= "\u06ff" for ch in text
    )


def _manual_log_handoff(text):
    """A diagnostics product must not make the end user research raw logs."""
    lowered = text.lower()
    return bool(re.search(
        r"\b(?:check|review|inspect|open|read|examine|search|look at)\b"
        r".{0,50}\b(?:logs?|console|trace|debugging output)\b",
        lowered,
    )) or any(term in lowered for term in (
        "a complete log of this run", "npm help ci", "/tmp/.npm/_logs",
    )))


def _jenkins_recommendations(pipeline, defaults):
    """Offer useful, evidence-conditioned work instead of generic log tasks."""
    if not isinstance(pipeline, dict):
        return defaults, None
    details = " ".join(str(pipeline.get(key) or "") for key in (
        "primary_error", "error_lines", "error_context",
    )).lower()
    stage = safe_text(pipeline.get("failing_stage"), 90) or "the failed CI stage"
    primary = pipeline.get("primary_error")
    if not primary:
        return [
            f"Revive could not isolate the error in {stage} from the available Jenkins output.",
            "Re-run the failed stage with its original npm error details printed to the Jenkins console; Revive can analyze the next run automatically.",
        ], "The build failed, but its console contained no actionable error message."
    if "package-lock.json" in details and ("npm ci" in details or "npm error" in details):
        return [
            "Synchronize package.json and package-lock.json with npm install, then commit the corrected lockfile.",
            "Re-run the frontend CI dependency installation with npm ci.",
        ], "Frontend dependency installation appears to have a package-lock.json consistency problem."
    if "eresolve" in details or "dependency tree" in details or "conflicting peer dependency" in details:
        return [
            "Resolve the conflicting package versions in the frontend dependency manifest and lockfile.",
            "Re-run npm ci and then the frontend test stage.",
        ], "npm reported a dependency resolution conflict."
    if "eacces" in details or "permission denied" in details:
        return [
            "Correct the CI worker's permissions for the files or directories named by the error.",
            "Retry the affected Jenkins stage and verify the job succeeds.",
        ], "The CI process encountered a permissions error."
    if "gunicorn" in details and "not found" in details:
        return [
            "Ensure gunicorn is installed in the backend Docker image and validated during image build.",
            "Rebuild and redeploy only after the image startup check succeeds.",
        ], "The runtime could not find the Gunicorn executable."
    if str(primary).lower().startswith(("npm error", "npm err!")):
        return [
            "Use Revive's captured npm failure details to correct the failed frontend installation step.",
            "Re-run frontend dependency installation and verify the Jenkins build passes.",
        ], "npm failed during the frontend stage; its exact cause is not yet confirmed."
    return [
        f"Correct the problem indicated by the observed error in {stage}.",
        "Retry the affected stage and verify the Jenkins build succeeds.",
    ], None


def readable_report(incident_context, reply_text, engine_status, agent=None, retrieval=None, error=None):
    """Create a plain-English, evidence-first report for every outcome.

    AI text is marked as a model assessment. For offline/invalid responses the
    report relies only on verified monitoring observations.
    """
    context = incident_context or {}
    alert = context.get("alert") or {}
    errors = context.get("errors") or []
    source = str(alert.get("source") or "").lower()
    resource = safe_text(alert.get("resource") or "unknown resource", 100)
    alert_text = safe_text(alert.get("message"), 360)
    status = str(alert.get("status") or "").lower()
    confirmed = observed_incident(context)
    model_ok = engine_status == "ok"
    try:
        parsed = json.loads(reply_text)
        if not isinstance(parsed, dict):
            parsed = {}
    except (TypeError, ValueError):
        parsed = {}
    model_report = parsed.get("user_report") if isinstance(parsed.get("user_report"), dict) else {}
    steps, verification = _default_steps(source, status)
    evidence = []
    for item in errors[:4]:
        if isinstance(item, dict) and item.get("message"):
            evidence.append({
                "text": safe_text(item["message"], 230),
                "source": safe_text(item.get("source") or "monitoring", 65),
                "type": "observed",
            })

    if confirmed:
        title = f"{source.upper()} incident: {resource}"
        summary = (
            f"Monitoring confirmed a failure affecting {resource}."
            + (f" Alert: {alert_text}" if alert_text else "")
        )
    elif alert_text:
        title = f"Infrastructure assessment: {resource}"
        summary = f"A request or alert was received: {alert_text}"
    else:
        title = "Infrastructure assessment"
        summary = "A request to investigate the infrastructure was received."

    pipeline_failure = None
    for group in ("ci_pipeline_logs", "incident_record_snapshot"):
        for item in (context.get("evidence") or {}).get(group, []):
            if isinstance(item, dict) and isinstance(item.get("failure_analysis"), dict):
                pipeline_failure = item["failure_analysis"]
                break
        if pipeline_failure is not None:
            break

    root_cause = "The root cause is not yet confirmed by the available evidence."
    if source == "jenkins" and pipeline_failure:
        primary = pipeline_failure.get("primary_error")
        steps, explanation = _jenkins_recommendations(pipeline_failure, steps)
        if isinstance(primary, str) and primary.strip():
            root_cause = (
                f"Jenkins reported: {safe_text(primary, 330)}. "
                "This is an observed failure message, not a verified root cause."
            )
            if explanation:
                root_cause = explanation + " " + root_cause
            stage = pipeline_failure.get("failing_stage")
            command = pipeline_failure.get("failing_command")
            if stage:
                evidence.append({
                    "text": "Failing stage: " + safe_text(stage, 100),
                    "source": "jenkins_console", "type": "observed",
                })
            if command:
                evidence.append({
                    "text": "Associated command: " + safe_text(command, 230),
                    "source": "jenkins_console", "type": "observed",
                })
            summary = f"The Jenkins build failed in {stage or 'an unidentified stage'}." + (
                f" {explanation}" if explanation else " Revive identified the reported error."
            )
        else:
            root_cause = (
                "Only general build-failure and npm help messages were available. "
                "Revive could not establish the specific reason for the failure."
            )
            stage = pipeline_failure.get("failing_stage")
            summary = (
                f"Jenkins reported a failure for {resource}. "
                "Revive could not identify a specific cause from the available console output."
            )
    if model_ok:
        # A convincing LLM explanation is NOT evidence. If Jenkins returned
        # only npm help text, do not allow the model to invent a specific cause.
        no_specific_jenkins_error = bool(
            source == "jenkins" and pipeline_failure
            and not pipeline_failure.get("primary_error")
        )
        model_summary = model_report.get("summary") or parsed.get("diagnostic_report")
        if (
            not no_specific_jenkins_error and _english(model_summary)
            and not _manual_log_handoff(model_summary)
        ):
            summary = safe_text(model_summary, 1050)
        suggested_cause = model_report.get("likely_cause")
        if (
            not no_specific_jenkins_error and _english(suggested_cause)
            and suggested_cause.strip().lower() not in ("unknown", "n/a", "none")
            and not _manual_log_handoff(suggested_cause)
        ):
            root_cause = "AI hypothesis (not yet verified): " + safe_text(suggested_cause, 430)
        proposed_steps = _list_of_text(model_report.get("recommended_steps"), limit=5)
        proposed_checks = _list_of_text(model_report.get("verification_steps"), limit=4)
        usable_steps = [step for step in proposed_steps if _english(step) and not _manual_log_handoff(step)]
        usable_checks = [check for check in proposed_checks if _english(check) and not _manual_log_handoff(check)]
        if usable_steps and not no_specific_jenkins_error:
            steps = usable_steps
        if usable_checks and not no_specific_jenkins_error:
            verification = usable_checks
        report_status = "ai_assessment"
        ai_note = "AI assessment is available. The proposed cause and recovery remain unverified until monitored evidence confirms them."
    else:
        report_status = "ai_unavailable" if engine_status == "offline" else "ai_unusable"
        ai_note = (
            "AI was unavailable. This report is based exclusively on monitoring evidence."
            if engine_status == "offline"
            else "The AI response was unusable. Revive used only verified monitoring data."
        )
        steps = list(steps) + [
            "Restore AI service availability to enable an additional automated assessment."
        ]
    if not evidence:
        ai_note += " No independent error evidence beyond the alert was available."

    agent = agent or {}
    executed = bool(agent.get("agent_triggered"))
    verified = executed and bool(agent.get("resolved"))
    if verified:
        action = "A remediation tool ran, and resource recovery was independently verified."
    elif executed:
        action = "A remediation tool ran, but recovery was not verified."
    else:
        action = "No remediation tool was executed."

    matched = (retrieval or {}).get("results") or []
    return {
        "language": "en",
        "status": report_status,
        "title": title,
        "incident_confirmed": confirmed,
        "summary": summary,
        "root_cause": root_cause,
        "evidence": evidence,
        "recommended_steps": steps,
        "verification_steps": verification,
        "ai_status": engine_status,
        "ai_note": ai_note,
        "runbook_count": len(matched),
        "pipeline_failure": {
            "diagnostic_status": pipeline_failure.get("diagnostic_status"),
            "primary_error": safe_text(pipeline_failure.get("primary_error"), 350) or None,
            "failing_stage": safe_text(pipeline_failure.get("failing_stage"), 110) or None,
            "failing_command": safe_text(pipeline_failure.get("failing_command"), 220) or None,
            "evidence_origin": pipeline_failure.get("evidence_origin") or "stored_jenkins_console",
        } if pipeline_failure else None,
        "action": action,
        "recovery_verified": verified,
        "source": "ai_and_monitoring" if model_ok else "monitoring_only",
    }
