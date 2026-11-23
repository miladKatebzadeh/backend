"""Build time-correlated Alert + Error evidence before routing or retrieval.

Only a known source/resource pair is used for scoped lookups. Do not persist raw
alerts as Chroma documents: Chroma holds runbooks, not transient observations.
"""
import re
from datetime import timedelta

from django.utils import timezone

from apps.collector.models import DockerMetric, JenkinsBuild, PrometheusAlert
from apps.mcp.jenkins_evidence import (
    ANALYZER_VERSION, analyze_jenkins_console, fetch_jenkins_build_console,
    select_jenkins_console,
)
from apps.mcp.source_evidence import (
    analyze_docker_observation, analyze_metric_observation,
    fetch_docker_evidence, fetch_prometheus_window, fetch_active_alert,
)


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
    for line in reversed(str(text or "").splitlines()):
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


def _can_check_live(resource_scope, observed_at):
    """Only incident-linked recent signals permit additional live provider reads."""
    if not resource_scope.get("incident_id") or observed_at is None:
        return False
    seconds = (timezone.now() - observed_at).total_seconds()
    return -90 <= seconds <= 20 * 60


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
    source_assessment = None
    can_check_live = _can_check_live(resource_scope, observed_at)

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
        live = None
        for index, row in enumerate(rows):
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
            baseline = analyze_docker_observation({
                **entry, "logs": row.container_logs, "state_error": state_error,
            })
            analysis = baseline
            if index == 0 and can_check_live and baseline["diagnostic_status"] == "insufficient_evidence":
                live = fetch_docker_evidence(resource)
                if isinstance(live, dict) and live.get("status") != "not_found":
                    inspected = analyze_docker_observation(live)
                    if inspected["diagnostic_status"] != "insufficient_evidence":
                        analysis = inspected
                entry["live_check"] = {
                    "status": (live or {}).get("status") if isinstance(live, dict) else "unavailable",
                    "checked_at": (live or {}).get("checked_at") if isinstance(live, dict) else None,
                    "origin": "live_docker_read_only",
                    "recovery_verified": False,
                }
            entry["failure_analysis"] = analysis
            evidence["container_telemetry"].append(entry)
            if index == 0:
                source_assessment = analysis
            if row.oom_killed:
                add_error("oom_killed", "Docker reports OOMKilled=true", "docker_inspect", row.timestamp)
            elif analysis.get("primary_error"):
                add_error("container_failure", analysis["primary_error"], analysis["evidence_origin"], row.timestamp)
            if exit_code not in (None, "", 0, "0"):
                add_error("exit_code", f"Container exit code {exit_code}; exit status is not a root cause", "docker_inspect", row.timestamp)
            if state_error and not row.oom_killed:
                add_error("state_error", state_error, "docker_inspect", row.timestamp)
            for line in entry["log_errors"][:2]:
                add_error("log_error", line, "docker_logs", row.timestamp)
        if not rows and can_check_live:
            live = fetch_docker_evidence(resource)
            if isinstance(live, dict) and live.get("status") not in ("not_found", None):
                analysis = analyze_docker_observation(live)
                evidence["container_telemetry"].append({
                    "container": resource,
                    "status": live.get("status"),
                    "timestamp": live.get("checked_at"),
                    "failure_analysis": analysis,
                    "live_check": {"status": live.get("status"), "origin": "live_docker_read_only",
                                   "recovery_verified": False},
                })
                source_assessment = analysis
                if analysis.get("primary_error"):
                    add_error("container_failure", analysis["primary_error"], "live_docker_read_only", timezone.now())
    elif resource and start <= end and source == "jenkins":
        # Keep the Incident's exact build, not another failure in the same job
        # that happened within the correlation time window.
        snapshot = resource_scope.get("snapshot")
        if not isinstance(snapshot, dict):
            snapshot = {}
        number = resource_scope.get("build_number") or snapshot.get("build_number")
        query = JenkinsBuild.objects.filter(
            job_name=resource, updated_at__gte=start, updated_at__lte=end
        )
        if str(number or "").isdigit():
            query = query.filter(build_number=int(number))
        rows = list(query.order_by("-updated_at", "-build_number", "-id")[:2])

        # When the saved console contains only npm help/footer lines, Revive
        # itself re-fetches the exact failing build once per diagnosis.
        # Never ask an end user to search for debug log paths.
        if resource_scope.get("incident_id") and str(number or "").isdigit():
            cached = rows[0] if rows else None
            saved_info = cached.raw_build_info if cached and isinstance(cached.raw_build_info, dict) else {}
            previous = saved_info.get("failure_analysis")
            if not isinstance(previous, dict) or previous.get("analyzer_version") != ANALYZER_VERSION:
                previous = analyze_jenkins_console(cached.console_output if cached else snapshot.get("console_excerpt"))
            if not previous.get("primary_error"):
                console = fetch_jenkins_build_console(resource, number)
                if console:
                    fetched = analyze_jenkins_console(console)
                    if fetched.get("primary_error"):
                        fetched["evidence_origin"] = "jenkins_exact_build_refetch"
                        bounded = select_jenkins_console(console)
                        if cached:
                            cached.raw_build_info = {**saved_info, "failure_analysis": fetched}
                            cached.console_output = bounded
                            cached.save(update_fields=["raw_build_info", "console_output"])
                        else:
                            snapshot = {**snapshot, "failure_analysis": fetched, "console_excerpt": bounded}
                            resource_scope = {**resource_scope, "snapshot": snapshot}

        evidence["ci_pipeline_logs"] = []
        for row in rows:
            build_info = row.raw_build_info if isinstance(row.raw_build_info, dict) else {}
            analysis = build_info.get("failure_analysis")
            if not isinstance(analysis, dict) or analysis.get("analyzer_version") != ANALYZER_VERSION:
                analysis = analyze_jenkins_console(row.console_output)
            entry = {
                "job": row.job_name,
                "build_number": row.build_number,
                "result": row.result,
                "updated_at": _timestamp(row.updated_at),
                "failure_analysis": analysis,
                "log_errors": list(analysis.get("error_lines") or [])[:4],
            }
            evidence["ci_pipeline_logs"].append(entry)
            if analysis.get("primary_error"):
                add_error("pipeline_error", analysis["primary_error"], "jenkins_console", row.updated_at)
                for line in entry["log_errors"][1:]:
                    add_error("log_error", line, "jenkins_console", row.updated_at)
            if row.result in ("FAILURE", "UNSTABLE", "ABORTED"):
                add_error("build_result", f"Build #{row.build_number} result: {row.result}", "jenkins", row.updated_at)
                if not analysis.get("primary_error") and analysis.get("execution_exit_code") is not None:
                    add_error(
                        "exit_status",
                        f"Shell exited with code {analysis['execution_exit_code']} (root cause unknown)",
                        "jenkins_console",
                        row.updated_at,
                    )
    elif resource and start <= end and source in ("prometheus", "alertmanager"):
        rows = list(
            PrometheusAlert.objects.filter(
                metric_name=resource, updated_at__gte=start, updated_at__lte=end
            ).order_by("-updated_at", "-id")[:2]
        )
        evidence["metric_window_anomalies"] = []
        for index, row in enumerate(rows):
            entry = {
                "metric": row.metric_name,
                "status": row.alert_status,
                "value": row.value,
                "type": row.metric_type,
                "labels": {
                    _redact(key, 60): _redact(value, 100)
                    for key, value in (row.labels if isinstance(row.labels, dict) else {}).items()
                },
                "updated_at": _timestamp(row.updated_at),
            }
            if can_check_live and index == 0 and str(row.metric_name).startswith("alert:"):
                details = fetch_active_alert(row.metric_name, source=source)
                if isinstance(details, dict):
                    entry["alert_detail"] = details
            if can_check_live and index == 0 and not str(row.metric_name).startswith("alert:"):
                window = fetch_prometheus_window(row.metric_name, row.labels, observed_at)
                if isinstance(window, dict):
                    entry["metric_window"] = window
            analysis = analyze_metric_observation(entry, entry.get("metric_window"))
            entry["failure_analysis"] = analysis
            evidence["metric_window_anomalies"].append(entry)
            if index == 0:
                source_assessment = analysis
            if str(row.alert_status).upper() != "NORMAL":
                add_error("metric_alert", analysis["issue"], row.metric_type, row.updated_at)

    evidence_status = "observed" if any(evidence.values()) else "alert_only"

    # Collector rows can be updated in place. For historic Incidents preserve
    # the bounded snapshot saved by the server-side Incident ledger instead of
    # substituting unrelated recent telemetry or silently losing the error.
    snapshot = resource_scope.get("snapshot")
    if resource and evidence_status == "alert_only" and isinstance(snapshot, dict):
        recorded = {"resource": resource, "observed_at": _timestamp(observed_at)}
        if source == "docker":
            recorded.update({
                "status": _redact(snapshot.get("container_status")),
                "oom_killed": bool(snapshot.get("oom_killed")),
                "restart_count": snapshot.get("restart_count"),
                "exit_code": snapshot.get("exit_code"),
                "state_error": _redact(snapshot.get("state_error")),
                "log_errors": _error_lines(snapshot.get("log_excerpt")),
            })
            recorded["failure_analysis"] = analyze_docker_observation({
                **recorded, "logs": snapshot.get("log_excerpt"),
                "evidence_origin": "incident_ledger_snapshot",
            })
            source_assessment = recorded["failure_analysis"]
            if recorded["oom_killed"]:
                add_error("oom_killed", "Incident snapshot reports OOMKilled=true", "incident_ledger", observed_at)
            if recorded["exit_code"] not in (None, "", 0, "0"):
                add_error("exit_code", f"Container exit code {recorded['exit_code']}", "incident_ledger", observed_at)
            if recorded["state_error"]:
                add_error("state_error", recorded["state_error"], "incident_ledger", observed_at)
            for line in recorded["log_errors"]:
                add_error("log_error", line, "incident_ledger", observed_at)
        elif source == "jenkins":
            analysis = snapshot.get("failure_analysis")
            if not isinstance(analysis, dict) or analysis.get("analyzer_version") != ANALYZER_VERSION:
                analysis = analyze_jenkins_console(snapshot.get("console_excerpt"))
            recorded.update({
                "build_number": snapshot.get("build_number"),
                "result": _redact(snapshot.get("build_result")),
                "failure_analysis": analysis,
                "log_errors": list(analysis.get("error_lines") or [])[:4],
            })
            if analysis.get("primary_error"):
                add_error("pipeline_error", analysis["primary_error"], "incident_ledger", observed_at)
            if recorded["result"] in ("FAILURE", "UNSTABLE", "ABORTED"):
                add_error("build_result", f"Build result {recorded['result']}", "incident_ledger", observed_at)
            if not analysis.get("primary_error") and analysis.get("execution_exit_code") is not None:
                add_error(
                    "exit_status",
                    f"Shell exited with code {analysis['execution_exit_code']} (root cause unknown)",
                    "incident_ledger", observed_at,
                )
        elif source in ("prometheus", "alertmanager"):
            recorded.update({
                "metric": resource,
                "value": snapshot.get("value"),
                "status": _redact(snapshot.get("alert_status")),
                "type": _redact(snapshot.get("metric_type")),
                "labels": snapshot.get("labels") if isinstance(snapshot.get("labels"), dict) else {},
            })
            recorded["failure_analysis"] = analyze_metric_observation(recorded)
            source_assessment = recorded["failure_analysis"]
            if recorded["status"] and recorded["status"] != "NORMAL":
                add_error("metric_alert", f"{resource}: {recorded['status']}", "incident_ledger", observed_at)
        if len(recorded) > 2:
            evidence["incident_record_snapshot"] = [recorded]
            evidence_status = "incident_snapshot"

    return {
        "alert": alert,
        "errors": errors,
        "evidence": evidence,
        "evidence_status": evidence_status,
        "window_minutes": 15,
        "source_assessment": source_assessment,
    }


def routing_context_text(incident_context, fallback_message):
    """Compact alert + true error indicators for Laya, without full raw logs."""
    if not incident_context:
        return str(fallback_message or "")
    alert = incident_context["alert"]
    pieces = [alert.get("family") or "", alert.get("message") or ""]
    source_issue = (incident_context.get("source_assessment") or {}).get("primary_error") or (
        incident_context.get("source_assessment") or {}
    ).get("issue")
    if source_issue:
        pieces.append(str(source_issue)[:300])
    for row in (incident_context.get("evidence") or {}).get("ci_pipeline_logs", []):
        failure = row.get("failure_analysis") or {}
        if failure.get("primary_error"):
            pieces.extend([
                failure.get("failing_stage") or "",
                failure.get("primary_error") or "",
            ])
            break
    pieces.extend(error["message"] for error in incident_context["errors"][:3])
    return _redact(" | ".join(filter(None, pieces)), 850)


def retrieval_query_text(decisions, incident_context, fallback_message):
    """Use the observed failure mechanism in Chroma search, not only alert text."""
    family = str(decisions.get("incident_family") or "unknown").replace("_", " ")
    if not incident_context:
        return f"{family} {fallback_message}".strip()
    alert = incident_context["alert"]
    parts = [family, str(alert.get("message") or "")[:220]]
    source_issue = (incident_context.get("source_assessment") or {}).get("primary_error") or (
        incident_context.get("source_assessment") or {}
    ).get("issue")
    if source_issue:
        parts.append(str(source_issue)[:260])
    for row in (incident_context.get("evidence") or {}).get("ci_pipeline_logs", []):
        failure = row.get("failure_analysis") or {}
        if failure.get("primary_error"):
            parts.extend([
                failure.get("failing_stage") or "",
                failure.get("primary_error") or "",
            ])
            break
    for error in incident_context["errors"][:3]:
        if error["kind"] in ("pipeline_error", "log_error", "oom_killed", "state_error", "exit_code", "container_failure", "metric_alert"):
            parts.append(error["message"])
        if error["kind"] == "oom_killed":
            parts.append("out of memory container OOM")
    return _redact(" ".join(part for part in parts if part), 900)
