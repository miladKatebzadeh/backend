"""Plain-English, evidence-grounded explanations for non-Jenkins incidents.

Only provider observations determine the failure category. No runbook or model
claim is accepted as proof of recovery or a causal deployment relationship.
"""
from apps.mcp.trace_presentation import safe_text


_DOCKER_ACTIONS = {
    "oom_killed": (
        "The container was terminated by an out-of-memory kill, confirmed by Docker.",
        [
            "Reduce the service's memory footprint or increase its memory allocation for the observed workload.",
            "Restart only after the memory configuration has been corrected and approved.",
        ],
        ["Confirm the container stays running and subsequent Docker samples report OOMKilled=false."],
    ),
    "out_of_memory": (
        "The application reported a memory-allocation failure, but Docker did not independently confirm an OOMKilled termination.",
        [
            "Reduce application memory pressure or increase its configured capacity based on observed usage.",
            "Retry startup only after the memory condition has been addressed.",
        ],
        ["Confirm the application stays running and check Docker OOMKilled and memory-pressure metrics."],
    ),
    "disk_full": (
        "The container reported that the filesystem has no available space.",
        [
            "Reclaim unused storage on the affected volume or expand the filesystem capacity.",
            "Restart the workload only after sufficient free space is available.",
        ],
        ["Confirm filesystem capacity is healthy and the container stops reporting storage errors."],
    ),
    "port_conflict": (
        "The service could not bind its network port because that address is already in use.",
        [
            "Change the service port mapping or release the conflicting listener.",
            "Redeploy with a nonconflicting port binding after approval.",
        ],
        ["Verify the service becomes reachable and its Docker health state is healthy."],
    ),
    "missing_executable": (
        "A required executable, file or module was not found in the container.",
        [
            "Include the missing executable or dependency in the container image and verify its startup command.",
            "Rebuild the image and roll out the corrected version after approval.",
        ],
        ["Confirm the service starts successfully without the missing-dependency error."],
    ),
    "permission_denied": (
        "A process inside the container was denied access to a required resource.",
        [
            "Correct ownership or access rights for the affected path, volume or runtime identity.",
            "Redeploy the service with only the permissions it requires.",
        ],
        ["Confirm the denied operation succeeds and the container remains healthy."],
    ),
    "database_connection": (
        "The application could not establish a connection to its database.",
        [
            "Restore reachability of the configured database endpoint and validate the service dependency.",
            "Retry application startup after the database is available.",
        ],
        ["Confirm database connectivity and a healthy container state."],
    ),
    "network_connection": (
        "The application reported a network or DNS connectivity failure.",
        [
            "Restore connectivity to the failed dependency or correct its DNS/service address.",
            "Retry the affected workload once the dependency is reachable.",
        ],
        ["Confirm the connection errors stop and the service remains healthy."],
    ),
    "configuration_error": (
        "The service reported an invalid or missing runtime configuration.",
        [
            "Correct the service's required configuration values without exposing secret contents.",
            "Redeploy only after validating the configuration format.",
        ],
        ["Confirm startup succeeds and the previous configuration error disappears."],
    ),
    "startup_failure": (
        "The application reported a startup or initialization failure.",
        [
            "Correct the initialization failure identified in the captured error evidence.",
            "Start the service again only after the underlying dependency or configuration is corrected.",
        ],
        ["Confirm the container reaches its expected healthy running state."],
    ),
    "docker_state_error": (
        "Docker inspect reported a runtime state error.",
        [
            "Correct the runtime condition identified by Docker state inspection.",
            "Retry service startup after verifying the image and runtime configuration.",
        ],
        ["Confirm Docker reports a stable running state with no state error."],
    ),
}


def _docker_report(assessment, resource):
    code = assessment.get("category")
    fallback = (
        "Docker recorded a stopped container, but the captured evidence does not identify the underlying failure.",
        [
            "Run another read-only Revive diagnosis after the collector's next sample to capture startup and state changes.",
            "Do not restart or modify the container automatically without a verified correction and authorization.",
        ],
        ["Confirm the container reaches a stable running state; do not treat a successful command as verified recovery."],
    )
    cause, actions, checks = _DOCKER_ACTIONS.get(code, fallback)
    observed = safe_text(assessment.get("primary_error"), 300)
    exit_code = assessment.get("exit_code")
    if code == "unclassified" and exit_code not in (None, "", 0, "0"):
        cause += f" Docker recorded exit code {exit_code}, which alone does not prove an OOM or other root cause."
    elif observed and code != "oom_killed":
        cause += " Observed error: " + observed
    state = assessment.get("container_status") or "unknown"
    summary = f"Docker reports the {resource} container in state {state}. " + (
        "OOMKilled was confirmed." if code == "oom_killed"
        else "Revive identified a specific error." if code != "unclassified"
        else "No specific failure mechanism was established."
    )
    return {
        "title": f"Docker incident: {resource}",
        "summary": summary,
        "root_cause": cause,
        "steps": actions,
        "verification": checks,
        "model_cause_allowed": code in _DOCKER_ACTIONS,
        "source": assessment,
    }


def _metric_report(assessment, resource):
    code = assessment.get("category")
    issue = safe_text(assessment.get("issue"), 360)
    if code == "low_available_memory":
        cause = issue + " This is a confirmed measurement of low available memory, not proof of which process caused it."
        actions = [
            "Relieve the observed host memory pressure or add capacity to the affected host.",
            "Avoid assuming a container OOM without an independent Docker OOMKilled signal.",
        ]
        verification = ["Confirm the available-memory metric rises and the associated alert clears."]
    elif code == "low_disk_space":
        cause = issue + " The responsible files or process have not been established by this metric."
        actions = [
            "Reclaim storage or expand the affected filesystem based on the reported device and mountpoint labels.",
            "Prevent repeated accumulation by applying appropriate retention limits.",
        ]
        verification = ["Confirm free disk space increases and the disk alert clears."]
    elif code == "high_cpu_utilization":
        cause = issue + " The metric does not identify which process is consuming CPU."
        actions = [
            "Reduce the observed workload pressure or scale capacity on the affected host.",
            "Use correlated service metrics to distinguish expected load from a malfunction before making configuration changes.",
        ]
        verification = ["Confirm CPU utilization returns below the configured alert threshold."]
    elif code == "firing_alert":
        cause = issue + " The alert alone does not establish the root cause."
        actions = [
            "Apply the correction appropriate to the monitored condition and affected instance when additional evidence supports it.",
            "Use Revive's correlated Docker, CI and metric evidence rather than treating the alert name as a complete diagnosis.",
        ]
        verification = ["Confirm the alert transitions out of FIRING and the underlying metric recovers."]
    else:
        cause = issue + " The underlying mechanism remains unverified."
        actions = [
            "Use the recorded alert labels, metric values and time window to select the affected component.",
            "Apply a targeted correction only after related source evidence supports it.",
        ]
        verification = ["Confirm the metric and alert state recover in a later monitoring sample."]
    label_map = assessment.get("labels") if isinstance(assessment.get("labels"), dict) else {}
    instance = safe_text(label_map.get("instance") or label_map.get("job"), 90)
    subject = f" on {instance}" if instance else ""
    window = assessment.get("time_window") or {}
    trend = ""
    if window.get("status") == "observed" and window.get("samples", 0) >= 2:
        first, last = window.get("first"), window.get("last")
        if first is not None and last is not None:
            trend = f" Revive sampled {window['samples']} points over the correlated period (first {first:g}, last {last:g})."
    return {
        "title": f"Monitoring incident: {resource}",
        "summary": f"The monitored signal {resource}{subject} is in state {assessment.get('status') or 'unknown'}." + trend,
        "root_cause": cause,
        "steps": actions,
        "verification": verification,
        "model_cause_allowed": False,
        "source": assessment,
    }


def describe_source_incident(context, operational_evidence=None, decisions=None):
    """Return a source-grounded report block or None for legacy/Jenkins paths."""
    context = context if isinstance(context, dict) else {}
    alert = context.get("alert") or {}
    source = str(alert.get("source") or "").lower()
    resource = safe_text(alert.get("resource") or "unknown resource", 110)
    assessment = context.get("source_assessment")
    if isinstance(assessment, dict):
        if source == "docker":
            return _docker_report(assessment, resource)
        if source in ("prometheus", "alertmanager"):
            return _metric_report(assessment, resource)
    # Deployment signals must not be passed off as a verified causal release.
    decisions = decisions if isinstance(decisions, dict) else {}
    evidence = operational_evidence if isinstance(operational_evidence, dict) else {}
    if decisions.get("incident_family") == "deployment_regression" and not source:
        changes = evidence.get("deployment_changes") or []
        recent = [c for c in changes[:3] if isinstance(c, dict) and c.get("job")]
        if recent:
            item = recent[0]
            status = safe_text(item.get("result"), 45) or "unknown"
            job = safe_text(item.get("job"), 100)
            build = item.get("build")
            summary = f"Revive observed Jenkins job {job}, build #{build}, with result {status}."
        else:
            summary = "Revive has no correlated deployment event establishing which release preceded the symptom."
        return {
            "title": "Deployment regression assessment",
            "summary": summary,
            "root_cause": (
                "A deployment regression has been suspected, but no causal link "
                "between a particular release and a service failure has been confirmed."
            ),
            "steps": [
                "Compare the observed deployment status with the affected service's health and version evidence.",
                "Use an approved rollback only after identifying the release responsible for the regression.",
            ],
            "verification": [
                "Confirm the service is healthy after any approved correction or rollback."
            ],
            "model_cause_allowed": False,
            "source": {"category": "unverified_deployment_correlation", "release_events": len(recent)},
        }
    return None
