# Revive Langfuse Trace Guide / راهنمای خواندن تریس‌ها

**Schema:** `revive.incident.v2` · **Trace name:** `Revive | Incident diagnosis`

Every new diagnostic trace is designed to answer five questions in order:

1. **What happened? / چه اتفاقی افتاد؟** The monitored alert, source and resource.
2. **What was observed? / چه شواهدی ثبت شده؟** Actual error indicators and telemetry, with provenance and timestamps.
3. **Which documentation was retrieved? / کدام مستندات بازیابی شدند؟** Ranked Runbook titles, matching terms, origin and search method.
4. **What did the AI assess? / تحلیل هوش مصنوعی چیست؟** A diagnosis, which may remain uncertain.
5. **Was anything executed and verified? / آیا اقدامی اجرا و نتیجه تأیید شد؟** Separate permission, execution and verification states.

## Reading the trace

Open the **trace output → overview** first. This is the reader-friendly summary.
For detailed investigation, expand these numbered spans in order:

| Span | Purpose | Important fields |
|---|---|---|
| `01 | Alert and evidence` | Alert + source-scoped, time-correlated errors | `status`, `observed_errors`, `telemetry_samples` |
| `02 | Laya routing` | Routing decision or keyword fallback | `router`, `incident_family`, `requested_evidence` |
| `03 | Runbook retrieval` | ChromaDB / hybrid / PostgreSQL search result | `retrieval_backend`, `matched_count`, `top_matches` |
| `04 | Telemetry checked` | Which evidence was available to the diagnosis | `status`, `sample_counts` |
| `05 | AI diagnosis` | Model assessment and supporting references | `status`, `assessment`, `evidence_references` |
| `05b | AI diagnosis retry` | Only if the initial model result was invalid | `status`, `assessment` |
| `06 | Remediation and verification` | Whether any tool was authorized, executed and verified | `authorized`, `tool_executed`, `recovery_verified` |

Span **input** indicates what that stage received; **output** is the result. They are no longer overwritten with identical data.

## Jenkins Pipeline errors / خطای واقعی Jenkins

For a Jenkins Incident, look under **trace output → incident_evidence → pipeline_failure**:

- `diagnostic_status: specific_error_found`: the Collector identified a substantive error in the Build's console (e.g. `executable file not found`). The actual error, its surrounding lines, nearby shell command and Pipeline stage are recorded separately.
- `diagnostic_status: only_generic_build_failure`: available data only shows the Build failed. The root cause **remains unknown**; request more complete Jenkins logs instead of guessing.
- `primary_error`: the precise observed error line; **not** necessarily the underlying verified root cause.
- `failing_stage` / `failing_command`: context near that error, if Jenkins emitted this information; not necessarily the command that caused the ultimate failure.
- `error_context`: short, sanitized lines near the selected error to help a human reproduce or investigate it.
- `execution_exit_code`: exit status of a process, **not** an explanation of why it exited.

`Finished: FAILURE`, `ERROR: script returned exit code 1` and `[Pipeline] // timeout` are generic Jenkins wrappers and will not be promoted to `primary_error` without a substantive error line. A closing `// timeout` block does **not** prove a timeout occurred.

The collector uses bounded, credential-redacted failure windows from the fetched console rather than blindly keeping the final 100 lines. Correlation is scoped to the specific Jenkins job and, when present, the Incident's exact Build number. When historical samples are unavailable, Revive can use the stored Incident snapshot, preserving its provenance.

The routing query for Laya, Runbook retrieval query and Ollama request use the same extracted failure evidence. **Runbook matches are still reference material**, and model-generated hypotheses require independent verification.

### Automatic Jenkins investigation and English reporting

- An `npm error A complete log of this run can be found in...` line, `npm help ci`, and generic npm usage/aliases are **not primary errors**. Specific npm errors such as lockfile mismatches, package version conflicts and missing dependencies outrank these footer lines.
- The system does not associate an npm failure with an unrelated `git rev-parse` command. It links only nearby compatible commands in the same Pipeline stage.
- When an Incident-linked Jenkins diagnosis has only generic stored output, Revive makes a **read-only request for that exact job/build console** using its already-configured Jenkins connection. If Jenkins still has actionable details, Revive updates the correlated evidence and its trace. It does not request that the user hunt through log files.
- Existing persisted summaries created by older parsing logic are reclassified before use. If the Jenkins output cannot be retrieved or contains only generic text, the root cause remains explicitly unknown.
- User-facing `user_report` defaults to **English** with “What went wrong,” “Recommended resolution,” and “How to verify recovery.” The model is prompted to write clear English and not hand off log reading. The backend uses grounded English fallbacks if model prose is not usable.
- Neither investigation nor report generation authorizes or executes remediation tools.

The routing query for Laya, Runbook retrieval query and Ollama request use the same extracted failure evidence. **Runbook matches are still reference material**, and model-generated hypotheses require independent verification.

**دستور بررسی پس از استقرار:**

```bash
python manage.py test apps.mcp.tests_jenkins_evidence apps.mcp.tests_incident_context apps.mcp.tests_diagnostic_reporting
```

## Critical distinctions / تفاوت‌های مهم

- **`engine_status: ok`**: the diagnostic model returned a usable answer. This does **not** mean the resource recovered.
- **`recovery_verified: true`**: a tool actually ran and the recovery verifier confirmed a recovered resource.
- **`not_requested`**: no remediation authorization was given, so no tool ran.
- **`not_executed`**: remediation was requested, but the system did not execute a tool.
- **`executed_unverified`**: tool returned success but independent recovery was not established.
- **`postgres_fallback`**: a Runbook was returned by the PostgreSQL fallback. Do **not** describe that as a ChromaDB result.
- **`ranking_score` / `vector_distance`**: ranking signals, *not* confidence percentages.
- **`detection_basis: monitoring_record`**: the monitoring source confirmed an active Incident even though the initial AI classification disagreed.
- **`evidence_status: incident_snapshot`**: stored historical Incident evidence was used, not necessarily a live telemetry sample.
- **`evidence_status: alert_only`**: no corroborating telemetry was found. Don't infer a root cause from the alert alone.

## Illustrative trace output (fictional data — not a claim about the live Grafana Incident)

```json
{
  "schema_version": "revive.incident.v2",
  "overview": {
    "what_happened": "Container grafana exited",
    "evidence_status": "observed",
    "observed_errors": ["Docker reports OOMKilled=true"],
    "routing": "Laya selected container_runtime.",
    "runbooks": "1 runbook(s) retrieved from hybrid search.",
    "ai_assessment": "Docker reports an OOM kill. Check the memory limit and recent usage.",
    "ai_status": "ok",
    "action": "Diagnosis only. No remediation tool was authorized or executed.",
    "recovery_verified": false
  }
}
```

A Runbook is **reference information**, not evidence that the suggested cause actually occurred. Keep the alert/error provenance and verification visible to the reader.

## Correlating a chat request with Langfuse

`POST /api/mcp/chat/` now also returns `trace_id` when Langfuse ingestion is configured. If Langfuse is disabled or missing credentials, the field is `null`. A returned ID alone does not prove the remote ingestion succeeded; look for errors in backend logs or verify the trace in Langfuse.

## Data minimization

The Trace intentionally records short descriptions, relevant observed error indicators and Runbook titles instead of full raw logs, documents and LLM prompts. Basic secret redaction and structured size limits are applied to the trace payload. For stricter confidentiality, use dedicated application redaction and Langfuse data governance; heuristics cannot guarantee that every secret is removed.

The new format changes observability only: it does not automatically close Incidents or execute MCP tools.
