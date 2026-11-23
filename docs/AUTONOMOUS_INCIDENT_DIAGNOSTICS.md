# Revive — Autonomous Evidence-First Incident Diagnosis

## Goal

The end user should receive a **plain-English explanation, the observed failure
mechanism, safe next steps and an objective recovery check**, without being
asked to investigate Docker logs, Prometheus dashboards, Jenkins logs or npm
debug files manually.

Revive automatically reads bounded provider evidence **using existing configured
connections** before Laya routing, ChromaDB retrieval and Ollama diagnosis. A
read-only investigation must never be treated as approval to execute remediation.

## Incident sources

| Source | Primary evidence | Automatic read-only follow-up | Output |
|---|---|---|---|
| Jenkins | Correlated build + console failure, stage and command | Exact build's console when cached failure details are insufficient | `pipeline_failure` |
| Docker | Container state, OOMKilled, exit code, state error, recent logs | Exact container list → inspect → bounded logs when failure is unclear | `source_assessment`, category and origin |
| Prometheus | Stored threshold alert, metric, value, instance labels | Time-bounded `/api/v1/query_range` for simple metric identifiers and exactly one matching series | Source assessment and observed samples |
| Alertmanager / Prometheus alerts | FIRING/PENDING alert with labels | Current provider alert details (summary/description) for same alert name and instance | Evidence-backed alert summary |
| Deployment regression | Recent Jenkins build status (maximum six-hour window) | Non-mutating release evidence comparison | Explicitly **unverified correlation** |

## Safety, accuracy and evidence provenance

- Provider rechecks happen **only** for a linked Incident with a reliable source
  and resource and a recent event timestamp (within 20 minutes). Older incidents
  use the saved Incident-ledger snapshot; current health must not be confused with
  historic failure state.
- Docker lookup matches an exact container name (not a substring), validates the
  Docker container ID, and only calls **GET** on container list, inspect and logs.
  If logs cannot be retrieved, Docker inspect can still confirm OOMKilled.
- Exit code **137 does not prove OOMKilled**. Only explicit Docker
  `OOMKilled=true` confirms the termination mechanism. Application log statements
  about memory allocation are evidence of an application failure, not Docker OOM
  confirmation.
- Prometheus does not execute arbitrary PromQL taken from an Incident title.
  Automated range queries accept simple metric names and matching stable instance
  labels; ambiguous or missing time series remain unverified.
- An Alertmanager alert name and a recent Jenkins build are **not themselves a
  root cause**. Recovery is not verified unless monitoring independently confirms it.
- Diagnostic findings and selected log lines are bounded and passed through
  the existing token/password redaction layer. Do not put secrets in runbooks.
- No automatic restart, rollback or other action is authorized by gathering
  evidence. Existing explicit remediation approval continues to govern tools.

## What the user sees

`POST /api/mcp/chat/` continues returning the existing structured `user_report`
and `trace_id`. For Docker and monitoring incidents the report also includes
`source_assessment`: observed issue, category, evidence origin and, when
available, metric samples / OOM flags / exact observed runtime errors.

Reports always distinguish:

1. **Observed failure** (source telemetry and error messages).
2. **Likely correction** (safe next steps grounded in the observed failure).
3. **Verification** (a new healthy source signal, never assumed).
4. **Uncertainty** (when only an alert or generic exit status exists).

ChromaDB runbook matches may add background guidance but are never treated as
authoritative evidence that a specific cause occurred.

## Smoke tests after deployment

```powershell
python -m compileall -q apps config manage.py
python manage.py check
python manage.py test apps.mcp.tests_source_evidence apps.mcp.tests_incident_context apps.mcp.tests_diagnostic_reporting apps.mcp.tests_trace_presentation
```

In the web app select an **existing** incident rather than composing an
unscoped message. Ask:

- Docker OOM: `What stopped this container and what would actually resolve it?`
- Docker startup: `Why does the container fail to start? Explain the observed error.`
- Prometheus memory: `What does this low available-memory alert tell us?`
- Prometheus disk: `What is the storage issue and what should be changed?`
- Alertmanager target down: `What is affected by the firing alert?`
- Deployment: `Is there evidence that the latest release caused this incident?`

In Langfuse confirm:

- `incident_evidence.source_assessment` contains a category, bounded observed
  error/value, provenance and no secrets.
- The Laya input and runbook retrieval query include the same observed
  issue, and the LLM prompt begins with `AUTOMATIC SOURCE DIAGNOSIS`.
- No `remediation.tool_executed` is set without authorization.
- If a provider is unavailable or a series is ambiguous, the report retains
  uncertainty and the existing snapshot without inventing results.

## Known constraints

- This PR does not install agents, change infrastructure credentials or add
  new monitoring sources. It uses Docker, Jenkins, Prometheus and Alertmanager
  connections that already exist.
- A Docker container already deleted from the daemon, a missing old Prometheus
  series, or a provider that never exposed an error cannot yield a reliable
  historic root cause. Revive reports this explicitly rather than manufacturing
  a confident explanation.
- A recorded Jenkins build time alone does not prove a service regression.
  Deploy attribution requires confirmed service/release linkage not currently
  represented in the Incident model.
