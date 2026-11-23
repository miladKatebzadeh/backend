"""Regression tests for human-readable and privacy-bounded Langfuse output."""
import json
from unittest.mock import patch

from django.test import SimpleTestCase

from apps.mcp.diagnostics import (
    _LangfuseTarget,
    _Trace,
    _child_span,
    _close_trace,
    _open_trace,
    _set_output,
)
from apps.mcp.trace_presentation import (
    STAGES,
    TRACE_SCHEMA,
    context_view,
    diagnosis_view,
    remediation_view,
    retrieval_view,
    routing_view,
    trace_data,
    trace_input,
    trace_summary,
)


class TracePresentationTests(SimpleTestCase):
    def setUp(self):
        self.context = {
            "alert": {
                "message": "Container grafana exited",
                "source": "docker",
                "resource": "grafana",
                "status": "exited",
                "observed_at": "2026-11-23T10:00:00Z",
                "incident_id": 42,
            },
            "errors": [
                {
                    "kind": "oom_killed",
                    "message": "Docker reports OOMKilled=true",
                    "source": "docker_inspect",
                    "observed_at": "2026-11-23T10:00:00Z",
                },
                {
                    "kind": "log_error",
                    "message": "ERROR: memory allocation failed token=should-not-appear",
                    "source": "docker_logs",
                },
            ],
            "evidence": {"container_telemetry": [{"status": "exited"}]},
            "evidence_status": "observed",
            "window_minutes": 15,
        }
        self.route = {
            "router": "keywords",
            "incident_family": "container_runtime",
            "family_source": "verified_alert_source",
            "need_container_events": True,
            "need_runbook_search": True,
        }
        self.retrieval = {
            "source": "postgres_fallback",
            "candidate_count": 6,
            "filters": {"component": ["docker"]},
            "results": [
                {
                    "title": "Docker OOMKilled",
                    "text": "Full runbook text " * 1000,
                    "document_id": 8,
                    "chunk": 0,
                    "section": "containers",
                    "component": "docker",
                    "retrieval_source": "postgres",
                    "relevance_score": 0.01523,
                    "distance": None,
                    "matched_terms": ["oom", "memory"],
                }
            ],
        }
        self.reply = json.dumps({
            "incident_detected": True,
            "error_scope": "container_runtime",
            "diagnostic_report": "Grafana was OOM killed. Check its memory limit.",
            "evidence_refs": ["Docker OOMKilled", "container logs"],
            "tool_name": "restart_container",
            "tool_target": "grafana",
        })

    def test_root_trace_tells_a_readable_story_without_claiming_recovery(self):
        output = trace_summary(
            self.context, "Grafana exited", self.route, self.retrieval,
            self.reply, "ok", {"agent_triggered": False}, False,
            query="container exited OOMKilled memory",
        )
        self.assertEqual(output["schema_version"], TRACE_SCHEMA)
        self.assertEqual(output["overview"]["what_happened"], "Container grafana exited")
        self.assertIn("OOMKilled", output["overview"]["observed_errors"][0])
        self.assertEqual(output["runbook_search"]["retrieval_backend"], "postgres_fallback")
        self.assertIn("not ChromaDB", output["overview"]["runbooks"])
        self.assertEqual(output["overview"]["ai_status"], "ok")
        self.assertFalse(output["overview"]["recovery_verified"])
        self.assertEqual(output["remediation"]["status"], "not_requested")
        self.assertIn("does not mean", output["interpretation"])
        self.assertNotIn("Full runbook text", json.dumps(output))
        self.assertNotIn("should-not-appear", json.dumps(output))

    def test_source_evidence_and_search_ranking_are_not_confidence_percentages(self):
        observed = context_view(self.context)
        searched = retrieval_view("container oom", self.retrieval)
        routed = routing_view(self.route)
        self.assertEqual(observed["status"], "observed")
        self.assertEqual(observed["telemetry_samples"]["container_telemetry"], 1)
        self.assertEqual(routed["status"], "fallback")
        self.assertEqual(routed["requested_evidence"], ["Container evidence", "Runbooks"])
        self.assertEqual(searched["matched_count"], 1)
        self.assertEqual(searched["top_matches"][0]["rank"], 1)
        self.assertEqual(searched["top_matches"][0]["ranking_score"], 0.01523)
        self.assertIn("not calibrated confidence", searched["score_note"])

    def test_assessment_distinguishes_monitoring_override(self):
        detected = diagnosis_view(self.reply, "ok", monitoring_override=True)
        self.assertEqual(detected["detection_basis"], "monitoring_record")
        self.assertTrue(detected["incident_detected_in_response"])

    def test_distinguishes_execution_failure_from_verified_recovery(self):
        self.assertEqual(remediation_view(False, {"agent_triggered": False})["status"], "not_requested")
        self.assertEqual(
            remediation_view(True, {"agent_triggered": False, "error": "no matching tool"})["status"],
            "not_executed",
        )
        attempted = remediation_view(True, {
            "agent_triggered": True, "matched_tool": "restart_container",
            "sandbox_output": {"success": True}, "resolved": False,
        })
        self.assertEqual(attempted["status"], "executed_unverified")
        self.assertFalse(attempted["recovery_verified"])
        unexpected = remediation_view(False, {
            "agent_triggered": True, "matched_tool": "restart_container",
            "sandbox_output": {"success": True}, "resolved": False,
        })
        self.assertTrue(unexpected["tool_executed"])
        self.assertFalse(unexpected["authorized"])
        self.assertEqual(unexpected["status"], "executed_unverified")
        verified = remediation_view(True, {
            "agent_triggered": True, "sandbox_output": {"success": True},
            "resolved": True, "proof": "container state",
        })
        self.assertEqual(verified["status"], "verified_recovery")

    def test_sensitive_fields_and_large_strings_are_bounded_without_breaking_json(self):
        payload = {
            "token": "very-secret",
            "extra": {
                "authorization": "Bearer also-secret",
                "notes": "error token=another-secret DB_PASSWORD=database-secret LANGFUSE_SECRET_KEY=langfuse-secret",
                "url": "https://operator:password@example.net/path",
                "long": "x" * 2000,
            },
        }
        cleaned = trace_data(payload)
        serialized = json.dumps(cleaned)
        self.assertNotIn("very-secret", serialized)
        self.assertNotIn("also-secret", serialized)
        self.assertNotIn("another-secret", serialized)
        self.assertNotIn("database-secret", serialized)
        self.assertNotIn("langfuse-secret", serialized)
        self.assertNotIn("password@example", serialized)
        self.assertIn("[REDACTED]", serialized)
        self.assertIn("[truncated]", serialized)
        self.assertIsInstance(cleaned["extra"], dict)

    def test_span_keeps_distinct_input_and_output(self):
        client = _LangfuseTarget("public", "secret", "http://langfuse.internal")
        trace = _Trace("Revive | Incident diagnosis", trace_input("Grafana exited", self.context))
        with _child_span(client, STAGES["routing"], {"message": "Grafana exited"}, parent=trace) as span:
            _set_output(span, routing_view(self.route))
        self.assertEqual(trace.children[0].input["message"], "Grafana exited")
        self.assertEqual(trace.children[0].output["incident_family"], "container_runtime")
        self.assertNotEqual(trace.children[0].input, trace.children[0].output)

    def test_exceptions_are_not_published_as_successful_spans(self):
        client = _LangfuseTarget("public", "secret", "http://langfuse.internal")
        trace = _Trace("Revive | Incident diagnosis", {"source": "docker"})
        with self.assertRaises(ValueError):
            with _child_span(client, STAGES["retrieval"], {"query": "grafana exited"}, parent=trace):
                raise ValueError("search crashed")
        self.assertEqual(trace.children[0].output["status"], "error")
        self.assertEqual(trace.children[0].output["error_type"], "ValueError")
        self.assertNotIn("search crashed", json.dumps(trace.children[0].output))
        self.assertEqual(diagnosis_view("{}", "error")["status"], "error")
        self.assertIn("failed", diagnosis_view("{}", "error")["summary"])

    def test_ingestion_emits_readable_stages_metadata_and_same_trace_id(self):
        client = _LangfuseTarget("pk", "sk", "http://langfuse.internal")
        handle = _open_trace(
            client, "Revive | Incident diagnosis",
            trace_input("grafana exited", self.context),
            metadata={"schema_version": TRACE_SCHEMA, "resource": "grafana"},
        )
        with _child_span(client, STAGES["context"], {"resource": "grafana"}, parent=handle["span"]) as span:
            _set_output(span, context_view(self.context))

        class Response:
            status_code = 207
            content = b'{"successes": [], "errors": []}'
            text = ""
            def json(self):
                return {"successes": [], "errors": []}

        with patch("apps.mcp.diagnostics.requests.post", return_value=Response()) as send:
            _close_trace(handle, trace_summary(
                self.context, "Grafana exited", self.route, self.retrieval,
                self.reply, "ok", {"agent_triggered": False}, False,
            ))
        batch = send.call_args.kwargs["json"]["batch"]
        self.assertEqual(batch[0]["type"], "trace-create")
        self.assertEqual(batch[0]["body"]["metadata"]["schema_version"], TRACE_SCHEMA)
        self.assertIn("trace-v2", batch[0]["body"]["tags"])
        self.assertEqual(batch[1]["body"]["name"], STAGES["context"])
        self.assertEqual(batch[1]["body"]["traceId"], batch[0]["body"]["id"])
        self.assertEqual(batch[1]["body"]["input"]["resource"], "grafana")
        self.assertEqual(batch[1]["body"]["output"]["status"], "observed")
        self.assertIsInstance(batch[0]["body"]["output"]["overview"], dict)
        self.assertNotIn("should-not-appear", json.dumps(batch))
