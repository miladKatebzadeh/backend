"""Regression coverage for evidence-first Alert + Error diagnosis."""
import json
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from apps.collector.models import DockerMetric, JenkinsBuild, PrometheusAlert
from apps.mcp.diagnostics import diagnose, monitor_incident_daemon
from apps.mcp.incident_context import (
    build_incident_context,
    retrieval_query_text,
    routing_context_text,
)


class EvidenceContextTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        DockerMetric.objects.create(
            container_name="grafana",
            status="exited",
            oom_killed=True,
            restart_count=3,
            raw_stats={
                "exit_code": 137,
                "state_error": "",
                "image": "grafana/grafana:latest",
            },
            container_logs="INFO normal\nERROR: out of memory token=supersecret",
            timestamp=self.now,
        )
        DockerMetric.objects.create(
            container_name="unrelated-container",
            status="exited",
            raw_stats={"exit_code": 1},
            container_logs="ERROR: image pull failed",
            timestamp=self.now,
        )
        DockerMetric.objects.create(
            container_name="grafana",
            status="exited",
            raw_stats={"exit_code": 9},
            container_logs="ERROR: old unrelated problem",
            timestamp=self.now - timedelta(hours=2),
        )

    def _docker_context(self):
        return build_incident_context(
            "System Alert: Container 'grafana' status is 'exited'.",
            resource_scope={"source": "docker", "resource": "grafana", "status": "exited"},
            observed_at=self.now,
        )

    def test_alert_and_correlated_errors_share_a_context(self):
        context = self._docker_context()
        self.assertEqual(context["evidence_status"], "observed")
        self.assertEqual(len(context["evidence"]["container_telemetry"]), 1)
        self.assertEqual(context["alert"]["resource"], "grafana")
        kinds = {error["kind"] for error in context["errors"]}
        self.assertIn("oom_killed", kinds)
        self.assertIn("exit_code", kinds)
        self.assertIn("log_error", kinds)
        rendered = json.dumps(context)
        self.assertNotIn("supersecret", rendered)
        self.assertNotIn("unrelated-container", rendered)
        self.assertNotIn("old unrelated problem", rendered)
        self.assertIn("[REDACTED]", rendered)

    def test_routing_and_retrieval_use_failure_mechanism(self):
        context = self._docker_context()
        routing = routing_context_text(context, "fallback alert")
        query = retrieval_query_text({"incident_family": "container_runtime"}, context, "fallback alert")
        self.assertIn("OOMKilled", routing)
        self.assertIn("out of memory", query)
        self.assertIn("exit code 137", query)
        self.assertNotIn("image pull failed", query)

    def test_no_matching_sample_does_not_guess_an_error(self):
        ctx = build_incident_context(
            "Container missing exited",
            resource_scope={"source": "docker", "resource": "missing", "status": "exited"},
            observed_at=self.now,
        )
        self.assertEqual(ctx["errors"], [])
        self.assertEqual(ctx["evidence_status"], "alert_only")

    def test_jenkins_and_prometheus_use_their_own_sources(self):
        JenkinsBuild.objects.create(
            job_name="release-pipeline",
            build_number=17,
            result="FAILURE",
            console_output="ERROR: tests failed",
            updated_at=self.now,
        )
        PrometheusAlert.objects.create(
            metric_name="node_cpu_usage",
            value=96.3,
            alert_status="FIRING",
            metric_type="cpu",
            updated_at=self.now,
        )
        jenkins = build_incident_context(
            "Build failed",
            {"source": "jenkins", "resource": "release-pipeline"},
            observed_at=self.now,
        )
        self.assertEqual(jenkins["evidence"]["ci_pipeline_logs"][0]["build_number"], 17)
        self.assertTrue(any(x["kind"] == "log_error" for x in jenkins["errors"]))
        prometheus = build_incident_context(
            "CPU alert",
            {"source": "prometheus", "resource": "node_cpu_usage"},
            observed_at=self.now,
        )
        self.assertEqual(prometheus["evidence"]["metric_window_anomalies"][0]["value"], 96.3)
        self.assertEqual(prometheus["errors"][0]["kind"], "metric_alert")
        self.assertNotIn("ci_pipeline_logs", prometheus["evidence"])

    @patch("apps.mcp.diagnostics._chat")
    @patch("apps.mcp.diagnostics.get_langfuse", return_value=None)
    @patch("apps.mcp.diagnostics.active_tool_catalog", return_value=[])
    @patch("apps.mcp.diagnostics.retrieve")
    @patch("apps.mcp.diagnostics.route")
    def test_both_laya_and_chroma_receive_error_before_llm(
        self, route, retrieve, tools, langfuse, chat,
    ):
        route.return_value = {
            "router": "laya", "incident_family": "container_runtime",
            "need_container_events": True, "need_runbook_search": True,
        }
        retrieve.return_value = {
            "results": [], "source": "none", "candidate_count": 0, "filters": [],
        }
        chat.return_value = json.dumps({
            "incident_detected": True,
            "error_scope": "container_runtime",
            "diagnostic_report": "OOM is supported by Docker inspect.",
            "evidence_refs": ["docker_inspect"],
            "engine_status": "ok", "tool_name": "", "tool_target": "",
        })
        result = diagnose(
            "System Alert: Container grafana exited",
            resource_scope={"source": "docker", "resource": "grafana", "status": "exited"},
            observed_at=self.now,
            allow_remediation=False,
        )
        self.assertEqual(result["engine_status"], "ok")
        self.assertIn("OOMKilled", route.call_args.args[0])
        self.assertIn("OOMKilled", retrieve.call_args.args[0])
        llm_packet = chat.call_args.args[3]
        self.assertIn("OBSERVED INCIDENT CONTEXT", llm_packet)
        self.assertIn("OOMKilled", llm_packet)
        self.assertIn("exit code 137", llm_packet)
        self.assertNotIn("image pull failed", llm_packet)

    @patch("apps.mcp.diagnostics._chat")
    @patch("apps.mcp.diagnostics.get_langfuse", return_value=None)
    @patch("apps.mcp.diagnostics.active_tool_catalog", return_value=[])
    @patch("apps.mcp.diagnostics.retrieve")
    @patch("apps.mcp.diagnostics.route")
    def test_verified_active_incident_overrides_false_model_detection(
        self, route, retrieve, tools, langfuse, chat,
    ):
        route.return_value = {"router": "laya", "incident_family": "unknown"}
        retrieve.return_value = {"results": [], "source": "none", "candidate_count": 0, "filters": []}
        chat.return_value = json.dumps({
            "incident_detected": False, "error_scope": "container_runtime",
            "diagnostic_report": "Everything is healthy.", "evidence_refs": [],
            "tool_name": "restart_container", "tool_target": "grafana",
        })
        result = diagnose(
            "Grafana exited", resource_scope={"source": "docker", "resource": "grafana", "status": "exited"},
            observed_at=self.now, allow_remediation=False,
        )
        self.assertEqual(result["decisions"]["incident_family"], "container_runtime")
        payload = json.loads(result["reply"])
        self.assertTrue(payload["incident_detected"])
        self.assertIn("Monitoring confirms", payload["diagnostic_report"])
        self.assertNotIn("Everything is healthy", payload["diagnostic_report"])
        self.assertEqual(payload["tool_name"], "")

    @patch("apps.mcp.diagnostics.get_setting")
    @patch("apps.mcp.diagnostics.diagnose")
    def test_monitor_daemon_supplies_scoped_evidence_and_does_not_fake_remediation(self, diagnose, settings):
        settings.side_effect = lambda key, default=None: "15" if key == "scrape_interval" else "0"
        diagnose.return_value = {
            "engine_status": "ok", "agent_automation": {"agent_triggered": False}, "reply": "{}",
        }
        result = monitor_incident_daemon()
        self.assertIsNotNone(result)
        self.assertEqual(diagnose.call_args.kwargs["resource_scope"]["resource"], "grafana")
        self.assertEqual(diagnose.call_args.kwargs["observed_at"], self.now)
        row = DockerMetric.objects.get(container_name="grafana", timestamp=self.now)
        row.refresh_from_db()
        self.assertFalse(row.remediation_attempted)
        self.assertIsNotNone(row.last_attempt_at)
