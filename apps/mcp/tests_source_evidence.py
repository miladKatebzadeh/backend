"""Source-aware, read-only diagnostic regression coverage (no live services)."""
import json
from datetime import timedelta
from unittest.mock import Mock, patch

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from apps.collector.models import DockerMetric, PrometheusAlert
from apps.mcp.diagnostic_reporting import readable_report
from apps.mcp.incident_context import (
    build_incident_context, retrieval_query_text, routing_context_text,
)
from apps.mcp.source_evidence import (
    analyze_docker_observation, analyze_metric_observation,
    fetch_active_alert, fetch_docker_evidence, fetch_prometheus_window,
)
from apps.mcp.source_reporting import describe_source_incident
from apps.mcp.trace_presentation import context_view, trace_summary


class SourceEvidenceUnitTests(SimpleTestCase):
    def test_oom_killed_is_a_confirmed_termination_mechanism(self):
        analysis = analyze_docker_observation({
            "status": "exited", "exit_code": 137, "oom_killed": True,
            "logs": "INFO starting",
        })
        self.assertEqual(analysis["category"], "oom_killed")
        self.assertTrue(analysis["root_cause_confirmed"])
        self.assertIn("OOMKilled=true", analysis["primary_error"])

    def test_exit_137_without_docker_oom_flag_does_not_prove_oom(self):
        analysis = analyze_docker_observation({
            "status": "exited", "exit_code": 137, "oom_killed": False,
            "logs": "INFO service shutdown",
        })
        self.assertEqual(analysis["diagnostic_status"], "insufficient_evidence")
        self.assertFalse(analysis["root_cause_confirmed"])
        self.assertIsNone(analysis["primary_error"])

    def test_actual_container_startup_error_is_extracted_and_redacted(self):
        analysis = analyze_docker_observation({
            "status": "exited", "oom_killed": False,
            "logs": "INFO start\nERROR executable file not found: gunicorn token=secret123",
        })
        self.assertEqual(analysis["category"], "missing_executable")
        self.assertIn("gunicorn", analysis["primary_error"])
        self.assertNotIn("secret123", json.dumps(analysis))
        self.assertIn("[REDACTED]", json.dumps(analysis))
        self.assertFalse(analysis["root_cause_confirmed"])

    def test_app_out_of_memory_text_is_not_docker_confirmed_oom(self):
        observation = analyze_docker_observation({
            "status": "exited", "oom_killed": False,
            "logs": "ERROR out of memory while allocating buffer",
        })
        self.assertEqual(observation["category"], "out_of_memory")
        self.assertFalse(observation["root_cause_confirmed"])
        report = describe_source_incident({
            "alert": {"source": "docker", "resource": "api"},
            "source_assessment": observation,
        })
        self.assertIn("did not independently confirm", report["root_cause"])

    @patch("apps.mcp.source_evidence.requests.get")
    @patch("apps.collector.tasks._docker_api", return_value="http://docker.local")
    def test_docker_provider_reads_only_exact_scoped_container(self, docker_api, get):
        get.side_effect = [
            Mock(json=lambda: [
                {"Id": "a" * 64, "Names": ["/other"], "State": "running"},
                {"Id": "b" * 64, "Names": ["/grafana"], "State": "exited"},
            ], raise_for_status=lambda: None),
            Mock(json=lambda: {
                "State": {"Status": "exited", "OOMKilled": False, "ExitCode": 1},
                "RestartCount": 2, "Config": {"Image": "grafana:latest"},
            }, raise_for_status=lambda: None),
            Mock(content=b"ERROR: address already in use", raise_for_status=lambda: None),
        ]
        detail = fetch_docker_evidence("grafana")
        self.assertEqual(detail["status"], "exited")
        self.assertIn("address already in use", detail["logs"])
        self.assertEqual(get.call_count, 3)
        urls = [call.args[0] for call in get.call_args_list]
        self.assertTrue(all("/containers" in url for url in urls))
        self.assertTrue(all("POST" not in url for url in urls))
        self.assertIn("b" * 64, urls[1])
        self.assertIn("b" * 64, urls[2])
        self.assertEqual(detail["evidence_origin"], "live_docker_read_only")

    @patch("apps.mcp.source_evidence.requests.get")
    @patch("apps.collector.tasks._docker_api", return_value="http://docker.local")
    def test_docker_inspect_still_used_if_log_api_unavailable(self, docker_api, get):
        import requests
        get.side_effect = [
            Mock(json=lambda: [{"Id": "c" * 64, "Names": ["/api"]}],
                 raise_for_status=lambda: None),
            Mock(json=lambda: {"State": {
                "Status": "exited", "OOMKilled": True, "ExitCode": 137,
            }}, raise_for_status=lambda: None),
            requests.ConnectionError("logs unavailable"),
        ]
        result = fetch_docker_evidence("api")
        self.assertTrue(result["oom_killed"])
        self.assertEqual(result["logs"], "")

    @patch("apps.mcp.source_evidence.requests.get")
    @patch("apps.mcp.models.get_setting", return_value="http://prometheus.local")
    def test_prometheus_range_is_scoped_by_metric_and_series_labels(self, setting, get):
        get.return_value = Mock(raise_for_status=lambda: None, json=lambda: {
            "status": "success", "data": {"result": [
                {"metric": {"instance": "other"}, "values": [[1, "999"]]},
                {"metric": {"instance": "node-a"}, "values": [
                    [1, "2000000000"], [2, "1000000000"], [3, "500000000"],
                ]},
            ]}
        })
        result = fetch_prometheus_window(
            "node_memory_MemAvailable_bytes", {"instance": "node-a"},
            timezone.now(),
        )
        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["samples"], 3)
        self.assertEqual(result["minimum"], 500000000)
        self.assertEqual(get.call_args.kwargs["params"]["query"], "node_memory_MemAvailable_bytes")
        self.assertIn("/api/v1/query_range", get.call_args.args[0])

    @patch("apps.mcp.source_evidence.requests.get")
    def test_arbitrary_promql_is_not_executed_from_an_incident_resource(self, get):
        self.assertIsNone(fetch_prometheus_window(
            'rate(http_requests_total[5m])', {}, timezone.now(),
        ))
        get.assert_not_called()

    @patch("apps.mcp.source_evidence.requests.get")
    @patch("apps.mcp.models.get_setting", return_value="http://alertmanager.local")
    def test_alertmanager_result_matches_exact_instance(self, setting, get):
        get.return_value = Mock(raise_for_status=lambda: None, json=lambda: [
            {"labels": {"alertname": "HostDown", "instance": "unrelated"},
             "annotations": {"summary": "A different host"}},
            {"labels": {"alertname": "HostDown", "instance": "node-a"},
             "annotations": {"summary": "Target is unreachable"},
             "status": {"state": "active"}},
        ])
        actual = fetch_active_alert(
            "alert:HostDown", source="alertmanager", labels={"instance": "node-a"},
        )
        self.assertEqual(actual["instance"], "node-a")
        self.assertIn("unreachable", actual["summary"])
        self.assertNotIn("different", json.dumps(actual).lower())

    def test_metric_interpretation_does_not_invent_a_process_cause(self):
        analysis = analyze_metric_observation({
            "metric": "node_filesystem_avail_bytes",
            "type": "host_disk_space", "status": "CRITICAL_DISK_FULL",
            "value": 1073741824, "labels": {"instance": "node-a", "mountpoint": "/"},
        })
        report = describe_source_incident({
            "alert": {"source": "prometheus", "resource": "node_filesystem_avail_bytes"},
            "source_assessment": analysis,
        })
        self.assertIn("1.00 GiB", report["root_cause"])
        self.assertIn("not been established", report["root_cause"])
        self.assertIn("Reclaim", report["steps"][0])
        self.assertFalse(analysis["root_cause_confirmed"])

    def test_deployment_events_are_evidence_not_proof_of_a_regression(self):
        report = describe_source_incident(
            {},
            operational_evidence={"deployment_changes": [{
                "job": "CSAI", "build": 6, "result": "FAILURE",
            }]},
            decisions={"incident_family": "deployment_regression"},
        )
        self.assertIn("CSAI", report["summary"])
        self.assertIn("no causal link", report["root_cause"])
        self.assertFalse(report["model_cause_allowed"])


class CrossSourceContextTests(TestCase):
    def setUp(self):
        self.now = timezone.now()

    @patch("apps.mcp.incident_context.fetch_docker_evidence")
    def test_docker_automatic_recheck_is_scoped_and_populates_report_and_trace(self, fetch):
        DockerMetric.objects.create(
            container_name="api", status="exited", oom_killed=False,
            container_logs="INFO process exited",
            raw_stats={"exit_code": 1}, timestamp=self.now,
        )
        DockerMetric.objects.create(
            container_name="other", status="exited",
            container_logs="ERROR: no space left on device",
            timestamp=self.now,
        )
        fetch.return_value = {
            "status": "exited", "oom_killed": False, "exit_code": 1,
            "state_error": "", "logs": "ERROR: bind: address already in use",
            "evidence_origin": "live_docker_read_only",
            "checked_at": self.now.isoformat(),
        }
        ctx = build_incident_context(
            "api container failed", {
                "source": "docker", "resource": "api", "status": "open",
                "incident_id": 7,
            }, observed_at=self.now,
        )
        fetch.assert_called_once_with("api")
        assessment = ctx["source_assessment"]
        self.assertEqual(assessment["category"], "port_conflict")
        self.assertEqual(assessment["evidence_origin"], "live_docker_read_only")
        self.assertNotIn("no space left on device", json.dumps(ctx))
        self.assertIn("address already in use", routing_context_text(ctx, "fallback"))
        self.assertIn("address already in use", retrieval_query_text(
            {"incident_family": "container_runtime"}, ctx, "fallback",
        ))
        report = readable_report(ctx, json.dumps({
            "incident_detected": True,
            "diagnostic_report": "Delete all containers now.",
            "user_report": {"summary": "Delete all containers now.",
                            "likely_cause": "broken disk",
                            "recommended_steps": ["Delete all containers now."]},
        }), "ok", agent={"agent_triggered": False})
        self.assertIn("network port", report["root_cause"])
        self.assertNotIn("Delete all", json.dumps(report))
        self.assertEqual(report["source_assessment"]["category"], "port_conflict")
        self.assertIn("port", report["recommended_steps"][0].lower())
        self.assertFalse(report["recovery_verified"])
        trace = context_view(ctx)
        self.assertEqual(trace["source_assessment"]["category"], "port_conflict")

    @patch("apps.mcp.incident_context.fetch_docker_evidence")
    def test_historical_docker_incident_does_not_use_live_container_as_past_proof(self, fetch):
        past = self.now - timedelta(days=2)
        ctx = build_incident_context(
            "api failed in the past",
            {
                "source": "docker", "resource": "api", "status": "open",
                "incident_id": 91,
                "snapshot": {"container_status": "exited", "exit_code": 137,
                             "oom_killed": False, "log_excerpt": "INFO shutdown"},
            }, observed_at=past,
        )
        fetch.assert_not_called()
        self.assertEqual(ctx["evidence_status"], "incident_snapshot")
        self.assertFalse(ctx["source_assessment"]["root_cause_confirmed"])
        self.assertEqual(ctx["source_assessment"]["evidence_origin"], "incident_ledger_snapshot")

    @patch("apps.mcp.incident_context.fetch_prometheus_window")
    def test_prometheus_auto_range_is_included_in_llm_routing_and_user_report(self, window):
        PrometheusAlert.objects.create(
            metric_name="node_filesystem_avail_bytes", value=1073741824,
            labels={"instance": "node-a", "mountpoint": "/"},
            alert_status="CRITICAL_DISK_FULL", metric_type="host_disk_space",
            updated_at=self.now,
        )
        window.return_value = {
            "status": "observed", "samples": 3,
            "first": 2000000000.0, "last": 1073741824.0,
            "minimum": 1073741824.0, "maximum": 2000000000.0,
        }
        ctx = build_incident_context(
            "Disk critically low", {
                "source": "prometheus", "resource": "node_filesystem_avail_bytes",
                "status": "open", "incident_id": 98,
            }, observed_at=self.now,
        )
        window.assert_called_once_with(
            "node_filesystem_avail_bytes",
            {"instance": "node-a", "mountpoint": "/"}, self.now,
        )
        self.assertIn("1.00 GiB", ctx["source_assessment"]["issue"])
        self.assertIn("available filesystem space", retrieval_query_text(
            {"incident_family": "metric_anomaly"}, ctx, "fallback",
        ).lower())
        report = readable_report(ctx, json.dumps({
            "incident_detected": True, "diagnostic_report": "Ask user to check logs.",
        }), "offline")
        self.assertIn("Reclaim", report["recommended_steps"][0])
        self.assertEqual(report["source_assessment"]["time_window"]["samples"], 3)
        self.assertFalse(report["recovery_verified"])

    @patch("apps.mcp.incident_context.fetch_prometheus_window")
    def test_historical_metric_uses_ledger_snapshot_not_live_series(self, window):
        past = self.now - timedelta(days=3)
        ctx = build_incident_context(
            "Low available memory",
            {"source": "prometheus", "resource": "node_memory_MemAvailable_bytes",
             "status": "open", "incident_id": 102, "snapshot": {
                 "metric_type": "host_memory_bounds",
                 "alert_status": "CRITICAL_LOW_MEMORY",
                 "value": 536870912,
                 "labels": {"instance": "node-a"},
             }},
            observed_at=past,
        )
        window.assert_not_called()
        self.assertEqual(ctx["evidence_status"], "incident_snapshot")
        self.assertIn("0.50 GiB", ctx["source_assessment"]["issue"])

    @patch("apps.mcp.incident_context.fetch_active_alert")
    def test_correlated_alertmanager_description_is_read_only(self, active):
        PrometheusAlert.objects.create(
            metric_name="alert:TargetDown", value=1, alert_status="FIRING",
            metric_type="alertmanager",
            labels={"alertname": "TargetDown", "instance": "node-a"},
            updated_at=self.now,
        )
        active.return_value = {
            "status": "observed", "alertname": "TargetDown",
            "description": "node-a did not respond",
            "source": "live_alert_read_only",
        }
        ctx = build_incident_context(
            "Target down", {"source": "alertmanager", "resource": "alert:TargetDown",
                            "status": "open", "incident_id": 77},
            observed_at=self.now,
        )
        active.assert_called_once_with(
            "alert:TargetDown", source="alertmanager",
            labels={"alertname": "TargetDown", "instance": "node-a"},
        )
        self.assertIn("did not respond", ctx["evidence"]["metric_window_anomalies"][0]["alert_detail"]["description"])
        self.assertEqual(ctx["source_assessment"]["category"], "firing_alert")
