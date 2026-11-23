from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from apps.collector.models import DockerMetric
from apps.incidents.models import Incident
from apps.mcp.diagnostics import gather


class IncidentChatTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.incident = Incident.objects.create(
            fingerprint="c" * 64,
            source=Incident.Source.DOCKER,
            resource="grafana",
            title="Container grafana exited",
            description="Container 'grafana' status is 'exited'.",
            severity=Incident.Severity.HIGH,
            status=Incident.Status.OPEN,
            first_seen=timezone.now(),
            last_seen=timezone.now(),
        )
        DockerMetric.objects.create(
            container_name="grafana",
            status="exited",
            oom_killed=True,
            restart_count=2,
            container_logs="grafana: out of memory",
            timestamp=timezone.now(),
        )
        DockerMetric.objects.create(
            container_name="unrelated-container",
            status="dead",
            container_logs="secret data from unrelated container",
            timestamp=timezone.now(),
        )

    @patch("apps.mcp.views.get_setting", return_value="1")
    @patch("apps.mcp.views.diagnose")
    def test_resolve_chat_uses_server_incident_and_scoped_telemetry(self, diagnose, setting):
        diagnose.return_value = {
            "reply": '{"incident_detected": true, "diagnostic_report": "Check OOM"}',
            "engine_status": "ok",
            "agent_automation": {"agent_triggered": False},
            "decisions": {"router": "keywords"},
        }
        response = self.client.post(
            "/api/mcp/chat/",
            {
                "incident_id": self.incident.pk,
                "message": "Diagnose and suggest safe recovery steps.",
                "history": [],
            },
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["incident_id"], self.incident.pk)
        args, kwargs = diagnose.call_args
        self.assertIn("Container grafana exited", args[0])
        self.assertIn("grafana: out of memory", args[0])
        self.assertNotIn("secret data from unrelated container", args[0])
        self.assertFalse(kwargs["allow_remediation"])
        self.assertEqual(kwargs["resource_scope"], {"source": "docker", "resource": "grafana"})

    @patch("apps.mcp.views.diagnose")
    def test_follow_up_includes_prior_context(self, diagnose):
        diagnose.return_value = {
            "reply": "ok",
            "engine_status": "ok",
            "agent_automation": {"agent_triggered": False},
            "decisions": {},
        }
        response = self.client.post(
            "/api/mcp/chat/",
            {
                "incident_id": self.incident.pk,
                "message": "What should I check next?",
                "history": [
                    {"role": "user", "text": "Diagnose this incident"},
                    {"role": "assistant", "text": '{"diagnostic_report":"Check memory pressure"}'},
                ],
            },
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        context = diagnose.call_args.args[0]
        self.assertIn("Check memory pressure", context)
        self.assertIn("What should I check next?", context)

    @patch("apps.mcp.views.diagnose")
    def test_missing_or_invalid_incident_rejected_before_diagnosis(self, diagnose):
        missing = self.client.post(
            "/api/mcp/chat/", {"incident_id": 99999, "message": "Analyze"}, format="json"
        )
        self.assertEqual(missing.status_code, 404)
        invalid = self.client.post(
            "/api/mcp/chat/", {"incident_id": "oops", "message": "Analyze"}, format="json"
        )
        self.assertEqual(invalid.status_code, 400)
        diagnose.assert_not_called()

    @patch("apps.mcp.views.diagnose")
    def test_explicit_remediation_approval_reaches_engine(self, diagnose):
        diagnose.return_value = {
            "reply": '{"incident_detected": true, "diagnostic_report": "Recovery proposed"}',
            "engine_status": "ok",
            "agent_automation": {"agent_triggered": False},
            "decisions": {},
        }
        response = self.client.post(
            "/api/mcp/chat/",
            {"incident_id": self.incident.pk, "message": "Apply recommended fix", "remediate": True},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(diagnose.call_args.kwargs["allow_remediation"])

    def test_diagnostic_gather_excludes_other_resource(self):
        evidence = gather(
            {"need_container_events": True, "need_ci_logs": True},
            resource_scope={"source": "docker", "resource": "grafana"},
        )
        self.assertEqual(len(evidence["container_telemetry"]), 1)
        self.assertEqual(evidence["container_telemetry"][0]["container"], "grafana")
        self.assertEqual(evidence["ci_pipeline_logs"], [])

    @patch("apps.mcp.views.diagnose")
    def test_malformed_history_rejected(self, diagnose):
        response = self.client.post(
            "/api/mcp/chat/",
            {"incident_id": self.incident.pk, "message": "Analyze", "history": {}},
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        diagnose.assert_not_called()
