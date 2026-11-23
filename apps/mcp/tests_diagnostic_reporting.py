"""Regression tests for Ollama failures and user-facing diagnosis reports."""
import json
from unittest.mock import patch

from django.test import SimpleTestCase, TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from apps.collector.models import JenkinsBuild
from apps.incidents.models import Incident
from apps.mcp.diagnostic_reporting import (
    observed_incident, offline_diagnosis, ollama_error_details, readable_report,
)


class OllamaDiagnosticsUnitTests(SimpleTestCase):
    def test_response_error_preserves_http_status_without_exposing_credentials(self):
        class ProviderError(Exception):
            status_code = 404
            error = "model 'missing:latest' not found; token=very-secret"
        info = ollama_error_details(ProviderError("private exception"), "missing:latest")
        self.assertEqual(info["http_status"], 404)
        self.assertEqual(info["category"], "not_found")
        self.assertIn("missing:latest", info["message"])
        self.assertNotIn("very-secret", json.dumps(info))
        self.assertIn("[REDACTED]", info["message"])

    def test_500_error_has_practical_troubleshooting_hint(self):
        class ProviderError(Exception):
            status_code = 500
            error = "failed to load model"
        info = ollama_error_details(ProviderError(), "my-model")
        self.assertEqual(info["category"], "server_error")
        self.assertIn("RAM/GPU", info["hint"])

    def test_monitoring_failure_survives_model_outage(self):
        context = {
            "alert": {
                "source": "jenkins", "resource": "CSAI", "status": "open",
                "message": "Jenkins build #6 finished with FAILURE",
            },
            "errors": [
                {"kind": "build_result", "source": "jenkins", "message": "Build #6 result: FAILURE"},
                {"kind": "log_error", "source": "jenkins_console", "message": "ERROR: script returned exit code 1"},
            ],
        }
        self.assertTrue(observed_incident(context))
        raw = offline_diagnosis(context, {"http_status": 404})
        parsed = json.loads(raw)
        self.assertTrue(parsed["incident_detected"])
        self.assertEqual(parsed["engine_status"], "offline")
        report = readable_report(context, raw, "offline", agent={"agent_triggered": False})
        self.assertTrue(report["incident_confirmed"])
        self.assertEqual(report["status"], "ai_unavailable")
        self.assertIn("CSAI", report["title"])
        self.assertIn("exit code 1", report["evidence"][1]["text"])
        self.assertIn("علت اصلی", report["root_cause"])
        self.assertTrue(report["recommended_steps"])
        self.assertTrue(report["verification_steps"])
        self.assertFalse(report["recovery_verified"])
        self.assertEqual(report["source"], "monitoring_only")

    def test_model_assessment_is_clearly_a_hypothesis_not_a_verified_fix(self):
        raw = json.dumps({
            "incident_detected": True, "diagnostic_report": "بررسی محدودیت حافظه",
            "user_report": {
                "summary": "احتمالاً حافظه کافی نبوده است.",
                "likely_cause": "کمبود حافظه",
                "recommended_steps": ["میزان حافظه را بررسی کنید."],
                "verification_steps": ["اجرای مجدد سرویس را بررسی کنید."],
            },
        }, ensure_ascii=False)
        ctx = {"alert": {"source": "docker", "resource": "grafana", "status": "exited"}}
        report = readable_report(ctx, raw, "ok")
        self.assertEqual(report["status"], "ai_assessment")
        self.assertIn("هنوز نیازمند تأیید", report["root_cause"])
        self.assertFalse(report["recovery_verified"])
        self.assertIn("میزان حافظه", report["recommended_steps"][0])


class OllamaDiagnosticsApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        now = timezone.now()
        self.incident = Incident.objects.create(
            fingerprint="o" * 64,
            source=Incident.Source.JENKINS,
            resource="CSAI",
            title="Jenkins build failure CSAI",
            description="Build #6 finished with result FAILURE.",
            severity=Incident.Severity.HIGH,
            status=Incident.Status.OPEN,
            first_seen=now,
            last_seen=now,
        )
        JenkinsBuild.objects.create(
            job_name="CSAI", build_number=6, result="FAILURE",
            console_output="ERROR: script returned exit code 1\nFinished: FAILURE",
            updated_at=now,
        )

    def _request(self):
        return self.client.post(
            "/api/mcp/chat/",
            {"message": "دلیل شکست این Build چیست؟", "incident_id": self.incident.pk},
            format="json",
        )

    def _diagnosis_context_patches(self):
        # Use real incident correlation, but no external routing, Chroma, or tools.
        return [
            patch("apps.mcp.diagnostics.get_langfuse", return_value=None),
            patch("apps.mcp.diagnostics.route", return_value={
                "router": "keywords", "incident_family": "ci_failure",
                "need_runbook_search": True, "need_ci_logs": True,
            }),
            patch("apps.mcp.diagnostics.retrieve", return_value={
                "results": [], "source": "none", "candidate_count": 0, "filters": {},
            }),
            patch("apps.mcp.diagnostics.active_tool_catalog", return_value=[]),
        ]

    def test_offline_model_returns_confirmed_incident_and_persian_report(self):
        class ResponseError(Exception):
            status_code = 404
            error = "model not found"
        patches = self._diagnosis_context_patches()
        with patches[0], patches[1], patches[2], patches[3], patch(
            "apps.mcp.diagnostics._chat", side_effect=ResponseError()
        ):
            result = self._request()
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.data["engine_status"], "offline")
        self.assertEqual(result.data["ollama_error"]["http_status"], 404)
        self.assertEqual(result.data["ollama_error"]["category"], "not_found")
        reply = json.loads(result.data["reply"])
        self.assertTrue(reply["incident_detected"])
        self.assertTrue(result.data["user_report"]["incident_confirmed"])
        self.assertEqual(result.data["user_report"]["language"], "fa")
        self.assertEqual(result.data["user_report"]["source"], "monitoring_only")
        self.assertFalse(result.data["action"]["triggered"])
        self.assertIn("ERROR: script returned exit code 1", [
            e["text"] for e in result.data["user_report"]["evidence"]
        ])

    def test_invalid_model_response_does_not_erase_monitoring_failure(self):
        patches = self._diagnosis_context_patches()
        with patches[0], patches[1], patches[2], patches[3], patch(
            "apps.mcp.diagnostics._chat", side_effect=["bad JSON", "still bad"]
        ) as model:
            result = self._request()
        self.assertEqual(model.call_count, 2)
        self.assertEqual(result.data["engine_status"], "invalid")
        self.assertTrue(json.loads(result.data["reply"])["incident_detected"])
        self.assertTrue(result.data["user_report"]["incident_confirmed"])
        self.assertEqual(result.data["user_report"]["status"], "ai_unusable")
        self.assertFalse(result.data["action"]["triggered"])

    def test_healthy_model_provides_structured_farsi_summary(self):
        output = json.dumps({
            "incident_detected": True, "error_scope": "ci_failure",
            "diagnostic_report": "این Build شکست خورده و علت قطعی مشخص نیست.",
            "evidence_refs": ["jenkins_console"],
            "user_report": {
                "summary": "ساخت پروژه CSAI ناموفق بود.",
                "likely_cause": "دستور Pipeline با کد ۱ خاتمه یافت",
                "recommended_steps": ["مرحله ناموفق را در لاگ پیدا کنید."],
                "verification_steps": ["اجرای موفق Build بعدی را بررسی کنید."],
            },
        }, ensure_ascii=False)
        patches = self._diagnosis_context_patches()
        with patches[0], patches[1], patches[2], patches[3], patch(
            "apps.mcp.diagnostics._chat", return_value=output
        ):
            result = self._request()
        self.assertEqual(result.data["engine_status"], "ok")
        report = result.data["user_report"]
        self.assertIn("CSAI", report["summary"])
        self.assertEqual(report["runbook_count"], 0)
        self.assertEqual(report["recommended_steps"], ["مرحله ناموفق را در لاگ پیدا کنید."])
        self.assertIn("نیازمند تأیید", report["root_cause"])
        self.assertFalse(report["recovery_verified"])
