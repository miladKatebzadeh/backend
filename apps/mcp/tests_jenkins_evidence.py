"""Jenkins console root-error extraction and evidence-flow regression tests."""
import json
from datetime import timedelta
from unittest.mock import patch

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from apps.collector.models import JenkinsBuild
from apps.collector.tasks import StandaloneCollectorDaemon
from apps.mcp.incident_context import build_incident_context, retrieval_query_text, routing_context_text
from apps.mcp.jenkins_evidence import analyze_jenkins_console, select_jenkins_console
from apps.mcp.trace_presentation import context_view


ACTUAL_ERROR = (
    'docker: Error response from daemon: failed to create task for container: '
    'OCI runtime create failed: exec: "gunicorn": executable file not found in $PATH.'
)

SAMPLE_JENKINS_CONSOLE = "\n".join([
    "Started by user Milad",
    "[Pipeline] stage",
    "[Pipeline] { (Deploy Container)",
    "[Pipeline] sh",
    "+ docker run -d --name opshubbackend opshubbackend:latest",
    ACTUAL_ERROR,
    "[Pipeline] }",
    "[Pipeline] // stage",
    "[Pipeline] timeout",
    "[Pipeline] {",
    "[Pipeline] }",
    "[Pipeline] // timeout",
    "ERROR: script returned exit code 127",
    "Finished: FAILURE",
])

GENERIC_CONSOLE = "\n".join([
    "[Pipeline] stage",
    "[Pipeline] { (Build)",
    "[Pipeline] sh",
    "[Pipeline] // timeout",
    "ERROR: script returned exit code 1",
    "Finished: FAILURE",
])


class JenkinsLogParserTests(SimpleTestCase):
    def test_specific_docker_runtime_error_outweighs_jenkins_wrapper(self):
        result = analyze_jenkins_console(SAMPLE_JENKINS_CONSOLE)
        self.assertEqual(result["diagnostic_status"], "specific_error_found")
        self.assertEqual(result["primary_error"], ACTUAL_ERROR)
        self.assertEqual(result["failing_stage"], "Deploy Container")
        self.assertEqual(
            result["failing_command"],
            "docker run -d --name opshubbackend opshubbackend:latest",
        )
        self.assertEqual(result["execution_exit_code"], 127)
        self.assertFalse(result["root_cause_confirmed"])
        self.assertNotIn("Finished: FAILURE", result["error_lines"])
        self.assertNotIn("[Pipeline] // timeout", result["error_lines"])

    def test_only_generic_jenkins_wrappers_does_not_fabricate_cause(self):
        result = analyze_jenkins_console(GENERIC_CONSOLE)
        self.assertEqual(result["diagnostic_status"], "only_generic_build_failure")
        self.assertIsNone(result["primary_error"])
        self.assertIsNone(result["failing_stage"])
        self.assertEqual(result["error_lines"], [])
        self.assertEqual(result["execution_exit_code"], 1)
        self.assertFalse(result["root_cause_confirmed"])

    def test_specific_error_survives_more_than_100_following_lines(self):
        source = (
            SAMPLE_JENKINS_CONSOLE.split("[Pipeline] }")[0]
            + "\n" + "\n".join("INFO background diagnostic entry" for _ in range(180))
            + "\nERROR: script returned exit code 127\nFinished: FAILURE"
        )
        self.assertNotIn("gunicorn", "\n".join(source.splitlines()[-100:]))
        saved = select_jenkins_console(source)
        self.assertIn("gunicorn", saved)
        self.assertIn("Deploy Container", saved)
        self.assertLessEqual(len(saved), 14000)
        self.assertEqual(
            analyze_jenkins_console(saved)["diagnostic_status"],
            "specific_error_found",
        )

    def test_log_credentials_are_redacted(self):
        source = (
            "[Pipeline] { (Deploy Container)\n"
            "+ docker run -e DB_PASSWORD=supersecret app\n"
            "error: connection refused token=private123\n"
            "Finished: FAILURE"
        )
        saved = select_jenkins_console(source)
        analysis = analyze_jenkins_console(source)
        self.assertNotIn("supersecret", saved)
        self.assertNotIn("private123", json.dumps(analysis))
        self.assertIn("[REDACTED]", saved)

    def test_compiler_failure_is_specific_not_wrapper(self):
        source = "\n".join([
            "[Pipeline] { (TypeScript)",
            "+ npm run build",
            "error TS2307: Cannot find module './missing'",
            "ERROR: script returned exit code 2",
            "Finished: FAILURE",
        ])
        analysis = analyze_jenkins_console(source)
        self.assertIn("TS2307", analysis["primary_error"])
        self.assertEqual(analysis["failing_stage"], "TypeScript")
        self.assertEqual(analysis["failing_command"], "npm run build")


class JenkinsEvidenceFlowTests(TestCase):
    def setUp(self):
        self.now = timezone.now()

    def test_context_uses_specific_error_for_routing_runbook_and_trace(self):
        analysis = analyze_jenkins_console(SAMPLE_JENKINS_CONSOLE)
        JenkinsBuild.objects.create(
            job_name="CSAI", build_number=6, result="FAILURE",
            raw_build_info={"failure_analysis": analysis},
            console_output=select_jenkins_console(SAMPLE_JENKINS_CONSOLE),
            updated_at=self.now,
        )
        JenkinsBuild.objects.create(
            job_name="other-project", build_number=99, result="FAILURE",
            raw_build_info={"failure_analysis": analyze_jenkins_console(
                "error: missing unrelated dependency"
            )},
            console_output="error: missing unrelated dependency",
            updated_at=self.now,
        )
        context = build_incident_context(
            "Jenkins CSAI build #6 FAILURE",
            {"source": "jenkins", "resource": "CSAI", "status": "open"},
            observed_at=self.now,
        )
        pipeline = context["evidence"]["ci_pipeline_logs"][0]["failure_analysis"]
        self.assertIn("gunicorn", pipeline["primary_error"])
        self.assertEqual(pipeline["failing_stage"], "Deploy Container")
        self.assertEqual(context["errors"][0]["kind"], "pipeline_error")
        self.assertIn("gunicorn", routing_context_text(context, "fallback"))
        query = retrieval_query_text({"incident_family": "ci_failure"}, context, "fallback")
        self.assertIn("gunicorn", query)
        self.assertNotIn("Finished: FAILURE", query)
        self.assertNotIn("unrelated dependency", json.dumps(context))
        trace = context_view(context)
        self.assertIn("gunicorn", trace["pipeline_failure"]["primary_error"])
        self.assertEqual(trace["pipeline_failure"]["failing_stage"], "Deploy Container")

    def test_generic_wrapper_only_keeps_cause_unknown(self):
        JenkinsBuild.objects.create(
            job_name="CSAI", build_number=6, result="FAILURE",
            console_output=GENERIC_CONSOLE, updated_at=self.now,
        )
        context = build_incident_context(
            "Jenkins build failed",
            {"source": "jenkins", "resource": "CSAI", "status": "open"},
            observed_at=self.now,
        )
        analysis = context["evidence"]["ci_pipeline_logs"][0]["failure_analysis"]
        self.assertEqual(analysis["diagnostic_status"], "only_generic_build_failure")
        self.assertEqual(context["errors"][0]["kind"], "build_result")
        self.assertIn("root cause unknown", context["errors"][1]["message"])
        query = retrieval_query_text({"incident_family": "ci_failure"}, context, "fallback")
        self.assertNotIn("script returned exit code", query)
        self.assertNotIn("timeout", query)

    def test_source_scoped_historical_snapshot_carries_original_failure(self):
        snapshot = {
            "build_result": "FAILURE",
            "build_number": 6,
            "failure_analysis": analyze_jenkins_console(SAMPLE_JENKINS_CONSOLE),
        }
        old = self.now - timedelta(days=2)
        context = build_incident_context(
            "CSAI failed",
            {"source": "jenkins", "resource": "CSAI", "status": "open", "snapshot": snapshot},
            observed_at=old,
        )
        self.assertEqual(context["evidence_status"], "incident_snapshot")
        failure = context["evidence"]["incident_record_snapshot"][0]["failure_analysis"]
        self.assertIn("gunicorn", failure["primary_error"])
        self.assertIn("gunicorn", context["errors"][0]["message"])

    @patch("apps.collector.tasks.requests.get")
    @patch("apps.collector.tasks.get_setting")
    def test_collector_persists_full_log_failure_analysis(self, get_setting, http_get):
        get_setting.side_effect = lambda key, default="": default

        class Reply:
            status_code = 200
            def __init__(self, payload=None, text=""):
                self._payload, self.text = payload, text
            def raise_for_status(self):
                pass
            def json(self):
                return self._payload

        long_log = (
            SAMPLE_JENKINS_CONSOLE.split("[Pipeline] }")[0]
            + "\n" + "\n".join("INFO ordinary work" for _ in range(130))
            + "\nERROR: script returned exit code 127\nFinished: FAILURE"
        )
        http_get.side_effect = [
            Reply(payload={"jobs": [{"name": "CSAI", "lastBuild": {
                "number": 6, "result": "FAILURE", "duration": 1000,
            }}]}),
            Reply(text=long_log),
        ]
        StandaloneCollectorDaemon.collect_jenkins_data()
        row = JenkinsBuild.objects.get(job_name="CSAI")
        self.assertIn("gunicorn", row.console_output)
        self.assertEqual(
            row.raw_build_info["failure_analysis"]["failing_stage"],
            "Deploy Container",
        )
        self.assertIn("gunicorn", row.raw_build_info["failure_analysis"]["primary_error"])
