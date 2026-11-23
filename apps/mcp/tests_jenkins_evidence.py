"""Jenkins console root-error extraction and evidence-flow regression tests."""
import json
from datetime import timedelta
from unittest.mock import patch

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from apps.collector.models import JenkinsBuild
from apps.collector.tasks import StandaloneCollectorDaemon
from apps.mcp.incident_context import build_incident_context, retrieval_query_text, routing_context_text
from apps.mcp.jenkins_evidence import (
    analyze_jenkins_console, select_jenkins_console, fetch_jenkins_build_console,
)
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

    def test_npm_help_and_debug_log_path_are_never_selected_as_root_error(self):
        console = "\n".join([
            "[Pipeline] stage",
            "[Pipeline] { (Frontend tests)",
            "[Pipeline] sh",
            "+ git rev-parse --short=12 HEAD",
            "npm error",
            "npm error aliases: clean-install, ic, install-clean",
            'npm error Run "npm help ci" for more info',
            "npm error A complete log of this run can be found in: /tmp/.npm/_logs/debug.log",
            "ERROR: script returned exit code 1",
            "Finished: FAILURE",
        ])
        result = analyze_jenkins_console(console)
        self.assertEqual(result["diagnostic_status"], "insufficient_console_detail")
        self.assertIsNone(result["primary_error"])
        self.assertIsNone(result["failing_command"])
        self.assertNotIn("/tmp/.npm", str(result["error_lines"]))

    def test_npm_ci_lockfile_problem_is_identified_and_associated_with_npm_command(self):
        console = "\n".join([
            "[Pipeline] stage",
            "[Pipeline] { (Frontend tests)",
            "[Pipeline] sh",
            "+ npm ci",
            "+ git rev-parse --short=12 HEAD",
            "npm error code EUSAGE",
            "npm error npm ci can only install packages when your package.json and package-lock.json are in sync.",
            "npm error Missing: eslint@9.1.0 from lock file",
            'npm error Run "npm help ci" for more info',
            "npm error A complete log of this run can be found in: /tmp/debug.log",
            "ERROR: script returned exit code 1",
            "Finished: FAILURE",
        ])
        parsed = analyze_jenkins_console(console)
        self.assertEqual(parsed["diagnostic_status"], "specific_error_found")
        self.assertTrue(
            "package-lock.json" in parsed["primary_error"]
            or "Missing:" in parsed["primary_error"]
        )
        self.assertEqual(parsed["failing_stage"], "Frontend tests")
        self.assertEqual(parsed["failing_command"], "npm ci")
        self.assertNotIn("/tmp/debug", str(parsed["error_lines"]))
        self.assertNotIn("git rev-parse", str(parsed["failing_command"]))

    @patch("apps.mcp.jenkins_evidence.requests.get")
    @patch("apps.mcp.models.get_setting")
    def test_exact_jenkins_console_fetch_is_read_only_scoped_and_authenticated(
        self, setting, request,
    ):
        lookup = {
            "jenkins_url": "https://jenkins.example.org",
            "jenkins_user": "ci-readonly",
            "jenkins_token": "example-token",
        }
        setting.side_effect = lambda key, default=None: lookup.get(key, default)

        class Response:
            text = "npm error code EUSAGE"
            def raise_for_status(self):
                pass

        request.return_value = Response()
        console = fetch_jenkins_build_console("folder/CSAI", 6)
        self.assertIn("EUSAGE", console)
        self.assertEqual(
            request.call_args.args[0],
            "https://jenkins.example.org/job/folder/job/CSAI/6/consoleText",
        )
        self.assertEqual(request.call_args.kwargs["auth"], ("ci-readonly", "example-token"))
        self.assertFalse(request.call_args.kwargs.get("data"))
        request.reset_mock()
        self.assertIsNone(fetch_jenkins_build_console("CSAI", "not-a-build"))
        request.assert_not_called()

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

    @patch("apps.mcp.incident_context.fetch_jenkins_build_console")
    def test_stale_old_parser_false_positive_triggers_refetch(self, fetch):
        footer = "npm error A complete log of this run can be found in: /tmp/debug.log"
        JenkinsBuild.objects.create(
            job_name="CSAI", build_number=6, result="FAILURE",
            raw_build_info={"failure_analysis": {
                "primary_error": footer,
                "diagnostic_status": "specific_error_found",
                "error_lines": [footer],
            }},
            console_output=footer,
            updated_at=self.now,
        )
        fetch.return_value = "\\n".join([
            "[Pipeline] { (Frontend tests)",
            "+ npm ci",
            "npm error code EUSAGE",
            "npm error npm ci cannot install packages when package-lock.json is outdated.",
            footer,
        ])
        context = build_incident_context(
            "CSAI #6 failed",
            {"source": "jenkins", "resource": "CSAI", "status": "open",
             "incident_id": 42, "snapshot": {"build_number": 6}},
            observed_at=self.now,
        )
        fetch.assert_called_once_with("CSAI", 6)
        error = context["evidence"]["ci_pipeline_logs"][0]["failure_analysis"]["primary_error"]
        self.assertNotIn("A complete log", error)
        self.assertIn("package-lock.json", error)

    def test_build_number_scope_excludes_another_failure_in_same_job(self):
        JenkinsBuild.objects.create(
            job_name="CSAI", build_number=6, result="FAILURE",
            raw_build_info={"failure_analysis": analyze_jenkins_console(SAMPLE_JENKINS_CONSOLE)},
            updated_at=self.now,
        )
        JenkinsBuild.objects.create(
            job_name="CSAI", build_number=7, result="FAILURE",
            raw_build_info={"failure_analysis": analyze_jenkins_console(
                "error: unrelated compile failure"
            )},
            updated_at=self.now,
        )
        context = build_incident_context(
            "CSAI Build #6 failed",
            {
                "source": "jenkins", "resource": "CSAI", "status": "open",
                "snapshot": {"build_number": 6, "build_result": "FAILURE"},
            },
            observed_at=self.now,
        )
        rows = context["evidence"]["ci_pipeline_logs"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["build_number"], 6)
        self.assertIn("gunicorn", rows[0]["failure_analysis"]["primary_error"])
        self.assertNotIn("unrelated compile", json.dumps(context))

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

    @patch("apps.mcp.diagnostics.get_langfuse", return_value=None)
    @patch("apps.mcp.diagnostics.active_tool_catalog", return_value=[])
    @patch("apps.mcp.diagnostics.retrieve", return_value={
        "results": [], "source": "none", "candidate_count": 0, "filters": {},
    })
    @patch("apps.mcp.diagnostics.route", return_value={
        "router": "keywords", "incident_family": "ci_failure",
        "need_runbook_search": True, "need_ci_logs": True,
    })
    @patch("apps.mcp.diagnostics._chat", return_value=json.dumps({
        "incident_detected": False,
        "error_scope": "OBSERVED INCIDENT CONTEXT",
        "diagnostic_report": "No issue was found.",
        "evidence_refs": [],
        "user_report": {"summary": "Everything is healthy."},
        "tool_name": "", "tool_target": "",
    }))
    def test_llm_receives_real_error_and_false_negative_is_corrected(
        self, chat, router, retrieval, tools, langfuse,
    ):
        from apps.mcp.diagnostics import diagnose

        JenkinsBuild.objects.create(
            job_name="CSAI", build_number=6, result="FAILURE",
            raw_build_info={"failure_analysis": analyze_jenkins_console(SAMPLE_JENKINS_CONSOLE)},
            console_output=select_jenkins_console(SAMPLE_JENKINS_CONSOLE),
            updated_at=self.now,
        )
        result = diagnose(
            "Jenkins build #6 failed",
            resource_scope={"source": "jenkins", "resource": "CSAI", "status": "open"},
            observed_at=self.now,
            allow_remediation=False,
        )
        self.assertIn("gunicorn", router.call_args.args[0])
        self.assertIn("gunicorn", retrieval.call_args.args[0])
        self.assertIn("gunicorn", chat.call_args.args[3])
        self.assertIn("JENKINS CONSOLE FAILURE ANALYSIS", chat.call_args.args[3])
        reply = json.loads(result["reply"])
        self.assertTrue(reply["incident_detected"])
        self.assertEqual(reply["error_scope"], "ci_failure")
        self.assertIn("gunicorn", reply["diagnostic_report"])
        self.assertNotIn("user_report", reply)
        self.assertIn("gunicorn", result["user_report"]["root_cause"])
        self.assertNotIn("Everything is healthy", json.dumps(result["user_report"]))
        self.assertFalse(result["agent_automation"]["agent_triggered"])

    @patch("apps.mcp.incident_context.fetch_jenkins_build_console")
    def test_incident_chat_retries_exact_build_and_recovers_real_npm_error(self, fetch):
        old_console = "\n".join([
            'npm error Run "npm help ci" for more info',
            "npm error A complete log of this run can be found in: /tmp/.npm/debug.log",
            "ERROR: script returned exit code 1",
        ])
        fresh_console = "\n".join([
            "[Pipeline] { (Frontend tests)",
            "+ npm ci",
            "npm error code EUSAGE",
            "npm error npm ci can only install packages when package.json and package-lock.json are in sync.",
            "npm error A complete log of this run can be found in: /tmp/.npm/debug.log",
            "ERROR: script returned exit code 1",
        ])
        fetch.return_value = fresh_console
        JenkinsBuild.objects.create(
            job_name="CSAI", build_number=6, result="FAILURE",
            console_output=old_console, updated_at=self.now,
        )
        context = build_incident_context(
            "CSAI Build #6 FAILURE",
            {
                "source": "jenkins", "resource": "CSAI", "status": "open",
                "incident_id": 42, "snapshot": {"build_number": 6},
            },
            observed_at=self.now,
        )
        fetch.assert_called_once_with("CSAI", 6)
        result = context["evidence"]["ci_pipeline_logs"][0]["failure_analysis"]
        self.assertIn("package-lock.json", result["primary_error"])
        self.assertEqual(result["failing_command"], "npm ci")
        self.assertEqual(result["evidence_origin"], "jenkins_exact_build_refetch")
        persisted = JenkinsBuild.objects.get(job_name="CSAI", build_number=6)
        self.assertIn("package-lock.json", persisted.console_output)

    @patch("apps.mcp.incident_context.fetch_jenkins_build_console")
    def test_no_live_refetch_when_previous_jenkins_error_is_substantive(self, fetch):
        analysis = analyze_jenkins_console(SAMPLE_JENKINS_CONSOLE)
        JenkinsBuild.objects.create(
            job_name="CSAI", build_number=6, result="FAILURE",
            console_output=SAMPLE_JENKINS_CONSOLE,
            raw_build_info={"failure_analysis": analysis},
            updated_at=self.now,
        )
        build_incident_context(
            "CSAI Build #6 FAILURE",
            {"source": "jenkins", "resource": "CSAI", "status": "open",
             "incident_id": 42, "snapshot": {"build_number": 6}},
            observed_at=self.now,
        )
        fetch.assert_not_called()

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
    def test_transient_console_fetch_failure_preserves_existing_build_evidence(
        self, get_setting, http_get,
    ):
        analysis = analyze_jenkins_console(SAMPLE_JENKINS_CONSOLE)
        JenkinsBuild.objects.create(
            job_name="CSAI", build_number=6, result="FAILURE",
            raw_build_info={"failure_analysis": analysis},
            console_output=select_jenkins_console(SAMPLE_JENKINS_CONSOLE),
            updated_at=self.now,
        )
        get_setting.side_effect = lambda key, default="": default

        class Reply:
            def __init__(self, status_code, payload=None):
                self.status_code, self._payload = status_code, payload
            def raise_for_status(self):
                if self.status_code >= 400:
                    raise ValueError("HTTP error")
            def json(self):
                return self._payload

        http_get.side_effect = [
            Reply(200, {"jobs": [{"name": "CSAI", "lastBuild": {
                "number": 6, "result": "FAILURE", "duration": 1000,
            }}]}),
            Reply(503),
        ]
        StandaloneCollectorDaemon.collect_jenkins_data()
        row = JenkinsBuild.objects.get(job_name="CSAI", build_number=6)
        self.assertIn("gunicorn", row.console_output)
        self.assertEqual(row.raw_build_info["failure_analysis"], analysis)

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
