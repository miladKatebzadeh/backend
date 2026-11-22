import json
import os
import sys
from unittest.mock import patch

from django.test import TestCase
from rest_framework.test import APITestCase

from apps.audit.models import AuditEvent
from apps.collector.models import DockerMetric, JenkinsBuild, PrometheusAlert
from apps.collector.tasks import classify_metric
from apps.mcp.models import MCPTool, SystemSetting, get_setting
from apps.mcp.runtime import MCPSandboxExecutor


class MCPToolApiTests(APITestCase):
    def setUp(self):
        self.langfuse = patch('apps.mcp.diagnostics.get_langfuse', return_value=None)
        self.laya = patch('apps.mcp.diagnostics.get_laya', return_value=None)
        self.chroma = patch('apps.mcp.diagnostics.get_chroma_collection', return_value=None)
        self.langfuse.start()
        self.laya.start()
        self.chroma.start()
        self.addCleanup(self.langfuse.stop)
        self.addCleanup(self.laya.stop)
        self.addCleanup(self.chroma.stop)

    def test_tool_lifecycle_requires_confirmation_for_delete(self):
        create = self.client.post('/api/mcp/tools/', {
            'name': 'restart_container',
            'description': 'Restart a container safely',
            'code': 'return name',
            'status': 'active',
        }, format='json')
        self.assertEqual(create.status_code, 201)
        tool_id = create.data['id']

        denied = self.client.delete(f'/api/mcp/tools/{tool_id}/')
        self.assertEqual(denied.status_code, 400)
        self.assertTrue(MCPTool.objects.get(id=tool_id).archived_at is None)

        deleted = self.client.delete(f'/api/mcp/tools/{tool_id}/?confirm=true')
        self.assertEqual(deleted.status_code, 204)
        archived_tool = MCPTool.objects.get(id=tool_id)
        self.assertIsNotNone(archived_tool.archived_at)
        self.assertEqual(archived_tool.status, 'archived')

    def test_tool_update_creates_version(self):
        create = self.client.post('/api/mcp/tools/', {
            'name': 'get_status',
            'description': 'Read status',
            'code': 'return "ok"',
            'status': 'active',
        }, format='json')
        tool_id = create.data['id']
        updated = self.client.patch(f'/api/mcp/tools/{tool_id}/', {'description': 'Read live status'}, format='json')
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(MCPTool.objects.get(id=tool_id).versions.count(), 2)

    def test_run_invokes_the_tool_function(self):
        create = self.client.post('/api/mcp/tools/', {
            'name': 'restart_container',
            'description': 'Restart',
            'code': 'def restart_container(name: str) -> str:\n    return f"restarted {name}"\n',
            'status': 'active',
        }, format='json')
        tool_id = create.data['id']
        result = self.client.post(f'/api/mcp/tools/{tool_id}/run/', {'target': 'web'}, format='json')
        self.assertEqual(result.status_code, 200)
        self.assertTrue(result.data['success'])
        self.assertIn('restarted web', result.data['stdout'])

    def test_settings_round_trip_masks_token(self):
        saved = self.client.post('/api/mcp/settings/', {
            'ollama_host': 'http://localhost:11434',
            'jenkins_token': 'secret-token',
            'scrape_interval': '30',
            'auto_remediate': 'yes',
        }, format='json')
        self.assertEqual(saved.status_code, 200, saved.data)
        current = self.client.get('/api/mcp/settings/')
        self.assertEqual(current.status_code, 200)
        self.assertEqual(current.data['ollama_host'], 'http://localhost:11434')
        self.assertEqual(current.data['jenkins_token'], '')
        self.assertTrue(current.data['jenkins_token_set'])
        self.assertEqual(current.data['scrape_interval'], '30')
        self.assertEqual(current.data['auto_remediate'], '1')
        stored = SystemSetting.objects.get(key='jenkins_token').value
        self.assertNotEqual(stored, 'secret-token')
        self.assertTrue(stored.startswith('enc:v1:'))
        self.assertEqual(get_setting('jenkins_token'), 'secret-token')
        self.client.post('/api/mcp/settings/', {'jenkins_token': ''}, format='json')
        self.assertEqual(get_setting('jenkins_token'), 'secret-token')
        audit = AuditEvent.objects.filter(resource_type='system_setting').first()
        self.assertNotIn('secret-token', json.dumps(audit.payload))

    def test_langfuse_settings_are_masked_and_used_for_the_client(self):
        import sys
        import types

        saved = self.client.post('/api/mcp/settings/', {
            'langfuse_base_url': 'http://10.0.0.8:3030/',
            'langfuse_public_key': 'pk-lf-test-public',
            'langfuse_secret_key': 'sk-lf-test-secret',
        }, format='json')
        self.assertEqual(saved.status_code, 200, saved.data)
        self.assertIn('next diagnosis', saved.data['notes'][0])
        current = self.client.get('/api/mcp/settings/')
        self.assertEqual(current.data['langfuse_base_url'], 'http://10.0.0.8:3030')
        self.assertEqual(current.data['langfuse_public_key'], 'pk-lf-test-public')
        self.assertEqual(current.data['langfuse_secret_key'], '')
        self.assertTrue(current.data['langfuse_secret_set'])
        stored = SystemSetting.objects.get(key='langfuse_secret_key').value
        self.assertTrue(stored.startswith('enc:v1:'))
        self.assertEqual(get_setting('langfuse_secret_key'), 'sk-lf-test-secret')
        self.client.post('/api/mcp/settings/', {'langfuse_secret_key': ''}, format='json')
        self.assertEqual(get_setting('langfuse_secret_key'), 'sk-lf-test-secret')
        audit = AuditEvent.objects.filter(resource_type='system_setting').first()
        self.assertNotIn('sk-lf-test-secret', json.dumps(audit.payload))

        from apps.mcp.diagnostics import reset_langfuse
        reset_langfuse()
        self.addCleanup(reset_langfuse)
        client = self.langfuse.temp_original()
        self.assertEqual(client.base_url, 'http://10.0.0.8:3030')
        self.assertEqual(client.public_key, 'pk-lf-test-public')
        self.assertEqual(client.secret_key, 'sk-lf-test-secret')

    def test_langfuse_probe_checks_access_and_can_send_a_trace(self):
        class Response:
            def __init__(self, status_code, payload):
                self.status_code = status_code
                self._payload = payload
                self.content = b'1' if payload is not None else b''

            def json(self):
                return self._payload

            def raise_for_status(self):
                if self.status_code >= 400:
                    raise RuntimeError('http')

        denied = Response(401, {})
        with patch('apps.mcp.views.requests.get', return_value=denied):
            rejected = self.client.post('/api/mcp/settings/test/', {
                'service': 'langfuse',
                'langfuse_base_url': 'http://10.0.0.8:3030',
                'langfuse_public_key': 'pk-lf-test-public',
                'langfuse_secret_key': 'sk-lf-test-secret',
            }, format='json')
        self.assertEqual(rejected.data['status'], 'invalid')
        self.assertIn('rejected', rejected.data['message'])
        self.assertFalse(SystemSetting.objects.filter(key='langfuse_base_url').exists())

        accepted = Response(200, [{'id': 'p', 'name': 'revive'}])
        with patch('apps.mcp.views.requests.get', return_value=accepted) as get:
            ok = self.client.post('/api/mcp/settings/test/', {
                'service': 'langfuse',
                'langfuse_base_url': 'http://10.0.0.8:3030',
                'langfuse_public_key': 'pk-lf-test-public',
                'langfuse_secret_key': 'sk-lf-test-secret',
            }, format='json')
        self.assertEqual(ok.data['status'], 'connected')
        self.assertEqual(ok.data['message'], 'revive')
        self.assertEqual(get.call_args.args[0], 'http://10.0.0.8:3030/api/public/projects')
        self.assertEqual(get.call_args.kwargs['auth'], ('pk-lf-test-public', 'sk-lf-test-secret'))

        sent = Response(207, {'successes': [{'id': '1'}], 'errors': []})
        with patch('apps.mcp.views.requests.post', return_value=sent) as post:
            traced = self.client.post('/api/mcp/settings/test/', {
                'service': 'langfuse_trace',
                'langfuse_base_url': 'http://10.0.0.8:3030',
                'langfuse_public_key': 'pk-lf-test-public',
                'langfuse_secret_key': 'sk-lf-test-secret',
            }, format='json')
        self.assertEqual(traced.data['status'], 'connected', traced.data)
        self.assertTrue(traced.data['trace_id'])
        body = post.call_args.kwargs['json']['batch'][0]
        self.assertEqual(body['type'], 'trace-create')
        self.assertEqual(body['body']['name'], 'revive-settings-test')
        self.assertEqual(body['body']['id'], traced.data['trace_id'])
        self.assertNotIn('sk-lf-test-secret', json.dumps(body))

    def test_blank_jenkins_user_can_be_cleared(self):
        self.client.post('/api/mcp/settings/', {'jenkins_user': 'milad'}, format='json')
        cleared = self.client.post('/api/mcp/settings/', {'jenkins_user': ''}, format='json')
        self.assertEqual(cleared.status_code, 200, cleared.data)
        self.assertEqual(self.client.get('/api/mcp/settings/').data['jenkins_user'], '')

    def test_settings_reject_metadata_and_empty_urls(self):
        metadata = self.client.post('/api/mcp/settings/', {'prometheus_url': 'http://169.254.169.254/latest'}, format='json')
        self.assertEqual(metadata.status_code, 400)
        empty = self.client.post('/api/mcp/settings/', {'ollama_host': '  '}, format='json')
        self.assertEqual(empty.status_code, 400)
        self.assertIn('ollama_host', empty.data['errors'])

    def test_settings_strip_trailing_slash_and_note_the_next_scrape(self):
        saved = self.client.post('/api/mcp/settings/', {
            'prometheus_url': 'http://127.0.0.1:9090/',
            'scrape_interval': '20',
        }, format='json')
        self.assertEqual(saved.status_code, 200, saved.data)
        self.assertEqual(self.client.get('/api/mcp/settings/').data['prometheus_url'], 'http://127.0.0.1:9090')
        self.assertIn('next collector cycle', saved.data['notes'][0])

    def test_embedding_change_requires_confirmation(self):
        with patch('apps.knowledge.chroma.rebuild_knowledge_index', return_value={'reindexed': True, 'count': 0}) as rebuild:
            denied = self.client.post('/api/mcp/settings/', {'embedding_engine': 'bge-small-en'}, format='json')
            self.assertEqual(denied.status_code, 409)
            rebuild.assert_not_called()
            saved = self.client.post('/api/mcp/settings/', {
                'embedding_engine': 'bge-small-en',
                'confirm_reindex': True,
            }, format='json')
        self.assertEqual(saved.status_code, 200, saved.data)
        self.assertTrue(saved.data['reindex']['reindexed'])

    def test_probe_does_not_save_and_blocks_metadata(self):
        with patch('apps.mcp.views.requests.get', side_effect=ConnectionError('down')):
            offline = self.client.post('/api/mcp/settings/test/', {
                'service': 'prometheus',
                'prometheus_url': 'http://10.0.0.8:9090',
            }, format='json')
        self.assertEqual(offline.status_code, 200)
        self.assertEqual(offline.data['status'], 'offline')
        self.assertFalse(SystemSetting.objects.filter(key='prometheus_url').exists())
        with patch('apps.mcp.views.requests.get') as get:
            blocked = self.client.post('/api/mcp/settings/test/', {
                'service': 'ollama',
                'ollama_host': 'http://169.254.169.254',
            }, format='json')
        get.assert_not_called()
        self.assertEqual(blocked.data['status'], 'invalid')

    def test_settings_reject_non_http_targets(self):
        rejected = self.client.post('/api/mcp/settings/', {'prometheus_url': 'file:///etc/passwd'}, format='json')
        self.assertEqual(rejected.status_code, 400)

    def test_chat_reports_offline_engine_instead_of_nominal(self):
        with patch('apps.mcp.diagnostics._chat', side_effect=ConnectionError('down')):
            result = self.client.post('/api/mcp/chat/', {'message': 'container web exited'}, format='json')
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.data['engine_status'], 'offline')
        payload = json.loads(result.data['reply'])
        self.assertEqual(payload['engine_status'], 'offline')
        self.assertFalse(payload['incident_detected'])

    def test_chat_writes_a_langfuse_span(self):
        from apps.mcp.diagnostics import _LangfuseTarget

        chat = patch('apps.mcp.diagnostics._chat').start()
        self.addCleanup(chat.stop)
        chat.return_value = '{"incident_detected": false, "engine_status": "ok", "diagnostic_report": "ok", "error_scope": "none"}'
        posted = {}

        class Response:
            status_code = 207
            content = b'{}'
            text = ''

            def json(self):
                return {'successes': [{'id': '1'}], 'errors': []}

        def capture(url, json=None, auth=None, timeout=None, allow_redirects=None):
            posted['url'] = url
            posted['json'] = json
            posted['auth'] = auth
            return Response()

        client = _LangfuseTarget('pk-lf-test-public', 'sk-lf-test-secret', 'http://10.0.0.8:3030')
        with patch('apps.mcp.diagnostics.get_langfuse', return_value=client), patch('apps.mcp.diagnostics.requests.post', side_effect=capture):
            result = self.client.post('/api/mcp/chat/', {'message': 'container web exited'}, format='json')
        self.assertEqual(result.status_code, 200)
        self.assertEqual(posted['url'], 'http://10.0.0.8:3030/api/public/ingestion')
        self.assertEqual(posted['auth'], ('pk-lf-test-public', 'sk-lf-test-secret'))
        batch = posted['json']['batch']
        names = [event['body']['name'] for event in batch]
        self.assertEqual(names[0], 'hierarchical_diagnostic_routing')
        self.assertEqual(names[1:], ['laya', 'chromadb', 'telemetry', 'llm'])
        self.assertEqual(batch[0]['type'], 'trace-create')
        self.assertEqual(batch[0]['body']['output']['engine_status'], 'ok')
        self.assertEqual(batch[0]['body']['output']['laya']['incident_family'], 'container_runtime')
        self.assertIn('runbooks', batch[0]['body']['output']['chromadb'])
        self.assertTrue(all(event['body']['traceId'] == batch[0]['body']['id'] for event in batch[1:]))
        self.assertEqual(batch[-1]['type'], 'generation-create')
        self.assertNotIn('/api/public/otel', posted['url'])

    def test_langfuse_base_url_drops_the_otel_suffix(self):
        saved = self.client.post('/api/mcp/settings/', {
            'langfuse_base_url': 'http://10.0.0.8:3030/api/public/otel/v1/traces',
            'langfuse_public_key': 'pk-lf-test-public',
        }, format='json')
        self.assertEqual(saved.status_code, 200, saved.data)
        self.assertEqual(self.client.get('/api/mcp/settings/').data['langfuse_base_url'], 'http://10.0.0.8:3030')

    def test_slow_laya_does_not_block_ollama(self):
        import time

        class SlowRouter:
            def predict(self, state, questions):
                time.sleep(1.5)
                return {'answers': {}}

        chat = patch('apps.mcp.diagnostics._chat').start()
        self.addCleanup(chat.stop)
        chat.return_value = '{"incident_detected": false, "engine_status": "ok", "diagnostic_report": "ok", "error_scope": "none"}'
        with patch('apps.mcp.diagnostics.get_laya', return_value=SlowRouter()), patch.dict(os.environ, {'OPSHUB_LAYA_TIMEOUT': '0.2'}):
            result = self.client.post('/api/mcp/chat/', {'message': 'container web exited'}, format='json')
        self.assertEqual(result.status_code, 200)
        self.assertEqual(chat.call_count, 1)
        self.assertEqual(result.data['router'], 'keywords')

    def test_child_spans_share_the_parent_trace(self):
        from apps.mcp.diagnostics import _LangfuseTarget, _Trace, _child_span
        trace = _Trace('hierarchical_diagnostic_routing', {'incident_raw': 'disk'})
        client = _LangfuseTarget('pk-lf-test-public', 'sk-lf-test-secret', 'http://10.0.0.8:3030')
        with _child_span(client, 'chromadb', {'query': 'disk'}, parent=trace) as span:
            span.update(output={'runbooks': ['restart']})
        self.assertEqual(trace.children[0].name, 'chromadb')
        self.assertEqual(trace.children[0].output['runbooks'], ['restart'])
        self.assertIsNotNone(trace.children[0].ended_at)

    def test_laya_answers_drive_the_route(self):
        from apps.mcp.diagnostics import route

        class Router:
            def predict(self, state, questions):
                return {
                    'answers': {
                        'incident_family': {'choice': 'ci_failure'},
                        'need_ci_logs': {'noul': 0.9},
                        'need_metric_window': {'noul': 0.01},
                        'need_container_events': {'noul': 0.01},
                        'need_deployment_changes': {'noul': 0.2},
                        'need_runbook_search': {'noul': 0.8},
                    },
                    'routing': {'model': 'multilingual'},
                }

        with patch('apps.mcp.diagnostics.get_laya', return_value=Router()):
            decisions = route('بیلد جنکینز شکست', {'fleet_anomaly_snapshot': ''})
        self.assertEqual(decisions['router'], 'laya')
        self.assertEqual(decisions['laya_model'], 'multilingual')
        self.assertEqual(decisions['incident_family'], 'ci_failure')
        self.assertTrue(decisions['need_ci_logs'])
        self.assertFalse(decisions['need_container_events'])

    def test_missing_laya_uses_keywords(self):
        from apps.mcp.diagnostics import route
        decisions = route('disk is full on the host', {})
        self.assertEqual(decisions['router'], 'keywords')
        self.assertTrue(decisions['need_metric_window'])

    def test_diagnosis_does_not_load_laya(self):
        import apps.mcp.diagnostics as diagnostics
        self.laya.stop()
        diagnostics._laya_checked = False
        diagnostics._laya_model = None
        diagnostics._laya_loading = False
        try:
            self.assertIsNone(diagnostics.get_laya())
            self.assertFalse(diagnostics._laya_checked)
            self.assertFalse(diagnostics._laya_loading)
        finally:
            diagnostics._laya_checked = False
            diagnostics._laya_model = None
            diagnostics._laya_loading = False
            self.laya.start()

    def test_warmup_loads_laya_before_any_incident(self):
        import apps.mcp.diagnostics as diagnostics
        self.laya.stop()
        diagnostics._laya_checked = False
        diagnostics._laya_model = None
        diagnostics._laya_loading = False
        router = object()

        class LayaModule:
            @staticmethod
            def Router(preload=False):
                return router

        try:
            with patch.dict(sys.modules, {'laya': LayaModule}):
                diagnostics.warmup_laya()
            self.assertIs(diagnostics.get_laya(), router)
            with patch.dict(sys.modules, {'laya': LayaModule}):
                diagnostics.warmup_laya()
            self.assertIs(diagnostics.get_laya(), router)
        finally:
            diagnostics._laya_checked = False
            diagnostics._laya_model = None
            diagnostics._laya_loading = False
            self.laya.start()

    def test_startup_probe_retires_laya_when_it_does_not_answer(self):
        import time
        import apps.mcp.diagnostics as diagnostics
        self.laya.stop()
        diagnostics._laya_checked = False
        diagnostics._laya_model = None
        diagnostics._laya_loading = False

        class SlowRouter:
            def predict(self, state, questions):
                time.sleep(1)

        class LayaModule:
            @staticmethod
            def Router(preload=False):
                return SlowRouter()

        try:
            with patch.dict(os.environ, {'OPSHUB_LAYA_TIMEOUT': '0.05'}), patch.dict(sys.modules, {'laya': LayaModule}):
                diagnostics.warmup_laya()
            self.assertTrue(diagnostics._laya_checked)
            self.assertIsNone(diagnostics.get_laya())
        finally:
            diagnostics._laya_checked = False
            diagnostics._laya_model = None
            diagnostics._laya_loading = False
            self.laya.start()

    def test_one_laya_timeout_does_not_delay_the_next_message(self):
        import time
        import apps.mcp.diagnostics as diagnostics
        self.laya.stop()
        calls = {'n': 0}

        class SlowRouter:
            def predict(self, state, questions):
                calls['n'] += 1
                time.sleep(1)

        diagnostics._laya_checked = True
        diagnostics._laya_model = SlowRouter()
        diagnostics._laya_loading = False
        try:
            with patch.dict(os.environ, {'OPSHUB_LAYA_TIMEOUT': '0.05'}):
                first = diagnostics.route('disk is full on the host', {})
                second = diagnostics.route('disk is full on the host', {})
            self.assertEqual(first['router'], 'keywords')
            self.assertEqual(second['router'], 'keywords')
            self.assertEqual(calls['n'], 1)
            self.assertIsNone(diagnostics.get_laya())
        finally:
            diagnostics._laya_checked = False
            diagnostics._laya_model = None
            diagnostics._laya_loading = False
            self.laya.start()

    def test_chat_sends_laya_section_and_runbook_to_the_model(self):
        chat = patch('apps.mcp.diagnostics._chat').start()
        self.addCleanup(chat.stop)
        chat.return_value = '{"incident_detected": true, "engine_status": "ok", "diagnostic_report": "restart it", "error_scope": "web"}'

        def fake_retrieve(query):
            fake_retrieve.query = query
            return ['[restart] Restart the stopped container.']

        with patch('apps.mcp.diagnostics.retrieve', side_effect=fake_retrieve):
            result = self.client.post('/api/mcp/chat/', {'message': 'container web exited'}, format='json')
        self.assertEqual(result.status_code, 200)
        packet = chat.call_args.args[3]
        self.assertIn('container runtime', fake_retrieve.query)
        self.assertIn('ERROR:', packet)
        self.assertIn('LAYA:', packet)
        self.assertIn('container_runtime', packet)
        self.assertIn('RUNBOOK:', packet)
        self.assertIn('[restart]', packet)

    def test_chat_retries_once_then_marks_invalid(self):
        with patch('apps.mcp.diagnostics._chat', side_effect=['not json', 'still not']) as chat:
            result = self.client.post('/api/mcp/chat/', {'message': 'container web exited'}, format='json')
        self.assertEqual(chat.call_count, 2)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.data['engine_status'], 'invalid')
        payload = json.loads(result.data['reply'])
        self.assertEqual(payload['engine_status'], 'invalid')
        self.assertIs(payload['incident_detected'], False)

    def test_chat_accepts_a_valid_retry(self):
        good = json.dumps({
            'incident_detected': True,
            'error_scope': 'web',
            'diagnostic_report': 'container exited',
            'evidence_refs': ['web'],
        })
        with patch('apps.mcp.diagnostics._chat', side_effect=['nope', good]):
            result = self.client.post('/api/mcp/chat/', {'message': 'container web exited'}, format='json')
        self.assertEqual(result.data['engine_status'], 'ok')
        self.assertTrue(json.loads(result.data['reply'])['incident_detected'])

    def test_gather_includes_time_and_deployment_changes(self):
        from django.utils import timezone
        from apps.mcp.diagnostics import gather
        when = timezone.now()
        DockerMetric.objects.create(
            container_name='web', status='exited', timestamp=when,
            container_logs='boot line\nError: disk full\n',
        )
        JenkinsBuild.objects.create(job_name='deploy', build_number=4, result='FAILURE', updated_at=when, console_output='ERROR compile failed')
        PrometheusAlert.objects.create(metric_name='disk_free', value=2, alert_status='FIRING', updated_at=when)
        payload = gather({
            'need_container_events': True,
            'need_metric_window': True,
            'need_ci_logs': True,
            'need_deployment_changes': True,
        })
        self.assertEqual(payload['container_telemetry'][0]['container'], 'web')
        self.assertIn('timestamp', payload['container_telemetry'][0])
        self.assertIn('Error: disk full', payload['container_telemetry'][0]['log_excerpt'])
        self.assertEqual(payload['ci_pipeline_logs'][0]['job'], 'deploy')
        self.assertEqual(payload['deployment_changes'][0]['build'], 4)
        self.assertEqual(payload['metric_window_anomalies'][0]['metric'], 'disk_free')

    def test_retrieve_falls_back_to_postgres_when_chroma_is_down(self):
        from apps.knowledge.models import KnowledgeCollection, KnowledgeDocument
        from apps.mcp.diagnostics import retrieve
        collection = KnowledgeCollection.objects.create(name='runbooks', description='')
        KnowledgeDocument.objects.create(
            collection=collection, external_id='1', title='disk full',
            content='Free inode space before restarting postgres.',
        )
        hits = retrieve('inode')
        self.assertTrue(any('disk full' in hit for hit in hits))

    def test_retrieve_skips_distant_chroma_hits(self):
        from apps.mcp.diagnostics import retrieve

        class Collection:
            def query(self, **kwargs):
                return {
                    'ids': [['9']],
                    'documents': [['unrelated novel']],
                    'distances': [[1.9]],
                    'metadatas': [[{'title': 'novel'}]],
                }

        with patch('apps.mcp.diagnostics.get_chroma_collection', return_value=Collection()):
            self.assertEqual(retrieve('disk full'), [])

    def test_remediation_uses_the_django_tool_table(self):
        from apps.mcp.diagnostics import maybe_execute
        MCPTool.objects.create(
            name='web_nginx',
            description='fix',
            code='def main(name):\n    return "fixed " + name\n',
            status='active',
        )
        reply = json.dumps({
            'incident_detected': True,
            'error_scope': 'web_nginx',
            'diagnostic_report': 'down',
            'engine_status': 'ok',
        })
        meta = maybe_execute(reply, {'incident_family': 'container_runtime'})
        self.assertTrue(meta['agent_triggered'])
        self.assertEqual(meta['matched_tool'], 'web_nginx')
        self.assertIn('fixed web_nginx', meta['sandbox_output']['stdout'])

    def test_telemetry_is_empty_instead_of_crashing(self):
        result = self.client.get('/api/infrastructure/telemetry/')
        self.assertEqual(result.status_code, 200)
        payload = result.json()
        self.assertEqual(payload['containers'], [])
        self.assertEqual(payload['builds'], [])

    def test_telemetry_counts_stored_builds_and_containers(self):
        DockerMetric.objects.create(container_name='api', status='running', cpu_percent=1, mem_usage_mb=2)
        DockerMetric.objects.create(container_name='api', status='exited', cpu_percent=0, mem_usage_mb=0)
        JenkinsBuild.objects.create(job_name='deploy', build_number=4, result='FAILURE', duration_ms=65000)
        result = self.client.get('/api/infrastructure/telemetry/')
        payload = result.json()
        self.assertEqual(payload['metrics']['active_containers'], '0')
        self.assertEqual(payload['containers'][0][1], 'exited')
        self.assertEqual(payload['metrics']['pipelines_today'], '1')
        self.assertEqual(payload['builds'][0][2], 'FAILURE')


class ToolExecutorTests(TestCase):
    def test_decorator_style_tool_is_called(self):
        code = '@mcp.tool()\ndef restart_container(name: str) -> str:\n    return f"restarted {name}"\n'
        result = MCPSandboxExecutor.execute_tool_safe(code, {'TARGET_RESOURCE': 'web'})
        self.assertTrue(result['success'], result)
        self.assertIn('restarted web', result['stdout'])

    def test_child_process_does_not_receive_django_secrets(self):
        os.environ['DJANGO_SECRET_KEY'] = 'super-secret-value'
        code = 'def main():\n    import os\n    return os.environ.get("DJANGO_SECRET_KEY")\n'
        result = MCPSandboxExecutor.execute_tool_safe(code, {'TARGET_RESOURCE': ''})
        self.assertTrue(result['success'], result)
        self.assertNotIn('super-secret-value', result['stdout'])

    def test_top_level_script_still_runs(self):
        code = 'import os\nprint("saw " + os.environ.get("TARGET_RESOURCE", ""))\n'
        result = MCPSandboxExecutor.execute_tool_safe(code, {'TARGET_RESOURCE': 'queue'})
        self.assertTrue(result['success'], result)
        self.assertIn('saw queue', result['stdout'])


class MetricClassificationTests(TestCase):
    def test_cpu_counter_is_not_treated_as_a_percentage(self):
        status, kind = classify_metric('node_cpu_seconds_total', 180000)
        self.assertEqual(status, 'NORMAL')
        self.assertEqual(kind, 'generic')

    def test_low_available_memory_is_critical(self):
        status, kind = classify_metric('node_memory_MemAvailable_bytes', 128 * 1024 * 1024)
        self.assertEqual(status, 'CRITICAL_LOW_MEMORY')
        self.assertEqual(kind, 'host_memory_bounds')
