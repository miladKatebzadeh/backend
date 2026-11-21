from unittest.mock import patch

from django.test import TestCase

from apps.collector.models import DockerMetric
from apps.collector.tasks import StandaloneCollectorDaemon
from apps.mcp.models import set_setting


class DockerApiCollectorTests(TestCase):
    def test_collects_a_container_from_the_engine_api(self):
        set_setting('docker_host', 'http://10.0.0.4:2375')
        header = b'\x01\x00\x00\x00\x00\x00\x00\x05hello'

        class Response:
            def __init__(self, payload=None, content=b''):
                self._payload = payload if payload is not None else {}
                self.content = content

            def json(self):
                return self._payload

            def raise_for_status(self):
                return None

        def fake_get(url, params=None, timeout=None):
            if url.endswith('/containers/json'):
                return Response([{'Id': 'abc', 'Names': ['/color-dot'], 'State': 'running'}])
            if url.endswith('/abc/json'):
                return Response({'RestartCount': 2, 'State': {'Status': 'running', 'OOMKilled': False}})
            if url.endswith('/abc/logs'):
                return Response(content=header)
            if url.endswith('/abc/stats'):
                return Response({
                    'cpu_stats': {'cpu_usage': {'total_usage': 200}, 'system_cpu_usage': 1000, 'online_cpus': 2},
                    'precpu_stats': {'cpu_usage': {'total_usage': 100}, 'system_cpu_usage': 500},
                    'memory_stats': {'usage': 50 * 1024 * 1024},
                })
            raise AssertionError(url)

        with patch('apps.collector.tasks.requests.get', side_effect=fake_get):
            StandaloneCollectorDaemon.collect_docker_data()

        row = DockerMetric.objects.get(container_name='color-dot')
        self.assertEqual(row.status, 'running')
        self.assertEqual(row.restart_count, 2)
        self.assertEqual(row.container_logs, 'hello')
        self.assertAlmostEqual(row.cpu_percent, 40.0)
        self.assertAlmostEqual(row.mem_usage_mb, 50.0)

    def test_skips_collection_when_no_docker_api_is_configured(self):
        with patch('apps.collector.tasks.requests.get') as get:
            StandaloneCollectorDaemon.collect_docker_data()
        get.assert_not_called()
        self.assertEqual(DockerMetric.objects.count(), 0)

    def test_alertmanager_and_prometheus_alerts_are_stored(self):
        from apps.collector.models import PrometheusAlert
        from apps.mcp.models import set_setting
        set_setting('alertmanager_url', 'http://10.0.0.8:9093')

        class Response:
            def __init__(self, payload):
                self._payload = payload

            def json(self):
                return self._payload

            def raise_for_status(self):
                return None

        def fake_get(url, params=None, timeout=None):
            if url.endswith('/api/v2/alerts'):
                return Response([{'labels': {'alertname': 'DiskLow'}, 'status': {'state': 'active'}}])
            if url.endswith('/api/v1/alerts'):
                return Response({'data': {'alerts': [{'labels': {'alertname': 'HighCPU'}, 'state': 'firing', 'value': '91'}]}})
            if url.endswith('/api/v1/label/__name__/values'):
                return Response({'data': []})
            if '/api/v1/query' in url:
                return Response({'data': {'result': []}})
            raise AssertionError(url)

        with patch('apps.collector.tasks.requests.get', side_effect=fake_get):
            StandaloneCollectorDaemon.collect_prometheus_data()
        disk = PrometheusAlert.objects.get(metric_name='alert:DiskLow')
        cpu = PrometheusAlert.objects.get(metric_name='alert:HighCPU')
        self.assertEqual(disk.metric_type, 'alertmanager')
        self.assertEqual(disk.alert_status, 'FIRING')
        self.assertEqual(cpu.metric_type, 'prometheus_alert')
        self.assertEqual(cpu.alert_status, 'FIRING')
