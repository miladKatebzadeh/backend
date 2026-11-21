import json
import logging
import os
from urllib.parse import quote

import requests
from django.utils import timezone

from apps.mcp.models import get_setting, set_setting

logger = logging.getLogger(__name__)

DEFAULT_WATCHED_METRICS = (
    'node_memory_MemAvailable_bytes',
    'node_filesystem_avail_bytes',
    'node_network_receive_bytes_total',
)


def classify_metric(query: str, value: float) -> tuple[str, str]:
    name = query or ''
    lowered = name.lower()
    if 'memavailable' in lowered:
        if value < 1024 ** 3:
            return 'CRITICAL_LOW_MEMORY', 'host_memory_bounds'
        return 'NORMAL', 'host_memory_bounds'
    if 'filesystem' in lowered and any(token in lowered for token in ('avail', 'free')):
        if value < 5 * 1024 ** 3:
            return 'CRITICAL_DISK_FULL', 'host_disk_space'
        return 'NORMAL', 'host_disk_space'
    if any(token in lowered for token in ('cpu_percent', 'cpu_usage_percent', 'utilization')) and 0 <= value <= 100:
        if value > 85:
            return 'CRITICAL_SPIKE', 'host_cpu_utilization'
        return 'NORMAL', 'host_cpu_utilization'
    return 'NORMAL', 'generic'


def _docker_api():
    host = get_setting('docker_host', os.getenv('DOCKER_API_URL', '')).strip().rstrip('/')
    if not host:
        return ''
    if not host.startswith(('http://', 'https://')):
        logger.error('Docker host must be an http(s) API address, not %s', host.split(':', 1)[0])
        return ''
    return host


def _decode_docker_logs(raw: bytes) -> str:
    if len(raw) >= 8 and raw[0] in (1, 2) and raw[1:4] == b'\x00\x00\x00':
        parts = []
        index = 0
        while index + 8 <= len(raw):
            size = int.from_bytes(raw[index + 4:index + 8], 'big')
            index += 8
            parts.append(raw[index:index + size])
            index += size
        raw = b''.join(parts)
    return raw.decode('utf-8', errors='ignore').strip()


def _cpu_percent(stats: dict) -> float:
    cpu_stats = stats.get('cpu_stats') or {}
    precpu_stats = stats.get('precpu_stats') or {}
    cpu_delta = (cpu_stats.get('cpu_usage') or {}).get('total_usage', 0) - (precpu_stats.get('cpu_usage') or {}).get('total_usage', 0)
    system_delta = cpu_stats.get('system_cpu_usage', 0) - precpu_stats.get('system_cpu_usage', 0)
    online_cpus = cpu_stats.get('online_cpus') or 1
    if system_delta > 0 and cpu_delta > 0:
        return (cpu_delta / system_delta) * online_cpus * 100.0
    return 0.0


class StandaloneCollectorDaemon:
    @staticmethod
    def scrape_interval() -> int:
        try:
            interval = int(get_setting('scrape_interval', os.getenv('SCRAPE_INTERVAL', '15')))
        except (TypeError, ValueError):
            interval = 15
        return max(5, min(interval, 3600))

    @classmethod
    def collect_docker_data(cls):
        from apps.collector.models import DockerMetric
        base = _docker_api()
        if not base:
            return
        try:
            listed = requests.get(f'{base}/containers/json', params={'all': 1}, timeout=5)
            listed.raise_for_status()
            containers = listed.json()
        except Exception as exc:
            logger.error('Collector could not reach Docker API at %s: %s', base, exc)
            return
        if not isinstance(containers, list):
            logger.error('Docker API returned an unexpected container list')
            return

        for container in containers:
            container_id = str(container.get('Id') or '')
            names = container.get('Names') or []
            name = str(names[0]).lstrip('/') if names else container_id[:12]
            if not name:
                continue
            status = str(container.get('State') or 'unknown')
            restart_count = 0
            oom = False
            try:
                inspected = requests.get(f'{base}/containers/{container_id}/json', timeout=5)
                inspected.raise_for_status()
                details = inspected.json()
                restart_count = int(details.get('RestartCount') or 0)
                state = details.get('State') or {}
                status = str(state.get('Status') or status)
                oom = bool(state.get('OOMKilled'))
            except Exception:
                logger.exception('Docker inspect failed for %s', name)

            try:
                logs = requests.get(
                    f'{base}/containers/{container_id}/logs',
                    params={'stdout': 1, 'stderr': 1, 'tail': 20},
                    timeout=5,
                )
                logs.raise_for_status()
                container_logs = _decode_docker_logs(logs.content)
            except Exception as exc:
                container_logs = f'Unable to read logs ({exc.__class__.__name__})'

            cpu_percent = 0.0
            mem_usage_mb = 0.0
            if status == 'running':
                try:
                    stats_response = requests.get(
                        f'{base}/containers/{container_id}/stats',
                        params={'stream': 'false'},
                        timeout=5,
                    )
                    stats_response.raise_for_status()
                    stats = stats_response.json()
                    cpu_percent = _cpu_percent(stats)
                    mem_usage_mb = (stats.get('memory_stats') or {}).get('usage', 0) / (1024 ** 2)
                except Exception:
                    logger.exception('Docker stats failed for %s', name)

            payload = {
                'status': status,
                'cpu_percent': cpu_percent,
                'mem_usage_mb': mem_usage_mb,
                'oom_killed': oom,
                'raw_stats': {'cpu_percent': cpu_percent, 'mem_usage_mb': mem_usage_mb, 'restart_count': restart_count},
                'container_logs': container_logs,
                'restart_count': restart_count,
                'timestamp': timezone.now(),
            }
            current = DockerMetric.objects.filter(container_name=name).order_by('-id').first()
            if current is None:
                DockerMetric.objects.create(container_name=name, **payload)
                continue
            if current.status != status:
                current.remediation_attempted = False
                current.resolved = False
                current.last_attempt_at = None
            for field, value in payload.items():
                setattr(current, field, value)
            current.save()

    @classmethod
    def collect_jenkins_data(cls):
        from apps.collector.models import JenkinsBuild
        jenkins_url = get_setting('jenkins_url', os.getenv('JENKINS_URL', 'http://127.0.0.1:8080')).rstrip('/')
        jenkins_user = get_setting('jenkins_user', os.getenv('JENKINS_USER', ''))
        jenkins_token = get_setting('jenkins_token', os.getenv('JENKINS_TOKEN', ''))
        auth = (jenkins_user, jenkins_token) if jenkins_user and jenkins_token else None
        try:
            url = f'{jenkins_url}/api/json?tree=jobs[name,lastBuild[number,result,duration,estimatedDuration]]'
            job_response = requests.get(url, auth=auth, timeout=5)
            job_response.raise_for_status()
            jobs = job_response.json().get('jobs', [])
        except Exception as exc:
            logger.error('Jenkins collection failed: %s', exc)
            return

        for job in jobs:
            last_build = job.get('lastBuild') or None
            if not last_build:
                continue
            job_name = job.get('name') or ''
            build_number = last_build.get('number')
            if not job_name or build_number is None:
                continue
            result = last_build.get('result') or 'BUILDING'
            duration = last_build.get('duration') or 0
            estimated = last_build.get('estimatedDuration') or 0
            console_output = ''
            if result in ('FAILURE', 'UNSTABLE', 'ABORTED'):
                try:
                    log_url = f'{jenkins_url}/job/{quote(job_name)}/{build_number}/consoleText'
                    log_response = requests.get(log_url, auth=auth, timeout=5)
                    if log_response.status_code == 200:
                        console_output = '\n'.join(log_response.text.splitlines()[-100:])
                except Exception as exc:
                    console_output = f'Console read failed ({exc.__class__.__name__})'
            payload = {
                'result': result,
                'duration_ms': duration,
                'estimated_duration_ms': estimated,
                'raw_build_info': last_build,
                'console_output': console_output,
                'updated_at': timezone.now(),
            }
            current = JenkinsBuild.objects.filter(job_name=job_name, build_number=build_number).first()
            if current is None:
                JenkinsBuild.objects.create(job_name=job_name, build_number=build_number, **payload)
                continue
            if current.result != result:
                current.remediation_attempted = False
                current.last_attempt_at = None
            for field, value in payload.items():
                setattr(current, field, value)
            current.save()

    @classmethod
    def collect_prometheus_data(cls):
        from apps.collector.models import PrometheusAlert
        prom_url = get_setting('prometheus_url', os.getenv('PROMETHEUS_URL', 'http://127.0.0.1:9090')).rstrip('/')
        if not prom_url:
            return
        try:
            catalog_response = requests.get(f'{prom_url}/api/v1/label/__name__/values', timeout=5)
            catalog_response.raise_for_status()
            names = catalog_response.json().get('data') or []
            if isinstance(names, list):
                set_setting('prometheus_catalog', json.dumps(names[:5000]))
        except Exception as exc:
            logger.error('Prometheus catalog failed: %s', exc)
            names = []

        try:
            watched = json.loads(get_setting('watched_metrics', '[]') or '[]')
        except json.JSONDecodeError:
            watched = []
        if not isinstance(watched, list) or not watched:
            watched = list(DEFAULT_WATCHED_METRICS)
        queries = []
        for name in watched:
            if isinstance(name, str) and name not in queries:
                queries.append(name)
            if len(queries) >= 50:
                break

        for query in queries:
            try:
                metric_response = requests.get(f'{prom_url}/api/v1/query', params={'query': query}, timeout=5)
                metric_response.raise_for_status()
                results = metric_response.json().get('data', {}).get('result', [])
            except Exception:
                continue
            if not results:
                continue
            sample = results[0]
            value_data = sample.get('value') or []
            if len(value_data) < 2:
                continue
            try:
                value = float(value_data[1])
            except (TypeError, ValueError):
                continue
            alert_status, metric_type = classify_metric(query, value)
            labels = sample.get('metric') or {}
            current = PrometheusAlert.objects.filter(metric_name=query).order_by('-id').first()
            payload = {
                'value': value,
                'labels': labels,
                'alert_status': alert_status,
                'metric_type': metric_type,
                'updated_at': timezone.now(),
            }
            if current is None:
                PrometheusAlert.objects.create(metric_name=query, **payload)
            else:
                for field, field_value in payload.items():
                    setattr(current, field, field_value)
                current.save()
                PrometheusAlert.objects.filter(metric_name=query).exclude(pk=current.pk).delete()

    @classmethod
    def run_continuous_loop(cls):
        import time
        from apps.mcp.diagnostics import monitor_incident_daemon

        logger.info('Infrastructure collector loop started')
        while True:
            try:
                cls.collect_docker_data()
                cls.collect_jenkins_data()
                cls.collect_prometheus_data()
                monitor_incident_daemon()
            except Exception:
                logger.exception('Collector loop fault')
            time.sleep(cls.scrape_interval())
