import json
import logging
import os
from urllib.parse import quote

import requests
from django.utils import timezone

from apps.mcp.models import get_setting, set_setting
from apps.mcp.jenkins_evidence import analyze_jenkins_console, select_jenkins_console

logger = logging.getLogger(__name__)

DEFAULT_WATCHED_METRICS = (
    'node_memory_MemAvailable_bytes',
    'node_filesystem_avail_bytes',
    'node_network_receive_bytes_total',
)


def classify_metric(query: str, value: float) -> tuple[str, str]:
    name = query or ''
    lowered = name.lower()
    limits = _threshold_limits()
    if 'memavailable' in lowered:
        if value < limits['memory_min_bytes']:
            return 'CRITICAL_LOW_MEMORY', 'host_memory_bounds'
        return 'NORMAL', 'host_memory_bounds'
    if 'filesystem' in lowered and any(token in lowered for token in ('avail', 'free')):
        if value < limits['disk_min_bytes']:
            return 'CRITICAL_DISK_FULL', 'host_disk_space'
        return 'NORMAL', 'host_disk_space'
    if any(token in lowered for token in ('cpu_percent', 'cpu_usage_percent', 'utilization')) and 0 <= value <= 100:
        if value > limits['cpu_max_percent']:
            return 'CRITICAL_SPIKE', 'host_cpu_utilization'
        return 'NORMAL', 'host_cpu_utilization'
    return 'NORMAL', 'generic'


def _bounded_int(key, default, low, high):
    try:
        value = int(get_setting(key, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(low, min(value, high))


def _threshold_limits():
    return {
        'memory_min_bytes': _bounded_int('memory_min_mb', 1024, 64, 1_048_576) * 1024 * 1024,
        'disk_min_bytes': _bounded_int('disk_min_gb', 5, 1, 100_000) * (1024 ** 3),
        'cpu_max_percent': _bounded_int('cpu_max_percent', 85, 1, 100),
    }


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


def container_state(name: str):
    """Live Docker state for one container. None means the API could not be checked."""
    base = _docker_api()
    wanted = str(name or '').strip().lstrip('/')
    if not base or not wanted:
        return None
    try:
        listed = requests.get(f'{base}/containers/json', params={'all': 1}, timeout=5)
        listed.raise_for_status()
        containers = listed.json()
    except Exception:
        logger.exception('Could not confirm container %s', wanted)
        return None
    if not isinstance(containers, list):
        return None
    for item in containers:
        names = [str(entry).lstrip('/') for entry in (item.get('Names') or [])]
        ident = str(item.get('Id') or '')
        if wanted in names or ident.startswith(wanted):
            return str(item.get('State') or 'unknown')
    return 'missing'


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
            details = {}
            state = {}
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

            try:
                exit_code = int(state['ExitCode']) if state.get('ExitCode') is not None else None
            except (TypeError, ValueError):
                exit_code = None
            payload = {
                'status': status,
                'cpu_percent': cpu_percent,
                'mem_usage_mb': mem_usage_mb,
                'oom_killed': oom,
                'raw_stats': {
                    'cpu_percent': cpu_percent,
                    'mem_usage_mb': mem_usage_mb,
                    'restart_count': restart_count,
                    'exit_code': exit_code,
                    'state_error': str(state.get('Error') or '')[:240],
                    'finished_at': str(state.get('FinishedAt') or '')[:80],
                    'image': str((details.get('Config') or {}).get('Image') or container.get('Image') or '')[:200],
                },
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
            build_info = dict(last_build)
            if result in ('FAILURE', 'UNSTABLE', 'ABORTED'):
                try:
                    log_url = f'{jenkins_url}/job/{quote(job_name)}/{build_number}/consoleText'
                    log_response = requests.get(log_url, auth=auth, timeout=5)
                    if log_response.status_code == 200:
                        full_console = log_response.text
                        build_info['failure_analysis'] = analyze_jenkins_console(full_console)
                        console_output = select_jenkins_console(full_console)
                    else:
                        logger.warning(
                            'Jenkins console unavailable for %s build %s (HTTP %s)',
                            job_name, build_number, log_response.status_code,
                        )
                except Exception as exc:
                    logger.warning(
                        'Jenkins console read failed for %s build %s (%s)',
                        job_name, build_number, exc.__class__.__name__,
                    )
            payload = {
                'result': result,
                'duration_ms': duration,
                'estimated_duration_ms': estimated,
                'raw_build_info': build_info,
                'console_output': console_output,
                'updated_at': timezone.now(),
            }
            current = JenkinsBuild.objects.filter(job_name=job_name, build_number=build_number).first()
            if current is None:
                JenkinsBuild.objects.create(job_name=job_name, build_number=build_number, **payload)
                continue
            if (
                result in ('FAILURE', 'UNSTABLE', 'ABORTED')
                and current.result == result
                and not console_output
                and current.console_output
            ):
                # A transient Jenkins console fetch failure must not erase the
                # previously captured evidence for this exact Build.
                payload['console_output'] = current.console_output
                existing = current.raw_build_info if isinstance(current.raw_build_info, dict) else {}
                if isinstance(existing.get('failure_analysis'), dict):
                    payload['raw_build_info']['failure_analysis'] = existing['failure_analysis']
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
        if prom_url:
            cls._collect_prometheus_queries(prom_url)
        cls._collect_firing_alerts(prom_url)

    @classmethod
    def _collect_prometheus_queries(cls, prom_url):
        from apps.collector.models import PrometheusAlert
        try:
            catalog_response = requests.get(f'{prom_url}/api/v1/label/__name__/values', timeout=5)
            catalog_response.raise_for_status()
            names = catalog_response.json().get('data') or []
            if isinstance(names, list):
                set_setting('prometheus_catalog', json.dumps(names[:5000]))
        except Exception as exc:
            logger.error('Prometheus catalog failed: %s', exc)

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
    def _collect_firing_alerts(cls, prom_url):
        from apps.collector.models import PrometheusAlert
        found = []
        successful_sources = set()
        if prom_url:
            try:
                response = requests.get(f'{prom_url}/api/v1/alerts', timeout=5)
                response.raise_for_status()
                alerts = (response.json().get('data') or {}).get('alerts') or []
                if not isinstance(alerts, list):
                    raise ValueError('Prometheus returned an invalid alerts payload')
                parsed_alerts = []
                for item in alerts:
                    state = str(item.get('state') or '').lower()
                    if state not in ('firing', 'pending'):
                        continue
                    labels = item.get('labels') or {}
                    name = str(labels.get('alertname') or 'prometheus')
                    try:
                        value = float(item.get('value') or 0)
                    except (TypeError, ValueError):
                        value = 0
                    parsed_alerts.append((f'alert:{name}', value, labels, 'FIRING' if state == 'firing' else 'PENDING', 'prometheus_alert'))
                found.extend(parsed_alerts)
                successful_sources.add('prometheus_alert')
            except Exception as exc:
                logger.error('Prometheus alerts failed: %s', exc)

        alertmanager = get_setting('alertmanager_url', os.getenv('ALERTMANAGER_URL', '')).strip().rstrip('/')
        if alertmanager:
            try:
                response = requests.get(f'{alertmanager}/api/v2/alerts', params={'active': 'true'}, timeout=5)
                response.raise_for_status()
                body = response.json()
                if not isinstance(body, list):
                    raise ValueError('Alertmanager returned an invalid alerts payload')
                parsed_alerts = []
                for item in body:
                    labels = item.get('labels') or {}
                    name = str(labels.get('alertname') or 'alertmanager')
                    state = str((item.get('status') or {}).get('state') or 'active').lower()
                    status = 'FIRING' if state in ('active', 'firing') else 'PENDING'
                    parsed_alerts.append((f'alert:{name}', 1, labels, status, 'alertmanager'))
                found.extend(parsed_alerts)
                successful_sources.add('alertmanager')
            except Exception as exc:
                logger.error('Alertmanager collection failed: %s', exc)

        kept_by_source = {source: set() for source in successful_sources}
        for name, value, labels, alert_status, metric_type in found:
            current = PrometheusAlert.objects.filter(metric_name=name, metric_type=metric_type).order_by('-id').first()
            payload = {
                'value': value,
                'labels': labels,
                'alert_status': alert_status,
                'metric_type': metric_type,
                'updated_at': timezone.now(),
            }
            if current is None:
                current = PrometheusAlert.objects.create(metric_name=name, **payload)
            else:
                for field, field_value in payload.items():
                    setattr(current, field, field_value)
                current.save()
            if metric_type in kept_by_source:
                kept_by_source[metric_type].add(current.pk)

        # An alert is cleared only after its own provider successfully confirms
        # that it is no longer active. Provider outages must not resolve alerts.
        now = timezone.now()
        for source, kept_ids in kept_by_source.items():
            stale = PrometheusAlert.objects.filter(metric_type=source).exclude(pk__in=kept_ids)
            stale.update(alert_status='NORMAL', updated_at=now)

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
                try:
                    from apps.incidents.services import sync_incidents_from_telemetry
                    sync_incidents_from_telemetry()
                except Exception:
                    logger.exception('Incident synchronization failed')
                monitor_incident_daemon()
            except Exception:
                logger.exception('Collector loop fault')
            time.sleep(cls.scrape_interval())
