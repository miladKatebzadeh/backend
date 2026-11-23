import hashlib
import json
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from apps.collector.models import DockerMetric, JenkinsBuild, PrometheusAlert
from apps.incidents.models import Incident, IncidentEvent
from apps.mcp.models import get_setting


def incident_fingerprint(source: str, resource: str, condition: str) -> str:
    """Return a stable, opaque identifier for one source/resource/condition tuple."""
    parts = (
        str(source or '').strip().lower(),
        str(resource or '').strip().casefold(),
        str(condition or '').strip().lower(),
    )
    raw = json.dumps(parts, ensure_ascii=False, separators=(',', ':'))
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def record_incident(
    *,
    source: str,
    resource: str,
    condition: str,
    title: str,
    description: str = '',
    severity: str = Incident.Severity.MEDIUM,
    metadata: dict | None = None,
    occurrence_key: str | None = None,
    observed_at=None,
) -> Incident:
    """Create or refresh an incident without creating a row on every scrape."""
    observed_at = observed_at or timezone.now()
    fingerprint = incident_fingerprint(source, resource, condition)
    metadata = metadata if isinstance(metadata, dict) else {}
    occurrence_key = str(occurrence_key or '')

    defaults = {
        'source': source,
        'resource': str(resource)[:255],
        'title': str(title)[:240],
        'description': str(description or ''),
        'severity': severity,
        'status': Incident.Status.OPEN,
        'first_seen': observed_at,
        'last_seen': observed_at,
        'occurrence_count': 1,
        'last_occurrence_key': occurrence_key,
        'metadata': metadata,
    }

    with transaction.atomic():
        incident, created = Incident.objects.select_for_update().get_or_create(
            fingerprint=fingerprint,
            defaults=defaults,
        )
        if created:
            IncidentEvent.objects.create(
                incident=incident,
                event_type=IncidentEvent.EventType.CREATED,
                message=incident.title,
                payload={'source': source, 'resource': resource, **metadata},
            )
            return incident

        was_resolved = incident.status == Incident.Status.RESOLVED
        changed_occurrence = bool(occurrence_key and occurrence_key != incident.last_occurrence_key)
        incident.last_seen = observed_at
        incident.title = str(title)[:240]
        incident.description = str(description or '')
        incident.severity = severity
        incident.metadata = {**(incident.metadata or {}), **metadata}

        if was_resolved:
            incident.status = Incident.Status.OPEN
            incident.resolved_at = None
            incident.occurrence_count += 1
            incident.last_occurrence_key = occurrence_key
            event_type = IncidentEvent.EventType.REOPENED
            event_message = f'Incident reopened: {incident.title}'
            event_payload = {'source': source, 'resource': resource, **metadata}
        elif changed_occurrence:
            incident.occurrence_count += 1
            incident.last_occurrence_key = occurrence_key
            event_type = IncidentEvent.EventType.OCCURRENCE
            event_message = f'New occurrence detected: {incident.title}'
            event_payload = {'occurrence_key': occurrence_key, **metadata}
        else:
            event_type = None

        incident.save()
        if event_type:
            IncidentEvent.objects.create(
                incident=incident,
                event_type=event_type,
                message=event_message,
                payload=event_payload,
            )
        return incident


def resolve_incident(
    *,
    source: str,
    resource: str,
    condition: str,
    message: str = 'The signal returned to a normal state.',
    metadata: dict | None = None,
    observed_at=None,
) -> bool:
    """Resolve an open incident only when its source explicitly reports recovery."""
    fingerprint = incident_fingerprint(source, resource, condition)
    observed_at = observed_at or timezone.now()
    with transaction.atomic():
        incident = Incident.objects.select_for_update().filter(
            fingerprint=fingerprint,
        ).exclude(status=Incident.Status.RESOLVED).first()
        if incident is None:
            return False
        incident.status = Incident.Status.RESOLVED
        incident.resolved_at = observed_at
        incident.last_seen = observed_at
        if isinstance(metadata, dict):
            incident.metadata = {**(incident.metadata or {}), **metadata}
        incident.save(update_fields=[
            'status', 'resolved_at', 'last_seen', 'metadata', 'updated_at',
        ])
        IncidentEvent.objects.create(
            incident=incident,
            event_type=IncidentEvent.EventType.RESOLVED,
            message=message,
            payload=metadata or {},
        )
        return True


def _latest_by(queryset, key_func, ordering):
    latest = {}
    for row in queryset.order_by(*ordering):
        key = key_func(row)
        latest.setdefault(key, row)
    return latest.values()


def _excerpt(value, limit=2000):
    return str(value or '')[-limit:]


def _telemetry_cutoff():
    try:
        interval = int(get_setting('scrape_interval', '15'))
    except (TypeError, ValueError):
        interval = 15
    interval = max(5, min(interval, 3600))
    return timezone.now() - timedelta(seconds=max(60, interval * 3))


def sync_incidents_from_telemetry() -> dict:
    """
    Synchronize persisted source signals into the incident ledger.

    Docker states 'created', 'restarting', and 'paused' are deliberately not
    promoted automatically. 'exited' is a medium-severity signal unless
    restart/OOM evidence raises it; 'dead' and OOM-killed are critical.
    """
    summary = {'active': 0, 'resolved': 0}
    cutoff = _telemetry_cutoff()

    # Ignore old samples. A collector outage must not make stale data look
    # current or automatically resolve an incident.
    docker_rows = _latest_by(
        DockerMetric.objects.filter(timestamp__gte=cutoff),
        lambda row: row.container_name,
        ('-timestamp', '-id'),
    )
    for row in docker_rows:
        resource = row.container_name
        condition = 'container_not_running'
        state = str(row.status or '').strip().lower()
        if state == 'running':
            if resolve_incident(
                source=Incident.Source.DOCKER,
                resource=resource,
                condition=condition,
                message=f'Container {resource} is running again.',
                metadata={'container_status': state},
            ):
                summary['resolved'] += 1
            continue
        if state not in ('exited', 'dead'):
            continue

        if row.oom_killed or state == 'dead':
            severity = Incident.Severity.CRITICAL
        elif row.restart_count:
            severity = Incident.Severity.HIGH
        else:
            severity = Incident.Severity.MEDIUM
        record_incident(
            source=Incident.Source.DOCKER,
            resource=resource,
            condition=condition,
            title=f'Container stopped: {resource}',
            description=f'Docker reports container state "{state}".',
            severity=severity,
            metadata={
                'container_status': state,
                'restart_count': row.restart_count,
                'oom_killed': row.oom_killed,
                'exit_code': (row.raw_stats or {}).get('exit_code') if isinstance(row.raw_stats, dict) else None,
                'state_error': str((row.raw_stats or {}).get('state_error') or '')[:240] if isinstance(row.raw_stats, dict) else '',
                'log_excerpt': _excerpt(row.container_logs),
            },
        )
        summary['active'] += 1

    jenkins_rows = _latest_by(
        JenkinsBuild.objects.filter(updated_at__gte=cutoff),
        lambda row: row.job_name,
        ('-build_number', '-updated_at', '-id'),
    )
    for row in jenkins_rows:
        resource = row.job_name
        condition = 'job_failure'
        result = str(row.result or '').strip().upper()
        if result == 'SUCCESS':
            if resolve_incident(
                source=Incident.Source.JENKINS,
                resource=resource,
                condition=condition,
                message=f'Jenkins job {resource} completed successfully.',
                metadata={'build_number': row.build_number, 'build_result': result},
            ):
                summary['resolved'] += 1
            continue
        if result not in ('FAILURE', 'UNSTABLE', 'ABORTED'):
            continue

        severity = {
            'FAILURE': Incident.Severity.HIGH,
            'UNSTABLE': Incident.Severity.MEDIUM,
            'ABORTED': Incident.Severity.LOW,
        }[result]
        record_incident(
            source=Incident.Source.JENKINS,
            resource=resource,
            condition=condition,
            title=f'Jenkins build {result.lower()}: {resource}',
            description=f'Build #{row.build_number} finished with result {result}.',
            severity=severity,
            occurrence_key=str(row.build_number),
            metadata={
                'build_number': row.build_number,
                'build_result': result,
                'failure_analysis': (
                    (row.raw_build_info or {}).get('failure_analysis')
                    if isinstance(row.raw_build_info, dict) else None
                ),
                'console_excerpt': _excerpt(row.console_output),
            },
        )
        summary['active'] += 1

    prometheus_rows = _latest_by(
        PrometheusAlert.objects.filter(updated_at__gte=cutoff),
        lambda row: (row.metric_type, row.metric_name),
        ('-updated_at', '-id'),
    )
    for row in prometheus_rows:
        source = (
            Incident.Source.ALERTMANAGER
            if row.metric_type == 'alertmanager'
            else Incident.Source.PROMETHEUS
        )
        resource = row.metric_name
        condition = f'{row.metric_type}:{row.metric_name}'
        alert_status = str(row.alert_status or 'NORMAL').strip().upper()
        if alert_status == 'NORMAL':
            if resolve_incident(
                source=source,
                resource=resource,
                condition=condition,
                message=f'Signal {resource} returned to NORMAL.',
                metadata={'alert_status': alert_status, 'value': row.value},
            ):
                summary['resolved'] += 1
            continue

        severity = (
            Incident.Severity.CRITICAL
            if alert_status.startswith('CRITICAL')
            else Incident.Severity.HIGH
            if alert_status == 'FIRING'
            else Incident.Severity.MEDIUM
        )
        record_incident(
            source=source,
            resource=resource,
            condition=condition,
            title=f'Infrastructure alert: {resource}',
            description=f'{resource} is reporting status {alert_status}.',
            severity=severity,
            metadata={
                'alert_status': alert_status,
                'metric_type': row.metric_type,
                'value': row.value,
                'labels': row.labels or {},
            },
        )
        summary['active'] += 1

    return summary
