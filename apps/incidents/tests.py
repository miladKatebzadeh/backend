from django.test import TestCase
from django.utils import timezone

from apps.collector.models import DockerMetric, JenkinsBuild, PrometheusAlert
from apps.incidents.models import Incident, IncidentEvent
from apps.incidents.services import (
    incident_fingerprint,
    record_incident,
    resolve_incident,
    sync_incidents_from_telemetry,
)


class IncidentLifecycleTests(TestCase):
    def test_repeated_scrapes_update_one_incident_without_event_spam(self):
        first = record_incident(
            source=Incident.Source.DOCKER,
            resource='api',
            condition='container_not_running',
            title='Container stopped: api',
            severity=Incident.Severity.MEDIUM,
            metadata={'container_status': 'exited'},
        )
        second = record_incident(
            source=Incident.Source.DOCKER,
            resource='api',
            condition='container_not_running',
            title='Container stopped: api',
            severity=Incident.Severity.MEDIUM,
            metadata={'container_status': 'exited'},
        )

        self.assertEqual(first.pk, second.pk)
        self.assertEqual(Incident.objects.count(), 1)
        self.assertEqual(second.occurrence_count, 1)
        self.assertEqual(second.events.count(), 1)
        self.assertEqual(second.fingerprint, incident_fingerprint(
            Incident.Source.DOCKER, 'api', 'container_not_running',
        ))

    def test_new_jenkins_build_is_a_distinct_occurrence(self):
        incident = record_incident(
            source=Incident.Source.JENKINS,
            resource='deploy',
            condition='job_failure',
            title='Jenkins build failed: deploy',
            occurrence_key='41',
        )
        incident = record_incident(
            source=Incident.Source.JENKINS,
            resource='deploy',
            condition='job_failure',
            title='Jenkins build failed: deploy',
            occurrence_key='42',
        )

        self.assertEqual(incident.occurrence_count, 2)
        self.assertEqual(
            list(incident.events.values_list('event_type', flat=True)),
            ['created', 'occurrence'],
        )

    def test_resolved_incident_reopens_when_the_signal_returns(self):
        incident = record_incident(
            source=Incident.Source.DOCKER,
            resource='worker',
            condition='container_not_running',
            title='Container stopped: worker',
        )
        resolved = resolve_incident(
            source=Incident.Source.DOCKER,
            resource='worker',
            condition='container_not_running',
            message='Container recovered.',
        )
        reopened = record_incident(
            source=Incident.Source.DOCKER,
            resource='worker',
            condition='container_not_running',
            title='Container stopped: worker',
        )

        self.assertTrue(resolved)
        self.assertEqual(reopened.pk, incident.pk)
        self.assertEqual(reopened.status, Incident.Status.OPEN)
        self.assertIsNone(reopened.resolved_at)
        self.assertEqual(reopened.occurrence_count, 2)
        self.assertEqual(
            list(reopened.events.values_list('event_type', flat=True)),
            ['created', 'resolved', 'reopened'],
        )

    def test_docker_terminal_state_is_recorded_and_running_resolves_it(self):
        DockerMetric.objects.create(
            container_name='api',
            status='exited',
            restart_count=3,
            container_logs='process exited',
            timestamp=timezone.now(),
        )
        sync_incidents_from_telemetry()
        incident = Incident.objects.get(source=Incident.Source.DOCKER, resource='api')
        self.assertEqual(incident.severity, Incident.Severity.HIGH)
        self.assertEqual(incident.metadata['restart_count'], 3)

        DockerMetric.objects.create(container_name='api', status='running', timestamp=timezone.now())
        sync_incidents_from_telemetry()
        incident.refresh_from_db()
        self.assertEqual(incident.status, Incident.Status.RESOLVED)
        self.assertEqual(incident.events.count(), 2)

    def test_expected_transitional_and_paused_docker_states_are_not_promoted(self):
        now = timezone.now()
        DockerMetric.objects.create(container_name='one-off', status='exited', restart_count=0, timestamp=now)
        DockerMetric.objects.create(container_name='paused', status='paused', timestamp=now)
        DockerMetric.objects.create(container_name='starting', status='restarting', timestamp=now)
        sync_incidents_from_telemetry()
        self.assertEqual(Incident.objects.count(), 1)
        self.assertEqual(Incident.objects.get(resource='one-off').severity, Incident.Severity.MEDIUM)

    def test_latest_successful_jenkins_build_resolves_previous_failure(self):
        JenkinsBuild.objects.create(job_name='deploy', build_number=10, result='FAILURE', updated_at=timezone.now())
        sync_incidents_from_telemetry()
        incident = Incident.objects.get(source=Incident.Source.JENKINS, resource='deploy')
        self.assertEqual(incident.severity, Incident.Severity.HIGH)

        JenkinsBuild.objects.create(job_name='deploy', build_number=11, result='SUCCESS', updated_at=timezone.now())
        sync_incidents_from_telemetry()
        incident.refresh_from_db()
        self.assertEqual(incident.status, Incident.Status.RESOLVED)

    def test_prometheus_and_alertmanager_recovery_resolve_incidents(self):
        PrometheusAlert.objects.create(
            metric_name='node_memory_MemAvailable_bytes',
            metric_type='host_memory_bounds',
            alert_status='CRITICAL_LOW_MEMORY',
            value=10,
            updated_at=timezone.now(),
        )
        PrometheusAlert.objects.create(
            metric_name='alert:DiskLow',
            metric_type='alertmanager',
            alert_status='FIRING',
            value=1,
            labels={'alertname': 'DiskLow'},
            updated_at=timezone.now(),
        )
        sync_incidents_from_telemetry()
        self.assertEqual(Incident.objects.count(), 2)
        self.assertTrue(Incident.objects.filter(severity=Incident.Severity.CRITICAL).exists())

        PrometheusAlert.objects.filter(metric_type='host_memory_bounds').update(alert_status='NORMAL')
        PrometheusAlert.objects.filter(metric_type='alertmanager').update(alert_status='NORMAL')
        sync_incidents_from_telemetry()
        self.assertFalse(Incident.objects.exclude(status=Incident.Status.RESOLVED).exists())


    def test_stale_telemetry_does_not_create_or_resolve_incidents(self):
        from datetime import timedelta

        stale_time = timezone.now() - timedelta(hours=1)
        existing = record_incident(
            source=Incident.Source.DOCKER,
            resource='api',
            condition='container_not_running',
            title='Container stopped: api',
            observed_at=stale_time,
        )
        DockerMetric.objects.create(
            container_name='api',
            status='running',
            timestamp=stale_time,
        )

        sync_incidents_from_telemetry()
        existing.refresh_from_db()
        self.assertEqual(existing.status, Incident.Status.OPEN)
        self.assertEqual(existing.last_seen, stale_time)
