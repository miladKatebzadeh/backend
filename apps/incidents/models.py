from django.db import models


class Incident(models.Model):
    class Source(models.TextChoices):
        DOCKER = 'docker', 'Docker'
        JENKINS = 'jenkins', 'Jenkins'
        PROMETHEUS = 'prometheus', 'Prometheus'
        ALERTMANAGER = 'alertmanager', 'Alertmanager'

    class Severity(models.TextChoices):
        CRITICAL = 'critical', 'Critical'
        HIGH = 'high', 'High'
        MEDIUM = 'medium', 'Medium'
        LOW = 'low', 'Low'

    class Status(models.TextChoices):
        OPEN = 'open', 'Open'
        ACKNOWLEDGED = 'acknowledged', 'Acknowledged'
        INVESTIGATING = 'investigating', 'Investigating'
        RESOLVED = 'resolved', 'Resolved'

    fingerprint = models.CharField(max_length=64, unique=True)
    source = models.CharField(max_length=20, choices=Source.choices)
    resource = models.CharField(max_length=255)
    title = models.CharField(max_length=240)
    description = models.TextField(blank=True, default='')
    severity = models.CharField(max_length=12, choices=Severity.choices, default=Severity.MEDIUM)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.OPEN)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    resolved_at = models.DateTimeField(null=True, blank=True)
    occurrence_count = models.PositiveIntegerField(default=1)
    last_occurrence_key = models.CharField(max_length=255, blank=True, default='')
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-last_seen', '-id']
        indexes = [
            models.Index(fields=['source', 'status'], name='inc_source_status_idx'),
            models.Index(fields=['status', 'severity'], name='inc_status_severity_idx'),
            models.Index(fields=['last_seen'], name='inc_last_seen_idx'),
        ]

    def __str__(self):
        return f'[{self.severity}] {self.title}'


class IncidentEvent(models.Model):
    class EventType(models.TextChoices):
        CREATED = 'created', 'Created'
        OCCURRENCE = 'occurrence', 'New occurrence'
        REOPENED = 'reopened', 'Reopened'
        RESOLVED = 'resolved', 'Resolved'
        STATUS_CHANGED = 'status_changed', 'Status changed'

    incident = models.ForeignKey(Incident, related_name='events', on_delete=models.CASCADE)
    event_type = models.CharField(max_length=24, choices=EventType.choices)
    actor = models.CharField(max_length=160, default='system')
    message = models.TextField(blank=True, default='')
    payload = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at', 'id']
        indexes = [
            models.Index(fields=['incident', 'created_at'], name='inc_event_created_idx'),
        ]

    def __str__(self):
        return f'{self.incident_id}: {self.event_type}'
