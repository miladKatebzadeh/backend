from django.db import models


class DockerMetric(models.Model):
    container_name = models.CharField(max_length=255)
    status = models.CharField(max_length=64, blank=True)
    cpu_percent = models.FloatField(default=0)
    mem_usage_mb = models.FloatField(default=0)
    oom_killed = models.BooleanField(default=False)
    raw_stats = models.JSONField(default=dict, blank=True)
    container_logs = models.TextField(blank=True, default='')
    restart_count = models.IntegerField(default=0)
    timestamp = models.DateTimeField(null=True, blank=True)
    resolved = models.BooleanField(default=False)
    remediation_attempted = models.BooleanField(default=False)
    last_attempt_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'docker_metrics'


class JenkinsBuild(models.Model):
    job_name = models.CharField(max_length=255)
    build_number = models.IntegerField()
    result = models.CharField(max_length=64, blank=True, default='')
    duration_ms = models.BigIntegerField(default=0)
    estimated_duration_ms = models.BigIntegerField(default=0)
    raw_build_info = models.JSONField(default=dict, blank=True)
    console_output = models.TextField(blank=True, default='')
    remediation_attempted = models.BooleanField(default=False)
    last_attempt_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'jenkins_builds'


class PrometheusAlert(models.Model):
    metric_name = models.CharField(max_length=512)
    value = models.FloatField(default=0)
    labels = models.JSONField(default=dict, blank=True)
    alert_status = models.CharField(max_length=64, default='NORMAL')
    metric_type = models.CharField(max_length=64, default='generic')
    updated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'prometheus_alerts'
