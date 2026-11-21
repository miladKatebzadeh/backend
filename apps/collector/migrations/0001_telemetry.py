from django.db import migrations, models


def forwards(apps, schema_editor):
    from apps.collector.models import DockerMetric, JenkinsBuild, PrometheusAlert

    connection = schema_editor.connection
    existing_tables = set(connection.introspection.table_names())
    for model in (DockerMetric, JenkinsBuild, PrometheusAlert):
        table = model._meta.db_table
        if table not in existing_tables:
            schema_editor.create_model(model)
            existing_tables.add(table)
            continue
        with connection.cursor() as cursor:
            columns = {col.name for col in connection.introspection.get_table_description(cursor, table)}
        for field in model._meta.local_fields:
            if field.column not in columns:
                schema_editor.add_field(model, field)


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.CreateModel(
                    name='DockerMetric',
                    fields=[
                        ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                        ('container_name', models.CharField(max_length=255)),
                        ('status', models.CharField(blank=True, max_length=64)),
                        ('cpu_percent', models.FloatField(default=0)),
                        ('mem_usage_mb', models.FloatField(default=0)),
                        ('oom_killed', models.BooleanField(default=False)),
                        ('raw_stats', models.JSONField(blank=True, default=dict)),
                        ('container_logs', models.TextField(blank=True, default='')),
                        ('restart_count', models.IntegerField(default=0)),
                        ('timestamp', models.DateTimeField(blank=True, null=True)),
                        ('resolved', models.BooleanField(default=False)),
                        ('remediation_attempted', models.BooleanField(default=False)),
                        ('last_attempt_at', models.DateTimeField(blank=True, null=True)),
                    ],
                    options={'db_table': 'docker_metrics'},
                ),
                migrations.CreateModel(
                    name='JenkinsBuild',
                    fields=[
                        ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                        ('job_name', models.CharField(max_length=255)),
                        ('build_number', models.IntegerField()),
                        ('result', models.CharField(blank=True, default='', max_length=64)),
                        ('duration_ms', models.BigIntegerField(default=0)),
                        ('estimated_duration_ms', models.BigIntegerField(default=0)),
                        ('raw_build_info', models.JSONField(blank=True, default=dict)),
                        ('console_output', models.TextField(blank=True, default='')),
                        ('remediation_attempted', models.BooleanField(default=False)),
                        ('last_attempt_at', models.DateTimeField(blank=True, null=True)),
                        ('updated_at', models.DateTimeField(blank=True, null=True)),
                    ],
                    options={'db_table': 'jenkins_builds'},
                ),
                migrations.CreateModel(
                    name='PrometheusAlert',
                    fields=[
                        ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                        ('metric_name', models.CharField(max_length=512)),
                        ('value', models.FloatField(default=0)),
                        ('labels', models.JSONField(blank=True, default=dict)),
                        ('alert_status', models.CharField(default='NORMAL', max_length=64)),
                        ('metric_type', models.CharField(default='generic', max_length=64)),
                        ('updated_at', models.DateTimeField(blank=True, null=True)),
                    ],
                    options={'db_table': 'prometheus_alerts'},
                ),
            ],
            database_operations=[
                migrations.RunPython(forwards, migrations.RunPython.noop),
            ],
        ),
    ]
