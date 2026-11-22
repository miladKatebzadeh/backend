from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='Incident',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('fingerprint', models.CharField(max_length=64, unique=True)),
                ('source', models.CharField(choices=[('docker', 'Docker'), ('jenkins', 'Jenkins'), ('prometheus', 'Prometheus'), ('alertmanager', 'Alertmanager')], max_length=20)),
                ('resource', models.CharField(max_length=255)),
                ('title', models.CharField(max_length=240)),
                ('description', models.TextField(blank=True, default='')),
                ('severity', models.CharField(choices=[('critical', 'Critical'), ('high', 'High'), ('medium', 'Medium'), ('low', 'Low')], default='medium', max_length=12)),
                ('status', models.CharField(choices=[('open', 'Open'), ('acknowledged', 'Acknowledged'), ('investigating', 'Investigating'), ('resolved', 'Resolved')], default='open', max_length=16)),
                ('first_seen', models.DateTimeField()),
                ('last_seen', models.DateTimeField()),
                ('resolved_at', models.DateTimeField(blank=True, null=True)),
                ('occurrence_count', models.PositiveIntegerField(default=1)),
                ('last_occurrence_key', models.CharField(blank=True, default='', max_length=255)),
                ('metadata', models.JSONField(blank=True, default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'ordering': ['-last_seen', '-id'],
                'indexes': [
                    models.Index(fields=['source', 'status'], name='inc_source_status_idx'),
                    models.Index(fields=['status', 'severity'], name='inc_status_severity_idx'),
                    models.Index(fields=['last_seen'], name='inc_last_seen_idx'),
                ],
            },
        ),
        migrations.CreateModel(
            name='IncidentEvent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('event_type', models.CharField(choices=[('created', 'Created'), ('occurrence', 'New occurrence'), ('reopened', 'Reopened'), ('resolved', 'Resolved'), ('status_changed', 'Status changed')], max_length=24)),
                ('actor', models.CharField(default='system', max_length=160)),
                ('message', models.TextField(blank=True, default='')),
                ('payload', models.JSONField(blank=True, default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('incident', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='events', to='incidents.incident')),
            ],
            options={
                'ordering': ['created_at', 'id'],
                'indexes': [
                    models.Index(fields=['incident', 'created_at'], name='inc_event_created_idx'),
                ],
            },
        ),
    ]
