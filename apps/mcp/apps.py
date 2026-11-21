import os
import sys
import threading

from django.apps import AppConfig


class McpConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.mcp'

    def ready(self):
        if any(command in sys.argv for command in ('migrate', 'makemigrations', 'test', 'collect_telemetry')):
            return
        if 'runserver' in sys.argv and os.environ.get('RUN_MAIN') != 'true':
            return
        from apps.mcp.diagnostics import warmup_laya

        threading.Thread(target=warmup_laya, daemon=True, name='LayaWarmup').start()
