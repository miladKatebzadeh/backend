import logging
import os
import sys
import threading

from django.apps import AppConfig

logger = logging.getLogger(__name__)


class CollectorConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.collector'

    def ready(self):
        if os.environ.get('RUN_MAIN') != 'true':
            return
        if os.environ.get('OPSHUB_DISABLE_COLLECTOR') == '1':
            return
        if any(command in sys.argv for command in ('migrate', 'makemigrations', 'test', 'collect_telemetry')):
            return
        from apps.collector.tasks import StandaloneCollectorDaemon

        thread = threading.Thread(
            target=StandaloneCollectorDaemon.run_continuous_loop,
            daemon=True,
            name='OpsHubCollector',
        )
        thread.start()
        logger.info('Collector thread started for runserver. For gunicorn, run: python manage.py collect_telemetry')
