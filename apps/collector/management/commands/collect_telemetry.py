from django.core.management.base import BaseCommand

from apps.collector.tasks import StandaloneCollectorDaemon


class Command(BaseCommand):
    help = 'Collect Docker, Jenkins, and Prometheus telemetry until stopped. Use this process in production.'

    def handle(self, *args, **options):
        self.stdout.write('Collector loop started. Stop it with Ctrl+C.')
        StandaloneCollectorDaemon.run_continuous_loop()
