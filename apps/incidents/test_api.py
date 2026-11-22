from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from .models import Incident, IncidentEvent


class IncidentAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        now = timezone.now()
        self.incident = Incident.objects.create(
            fingerprint="a" * 64,
            source=Incident.Source.DOCKER,
            resource="web-1",
            title="Container stopped",
            description="Container exited unexpectedly.",
            severity=Incident.Severity.HIGH,
            status=Incident.Status.OPEN,
            first_seen=now,
            last_seen=now,
        )

    def test_list_returns_summary_and_incidents(self):
        response = self.client.get("/api/incidents/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["summary"]["open"], 1)
        self.assertEqual(response.data["results"][0]["fingerprint"], "a" * 64)

    def test_list_filters_by_severity_and_search(self):
        response = self.client.get("/api/incidents/?severity=high&q=web")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1)

        response = self.client.get("/api/incidents/?severity=critical")
        self.assertEqual(response.data["count"], 0)

    def test_detail_includes_event_history(self):
        IncidentEvent.objects.create(
            incident=self.incident,
            event_type=IncidentEvent.EventType.CREATED,
            message="Incident created.",
        )
        response = self.client.get(f"/api/incidents/{self.incident.id}/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data["events"]), 1)

    def test_dashboard_can_acknowledge_and_investigate(self):
        response = self.client.patch(
            f"/api/incidents/{self.incident.id}/",
            {"status": Incident.Status.ACKNOWLEDGED},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["status"], Incident.Status.ACKNOWLEDGED)
        self.assertEqual(
            IncidentEvent.objects.filter(
                incident=self.incident,
                event_type=IncidentEvent.EventType.STATUS_CHANGED,
            ).count(),
            1,
        )

        response = self.client.patch(
            f"/api/incidents/{self.incident.id}/",
            {"status": Incident.Status.INVESTIGATING},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["status"], Incident.Status.INVESTIGATING)

    def test_dashboard_cannot_manually_resolve_or_reopen_incident(self):
        response = self.client.patch(
            f"/api/incidents/{self.incident.id}/",
            {"status": Incident.Status.RESOLVED},
            format="json",
        )
        self.assertEqual(response.status_code, 400)

        self.incident.status = Incident.Status.RESOLVED
        self.incident.save(update_fields=["status"])
        response = self.client.patch(
            f"/api/incidents/{self.incident.id}/",
            {"status": Incident.Status.ACKNOWLEDGED},
            format="json",
        )
        self.assertEqual(response.status_code, 409)
