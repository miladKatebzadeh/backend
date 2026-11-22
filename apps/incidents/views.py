from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response

from .models import Incident, IncidentEvent


def _event_payload(event):
    return {
        "id": event.id,
        "event_type": event.event_type,
        "actor": event.actor,
        "message": event.message,
        "payload": event.payload,
        "created_at": event.created_at.isoformat(),
    }


def _incident_payload(incident, include_events=False):
    payload = {
        "id": incident.id,
        "fingerprint": incident.fingerprint,
        "source": incident.source,
        "resource": incident.resource,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "status": incident.status,
        "first_seen": incident.first_seen.isoformat(),
        "last_seen": incident.last_seen.isoformat(),
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
        "occurrence_count": incident.occurrence_count,
        "metadata": incident.metadata,
        "created_at": incident.created_at.isoformat(),
        "updated_at": incident.updated_at.isoformat(),
    }
    if include_events:
        payload["events"] = [
            _event_payload(event)
            for event in incident.events.order_by("-created_at", "-id")[:50]
        ]
    return payload


@api_view(["GET"])
def incident_list(request):
    queryset = Incident.objects.all()

    source = request.query_params.get("source")
    severity = request.query_params.get("severity")
    incident_status = request.query_params.get("status")
    search = request.query_params.get("q", "").strip()

    valid_sources = {value for value, _ in Incident.Source.choices}
    valid_severities = {value for value, _ in Incident.Severity.choices}
    valid_statuses = {value for value, _ in Incident.Status.choices}

    if source:
        if source not in valid_sources:
            return Response({"detail": "Invalid source filter."}, status=status.HTTP_400_BAD_REQUEST)
        queryset = queryset.filter(source=source)
    if severity:
        if severity not in valid_severities:
            return Response({"detail": "Invalid severity filter."}, status=status.HTTP_400_BAD_REQUEST)
        queryset = queryset.filter(severity=severity)
    if incident_status:
        if incident_status not in valid_statuses:
            return Response({"detail": "Invalid status filter."}, status=status.HTTP_400_BAD_REQUEST)
        queryset = queryset.filter(status=incident_status)
    if search:
        queryset = queryset.filter(title__icontains=search) | queryset.filter(resource__icontains=search)

    try:
        limit = min(max(int(request.query_params.get("limit", "100")), 1), 200)
    except (TypeError, ValueError):
        return Response({"detail": "limit must be an integer."}, status=status.HTTP_400_BAD_REQUEST)

    summary = {
        "open": Incident.objects.filter(status=Incident.Status.OPEN).count(),
        "acknowledged": Incident.objects.filter(status=Incident.Status.ACKNOWLEDGED).count(),
        "investigating": Incident.objects.filter(status=Incident.Status.INVESTIGATING).count(),
        "resolved": Incident.objects.filter(status=Incident.Status.RESOLVED).count(),
        "critical": Incident.objects.filter(severity=Incident.Severity.CRITICAL).exclude(
            status=Incident.Status.RESOLVED
        ).count(),
    }
    total = queryset.count()
    results = [_incident_payload(item) for item in queryset.order_by("-last_seen", "-id")[:limit]]
    return Response({"count": total, "summary": summary, "results": results})


@api_view(["GET", "PATCH"])
def incident_detail(request, incident_id):
    if request.method == "GET":
        incident = get_object_or_404(
            Incident.objects.prefetch_related("events"),
            pk=incident_id,
        )
        return Response(_incident_payload(incident, include_events=True))

    target_status = request.data.get("status")
    allowed_statuses = {
        Incident.Status.ACKNOWLEDGED,
        Incident.Status.INVESTIGATING,
    }
    if target_status not in allowed_statuses:
        return Response(
            {"detail": "Only acknowledged and investigating status changes are allowed from the dashboard."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    with transaction.atomic():
        incident = get_object_or_404(
            Incident.objects.select_for_update(),
            pk=incident_id,
        )
        if incident.status == Incident.Status.RESOLVED:
            return Response(
                {"detail": "A resolved incident cannot be changed from the dashboard."},
                status=status.HTTP_409_CONFLICT,
            )

        previous_status = incident.status
        if previous_status != target_status:
            incident.status = target_status
            incident.save(update_fields=["status", "updated_at"])
            IncidentEvent.objects.create(
                incident=incident,
                event_type=IncidentEvent.EventType.STATUS_CHANGED,
                actor="dashboard",
                message=f"Status changed from {previous_status} to {target_status}.",
                payload={"from": previous_status, "to": target_status},
            )

    return Response(_incident_payload(incident, include_events=True))
