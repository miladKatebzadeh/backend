import os

from rest_framework.permissions import BasePermission


class OptionalAPIKey(BasePermission):
    """Open for local development. When OPSHUB_API_KEY is set, require X-API-Key."""

    def has_permission(self, request, view):
        expected = os.getenv('OPSHUB_API_KEY', '').strip()
        if not expected:
            return True
        return request.headers.get('X-API-Key', '') == expected
