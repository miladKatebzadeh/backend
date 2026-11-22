from django.urls import path

from . import views

urlpatterns = [
    path("", views.incident_list, name="incident-list"),
    path("<int:incident_id>/", views.incident_detail, name="incident-detail"),
]
