from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import CollectionViewSet, DocumentViewSet, knowledge_health

router = DefaultRouter()
router.register('collections', CollectionViewSet, basename='collection')
router.register('documents', DocumentViewSet, basename='document')
urlpatterns = [path('health/', knowledge_health, name='knowledge-health')] + router.urls
