from rest_framework import serializers
from .models import KnowledgeCollection, KnowledgeDocument


class KnowledgeDocumentSerializer(serializers.ModelSerializer):
    source = serializers.SerializerMethodField()

    class Meta:
        model = KnowledgeDocument
        fields = [
            'id', 'collection', 'external_id', 'title', 'content', 'metadata',
            'archived_at', 'created_at', 'updated_at', 'source',
        ]

    def get_source(self, obj):
        if isinstance(obj.metadata, dict):
            return obj.metadata.get('source') or 'Knowledge base'
        return 'Knowledge base'


class KnowledgeCollectionSerializer(serializers.ModelSerializer):
    documents = KnowledgeDocumentSerializer(many=True, read_only=True)
    document_count = serializers.SerializerMethodField()

    class Meta:
        model = KnowledgeCollection
        fields = [
            'id', 'name', 'description', 'provider', 'archived_at',
            'created_at', 'updated_at', 'documents', 'document_count',
        ]

    def get_document_count(self, obj):
        return obj.documents.filter(archived_at__isnull=True).count()
