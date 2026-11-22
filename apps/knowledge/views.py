import io
import logging
import uuid

from django.utils import timezone
from django.utils.text import slugify
from rest_framework import decorators, response, viewsets
from rest_framework.exceptions import ValidationError

from apps.audit.models import AuditEvent
from apps.knowledge.chroma import delete_document_vectors, get_chroma_collection, index_document
from apps.knowledge.ingestion import content_fingerprint, parse_front_matter
from apps.knowledge.retrieval import retrieve_runbooks
from apps.knowledge.models import KnowledgeCollection, KnowledgeDocument
from apps.knowledge.serializers import KnowledgeCollectionSerializer, KnowledgeDocumentSerializer

logger = logging.getLogger(__name__)
MAX_UPLOAD_BYTES = 25 * 1024 * 1024

try:
    import pypdf
except ImportError:
    pypdf = None


def extract_text_from_pdf(pdf_file_bytes):
    if not pypdf:
        return ''
    reader = pypdf.PdfReader(io.BytesIO(pdf_file_bytes))
    parts = []
    for page in reader.pages:
        text = page.extract_text()
        if text:
            parts.append(text)
    return '\n'.join(parts)


def _clean(value):
    return (value or '').replace('\x00', '').replace('\u0000', '').strip()


class CollectionViewSet(viewsets.ModelViewSet):
    serializer_class = KnowledgeCollectionSerializer
    queryset = KnowledgeCollection.objects.filter(archived_at__isnull=True).order_by('-updated_at')


class DocumentViewSet(viewsets.ModelViewSet):
    serializer_class = KnowledgeDocumentSerializer
    queryset = KnowledgeDocument.objects.all().order_by('-updated_at')

    def get_queryset(self):
        queryset = super().get_queryset()
        if self.request.query_params.get('include_archived') != 'true':
            queryset = queryset.filter(archived_at__isnull=True)
        return queryset

    def destroy(self, request, *args, **kwargs):
        document = self.get_object()
        if request.query_params.get('confirm') != 'true':
            return response.Response({'detail': 'Deletion requires confirm=true.'}, status=400)
        collection = get_chroma_collection()
        if collection is not None:
            try:
                delete_document_vectors(collection, document.pk)
            except Exception:
                logger.exception('Chroma delete failed')
        document.archived_at = timezone.now()
        document.save(update_fields=['archived_at', 'updated_at'])
        AuditEvent.objects.create(action='delete', resource_type='document', resource_id=str(document.pk))
        return response.Response(status=204)

    def perform_update(self, serializer):
        content = serializer.validated_data.get("content", serializer.instance.content)
        try:
            front_matter, _ = parse_front_matter(content)
        except ValueError as exc:
            raise ValidationError({"content": str(exc)}) from exc

        document = serializer.save()
        metadata = document.metadata if isinstance(document.metadata, dict) else {}
        source = metadata.get("source") or "Manual Ingestion"
        runbook_fields = {"id", "section", "component", "title", "keywords"}
        preserved_metadata = {
            key: value for key, value in metadata.items()
            if key not in runbook_fields
        }
        document.metadata = {
            **preserved_metadata,
            **front_matter,
            "source": source,
            "content_hash": content_fingerprint(document.content),
        }
        document.save(update_fields=["metadata", "updated_at"])
        self._index(document, source)

    def create(self, request, *args, **kwargs):
        uploaded_file = request.FILES.get('file')
        file_content = ''
        file_name = ''
        if uploaded_file is not None:
            if uploaded_file.size > MAX_UPLOAD_BYTES:
                return response.Response({'detail': 'File exceeds 25 MB.'}, status=400)
            file_name = uploaded_file.name
            raw_bytes = uploaded_file.read()
            if file_name.lower().endswith('.pdf'):
                try:
                    file_content = extract_text_from_pdf(raw_bytes)
                except Exception:
                    logger.exception('PDF parse failed')
                    return response.Response({'detail': 'Could not read that PDF.'}, status=400)
            else:
                file_content = raw_bytes.decode('utf-8', errors='ignore')

        content = _clean(request.data.get('content') or file_content)
        if not content:
            return response.Response({'detail': 'Unable to extract any valid text content.'}, status=400)

        try:
            front_matter, _ = parse_front_matter(content)
        except ValueError as exc:
            return response.Response({'detail': str(exc)}, status=400)

        title = _clean(
            request.data.get('title')
            or front_matter.get('title')
            or file_name
            or 'Untitled Runbook'
        )
        source = _clean(request.data.get('source') or 'Manual Ingestion') or 'Manual Ingestion'
        document_metadata = {
            **front_matter,
            'source': source,
            'content_hash': content_fingerprint(content),
        }

        collection = KnowledgeCollection.objects.filter(archived_at__isnull=True).first()
        if collection is None:
            collection = KnowledgeCollection.objects.create(
                name='global-ops-knowledge-base',
                description='Global Ops Knowledge Base',
                provider='chromadb',
            )

        runbook_id = str(front_matter.get('id') or '').strip()
        runbook_slug = slugify(runbook_id) if runbook_id else ''
        if runbook_id and not runbook_slug:
            runbook_slug = content_fingerprint(runbook_id)[:32]
        external_id = (
            f"runbook_{runbook_slug[:160]}"
            if runbook_slug
            else f'ext_{uuid.uuid4().hex[:12]}'
        )
        document = KnowledgeDocument.objects.filter(
            collection=collection,
            external_id=external_id,
            archived_at__isnull=True,
        ).first()
        if document is None and runbook_id:
            document = KnowledgeDocument.objects.filter(
                collection=collection,
                archived_at__isnull=True,
                metadata__id=runbook_id,
            ).first()

        if document is None:
            document = KnowledgeDocument.objects.filter(
                collection=collection,
                archived_at__isnull=True,
                metadata__content_hash=document_metadata['content_hash'],
            ).first()

        if document is not None:
            document.title = title
            document.content = content
            document.metadata = document_metadata
            document.save(update_fields=['title', 'content', 'metadata', 'updated_at'])
            indexed_chunks = self._index(document, source)
            AuditEvent.objects.create(
                action='update',
                resource_type='document',
                resource_id=str(document.pk),
                payload={'title': title, 'reason': 'idempotent knowledge ingestion'},
            )
            payload = self.get_serializer(document).data
            payload['indexed'] = bool(indexed_chunks)
            payload['indexed_chunks'] = indexed_chunks
            payload['updated_existing'] = True
            return response.Response(payload, status=200)

        serializer = self.get_serializer(data={
            'title': title,
            'content': content,
            'external_id': external_id,
            'collection': collection.pk,
            'metadata': document_metadata,
        })
        serializer.is_valid(raise_exception=True)
        document = serializer.save()
        indexed_chunks = self._index(document, source)
        AuditEvent.objects.create(
            action='create',
            resource_type='document',
            resource_id=str(document.pk),
            payload={'title': title},
        )
        payload = self.get_serializer(document).data
        payload['indexed'] = bool(indexed_chunks)
        payload['indexed_chunks'] = indexed_chunks
        payload['updated_existing'] = False
        return response.Response(payload, status=201)

    def _index(self, document, source=None):
        collection = get_chroma_collection()
        if collection is None or not document.content:
            return 0
        metadata = document.metadata if isinstance(document.metadata, dict) else {}
        source = source or metadata.get('source') or 'Manual Ingestion'
        try:
            return index_document(
                collection,
                document.pk,
                document.title,
                document.content,
                source,
                metadata=metadata,
                collection_id=document.collection_id,
            )
        except Exception:
            logger.exception('Chroma index failed')
            return 0

    @decorators.action(detail=False, methods=['get'])
    def search(self, request):
        query = request.query_params.get('q', '').strip()
        queryset = self.get_queryset()
        if not query:
            return response.Response(self.get_serializer(queryset[:50], many=True).data)

        retrieval = retrieve_runbooks(query, limit=50)
        matched_ids = []
        for hit in retrieval.get('results', []):
            document_id = hit.get('document_id')
            if document_id is not None and document_id not in matched_ids:
                matched_ids.append(document_id)

        if not matched_ids:
            return response.Response([])
        found = {row.pk: row for row in queryset.filter(pk__in=matched_ids)}
        ordered = [found[document_id] for document_id in matched_ids if document_id in found]
        return response.Response(self.get_serializer(ordered, many=True).data)


@decorators.api_view(['GET'])
def knowledge_health(request):
    from apps.mcp.models import get_setting
    host = get_setting('chroma_host', 'localhost')
    port = get_setting('chroma_port', '8001')
    collection = get_chroma_collection()
    if collection is None:
        return response.Response({'status': 'offline', 'host': host, 'port': port})
    try:
        count = collection.count()
    except Exception:
        return response.Response({'status': 'offline', 'host': host, 'port': port})
    return response.Response({'status': 'connected', 'host': host, 'port': port, 'count': count})
