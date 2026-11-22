import io
import logging
import uuid

from django.utils import timezone
from rest_framework import decorators, response, viewsets

from apps.audit.models import AuditEvent
from apps.knowledge.chroma import delete_document_vectors, get_chroma_collection, index_document
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
        document = serializer.save()
        self._index(document)

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

        title = _clean(request.data.get('title') or file_name or 'Untitled Runbook')
        content = _clean(request.data.get('content') or file_content)
        source = _clean(request.data.get('source') or 'Manual Ingestion') or 'Manual Ingestion'
        if not content:
            return response.Response({'detail': 'Unable to extract any valid text content.'}, status=400)

        collection = KnowledgeCollection.objects.filter(archived_at__isnull=True).first()
        if collection is None:
            collection = KnowledgeCollection.objects.create(
                name='global-ops-knowledge-base',
                description='Global Ops Knowledge Base',
                provider='chromadb',
            )
        serializer = self.get_serializer(data={
            'title': title,
            'content': content,
            'external_id': f'ext_{uuid.uuid4().hex[:12]}',
            'collection': collection.pk,
            'metadata': {'source': source},
        })
        serializer.is_valid(raise_exception=True)
        document = serializer.save()
        indexed = self._index(document, source)
        AuditEvent.objects.create(action='create', resource_type='document', resource_id=str(document.pk), payload={'title': title})
        payload = self.get_serializer(document).data
        payload['indexed'] = indexed
        return response.Response(payload, status=201)

    def _index(self, document, source=None):
        collection = get_chroma_collection()
        if collection is None or not document.content:
            return False
        metadata = document.metadata if isinstance(document.metadata, dict) else {}
        source = source or metadata.get('source') or 'Manual Ingestion'
        try:
            return index_document(collection, document.pk, document.title, document.content, source) > 0
        except Exception:
            logger.exception('Chroma index failed')
            return False

    @decorators.action(detail=False, methods=['get'])
    def search(self, request):
        query = request.query_params.get('q', '').strip()
        queryset = self.get_queryset()
        if not query:
            return response.Response(self.get_serializer(queryset[:50], many=True).data)
        collection = get_chroma_collection()
        if collection is not None:
            try:
                results = collection.query(query_texts=[query], n_results=10)
                matched_ids = []
                for raw in (results.get('ids') or [[]])[0]:
                    head = str(raw).split(':', 1)[0]
                    if head.isdigit() and int(head) not in matched_ids:
                        matched_ids.append(int(head))
                if matched_ids:
                    matched = queryset.filter(pk__in=matched_ids)
                    return response.Response(self.get_serializer(matched, many=True).data)
            except Exception:
                logger.exception('vector search failed')
        matched = queryset.filter(title__icontains=query) | queryset.filter(content__icontains=query)
        return response.Response(self.get_serializer(matched[:50], many=True).data)


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
