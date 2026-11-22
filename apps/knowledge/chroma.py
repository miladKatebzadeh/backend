import logging
import os
import time
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)

_collection = None
_signature = None
_down_until = 0.0


def _heartbeat(host, port):
    for path in ('/api/v2/heartbeat', '/api/v1/heartbeat'):
        try:
            with urllib.request.urlopen(f'http://{host}:{port}{path}', timeout=2) as response:
                return response.status < 500
        except urllib.error.HTTPError as exc:
            if exc.code < 500:
                return True
        except Exception:
            continue
    return False


def get_chroma_collection():
    global _collection, _signature, _down_until
    host = os.getenv('CHROMA_HOST', 'localhost')
    port = int(os.getenv('CHROMA_PORT', '8001') or 8001)
    embedding_name = 'all-MiniLM-L6-v2'
    try:
        from apps.mcp.models import get_setting
        host = get_setting('chroma_host', host) or host
        port = int(get_setting('chroma_port', str(port)) or port)
        embedding_name = get_setting('embedding_engine', embedding_name) or embedding_name
    except Exception:
        logger.exception('Could not read Chroma settings')
    signature = (host, port, embedding_name)
    if _collection is not None and _signature == signature:
        return _collection
    if time.time() < _down_until and _signature == signature:
        return None
    if not _heartbeat(host, port):
        logger.info('Chroma is not reachable at %s:%s; runbook search will use Postgres.', host, port)
        _collection = None
        _signature = signature
        _down_until = time.time() + 30
        return None
    try:
        import chromadb
        from chromadb.utils import embedding_functions
        embedding = embedding_functions.DefaultEmbeddingFunction()
        if embedding_name and embedding_name not in ('default', 'all-MiniLM-L6-v2'):
            sentence_transformer = getattr(embedding_functions, 'SentenceTransformerEmbeddingFunction', None)
            if sentence_transformer is not None:
                embedding = sentence_transformer(model_name=embedding_name)
        client = chromadb.HttpClient(host=host, port=port)
        _collection = client.get_or_create_collection(name='devops_knowledge_base', embedding_function=embedding)
        _signature = signature
        _down_until = 0
        return _collection
    except Exception:
        logger.exception('Could not connect to ChromaDB at %s:%s', host, port)
        _collection = None
        _signature = signature
        _down_until = time.time() + 30
        return None


CHUNK_SIZE = 1000
CHUNK_OVERLAP = 150


def chunk_text(text, size=CHUNK_SIZE, overlap=CHUNK_OVERLAP):
    """Split a runbook near a paragraph boundary so one vector is not the whole file."""
    text = (text or "").strip()
    if not text:
        return []
    if len(text) <= size:
        return [text]
    chunks = []
    start = 0
    while start < len(text):
        end = min(len(text), start + size)
        if end < len(text):
            window = text.rfind("\n", start + size // 2, end)
            if window == -1:
                window = text.rfind(" ", start + size // 2, end)
            if window > start:
                end = window
        piece = text[start:end].strip()
        if piece:
            chunks.append(piece)
        if end >= len(text):
            break
        start = max(end - overlap, start + 1)
    return chunks


def delete_document_vectors(collection, document_id):
    document_id = str(document_id)
    try:
        collection.delete(where={"document_id": document_id})
    except Exception:
        logger.info("Chroma metadata delete skipped for document %s", document_id)
    try:
        collection.delete(ids=[document_id])
    except Exception:
        logger.info("Chroma legacy delete skipped for document %s", document_id)


def index_document(collection, document_id, title, content, source="Manual Ingestion"):
    chunks = chunk_text(content)
    delete_document_vectors(collection, document_id)
    if not chunks:
        return 0
    source = source or "Manual Ingestion"
    collection.upsert(
        ids=[f"{document_id}:{index}" for index in range(len(chunks))],
        documents=chunks,
        metadatas=[
            {
                "title": title or "runbook",
                "source": source,
                "document_id": str(document_id),
                "chunk": index,
            }
            for index in range(len(chunks))
        ],
    )
    return len(chunks)


def reset_chroma_cache():
    global _collection, _signature, _down_until
    _collection = None
    _signature = None
    _down_until = 0.0


def rebuild_knowledge_index():
    """Drop the vector collection and index the documents stored in Postgres again."""
    reset_chroma_cache()
    host = os.getenv('CHROMA_HOST', 'localhost')
    port = int(os.getenv('CHROMA_PORT', '8001') or 8001)
    try:
        from apps.mcp.models import get_setting
        host = get_setting('chroma_host', host) or host
        port = int(get_setting('chroma_port', str(port)) or port)
        import chromadb
        client = chromadb.HttpClient(host=host, port=port)
        try:
            client.delete_collection('devops_knowledge_base')
        except Exception:
            logger.info('Chroma collection was not deleted before rebuild')
        reset_chroma_cache()
        collection = get_chroma_collection()
        if collection is None:
            return {'reindexed': False, 'count': 0}
        from apps.knowledge.models import KnowledgeDocument
        count = 0
        chunks = 0
        for document in KnowledgeDocument.objects.filter(archived_at__isnull=True):
            if not document.content:
                continue
            metadata = document.metadata if isinstance(document.metadata, dict) else {}
            source = metadata.get('source') or 'Manual Ingestion'
            written = index_document(collection, document.pk, document.title, document.content, source)
            if written:
                count += 1
                chunks += written
        return {'reindexed': True, 'count': count, 'chunks': chunks}
    except Exception:
        logger.exception('Knowledge reindex failed')
        reset_chroma_cache()
        return {'reindexed': False, 'count': 0}
