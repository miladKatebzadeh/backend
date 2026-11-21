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
        for document in KnowledgeDocument.objects.filter(archived_at__isnull=True):
            if not document.content:
                continue
            metadata = document.metadata if isinstance(document.metadata, dict) else {}
            payload = {'title': document.title, 'source': metadata.get('source') or 'Manual Ingestion'}
            collection.upsert(ids=[str(document.pk)], documents=[document.content], metadatas=[payload])
            count += 1
        return {'reindexed': True, 'count': count}
    except Exception:
        logger.exception('Knowledge reindex failed')
        reset_chroma_cache()
        return {'reindexed': False, 'count': 0}
