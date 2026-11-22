import logging
import os
import re
import time
import urllib.error
import urllib.request

from apps.knowledge.ingestion import chunk_markdown, content_fingerprint, parse_front_matter

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
    """Backward-compatible wrapper around the Markdown-aware chunker."""
    return chunk_markdown(text, size=size, overlap=overlap)


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


def index_document(
    collection,
    document_id,
    title,
    content,
    source="Manual Ingestion",
    metadata=None,
    collection_id=None,
):
    """Index Markdown chunks with searchable runbook metadata."""
    try:
        front_matter, body = parse_front_matter(content)
    except ValueError:
        logger.exception("Invalid front matter while indexing document %s", document_id)
        front_matter, body = {}, content or ""

    document_metadata = {**front_matter, **(metadata or {})}
    chunks = chunk_text(body)
    delete_document_vectors(collection, document_id)
    if not chunks:
        return 0

    source = source or document_metadata.get("source") or "Manual Ingestion"
    effective_title = str(document_metadata.get("title") or title or "runbook")[:240]
    keywords = document_metadata.get("keywords") or []
    if isinstance(keywords, str):
        keywords = [item.strip() for item in keywords.replace(";", ",").split(",") if item.strip()]
    keywords_text = " ".join(str(item).strip() for item in keywords if str(item).strip())
    section = re.sub(r"[\s-]+", "_", str(document_metadata.get("section") or "").strip().lower())
    component = re.sub(r"[\s-]+", "_", str(document_metadata.get("component") or "").strip().lower())
    runbook_id = str(document_metadata.get("id") or document_id)
    content_hash = content_fingerprint(body)

    ids = []
    documents = []
    metadatas = []
    for index, chunk in enumerate(chunks):
        context = [
            f"Title: {effective_title}",
            f"Section: {section}",
            f"Component: {component}",
            f"Keywords: {keywords_text}",
        ]
        documents.append("\n".join(item for item in context if item.strip()) + "\n\n" + chunk)
        metadata_item = {
            "title": effective_title,
            "source": str(source),
            "document_id": str(document_id),
            "runbook_id": runbook_id,
            "chunk": index,
            "content_hash": content_hash,
            "chunking_version": 2,
        }
        if section:
            metadata_item["section"] = section
        if component:
            metadata_item["component"] = component
        if keywords_text:
            metadata_item["keywords"] = keywords_text
        if collection_id is not None:
            metadata_item["collection_id"] = int(collection_id)
        headings = [
            line.strip()
            for line in chunk.splitlines()
            if line.lstrip().startswith("#")
        ]
        if headings:
            metadata_item["heading_path"] = " / ".join(headings[-4:])
        ids.append(f"{document_id}:{index}")
        metadatas.append(metadata_item)

    collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
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
            try:
                front_matter, _ = parse_front_matter(document.content)
            except ValueError:
                logger.warning('Could not parse front matter for knowledge document %s during rebuild', document.pk, exc_info=True)
                front_matter = {}
            metadata = {**front_matter, **metadata}
            metadata['content_hash'] = content_fingerprint(document.content)
            source = metadata.get('source') or 'Manual Ingestion'
            document.title = str(metadata.get('title') or document.title)[:240]
            document.metadata = metadata
            document.save(update_fields=['title', 'metadata', 'updated_at'])
            written = index_document(
                collection,
                document.pk,
                document.title,
                document.content,
                source,
                metadata=metadata,
                collection_id=document.collection_id,
            )
            if written:
                count += 1
                chunks += written
        return {'reindexed': True, 'count': count, 'chunks': chunks}
    except Exception:
        logger.exception('Knowledge reindex failed')
        reset_chroma_cache()
        return {'reindexed': False, 'count': 0}
