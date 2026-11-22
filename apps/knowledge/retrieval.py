import logging
import re

from django.db.models import Q

from apps.knowledge.chroma import get_chroma_collection
from apps.knowledge.ingestion import chunk_markdown, parse_front_matter
from apps.knowledge.models import KnowledgeDocument

logger = logging.getLogger(__name__)

_FAMILY_METADATA = {
    "container_runtime": {
        "section": ("container", "containers", "container_runtime", "runtime", "docker"),
        "component": ("container", "docker", "runtime"),
    },
    "deployment_regression": {
        "section": ("release", "deployment", "deploy", "deployment_regression"),
        "component": ("deploy", "deployment", "release", "rollout"),
    },
    "ci_failure": {
        "section": ("ci", "cicd", "pipeline", "build"),
        "component": ("jenkins", "ci", "pipeline", "build"),
    },
    "metric_anomaly": {
        "section": ("metrics", "metric", "monitoring", "observability"),
        "component": ("prometheus", "metrics", "monitoring"),
    },
}

_STOPWORDS = {
    "system", "alert", "status", "issue", "problem", "error", "errors",
    "the", "and", "for", "with", "from", "that", "this", "when", "what",
    "which", "into", "after", "before", "about", "please", "check",
    "container", "containers", "runtime", "docker",
}

_SYNONYMS = {
    "exited": {"exit", "exited", "stopped", "terminated", "dead", "crashed", "crash"},
    "exit": {"exit", "exited", "stopped", "terminated", "dead", "crashed", "crash"},
    "crashed": {"crash", "crashed", "exited", "terminated", "dead"},
    "failure": {"failure", "failed", "fail", "broken"},
    "failed": {"failure", "failed", "fail", "broken"},
    "rollback": {"rollback", "revert", "previous", "restore"},
}


def _normalise(value):
    text = str(value or "").lower().replace("ي", "ی").replace("ك", "ک").replace("\u200c", " ")
    return re.sub(r"\s+", " ", text).strip()


def _tokens(value):
    text = _normalise(value)
    raw = re.findall(r"[a-z0-9][a-z0-9_.:/-]*|[\u0600-\u06ff]{2,}", text)
    result = set()
    for token in raw:
        token = token.strip("._:/-")
        if len(token) < 3 or token in _STOPWORDS:
            continue
        if token.endswith("ies") and len(token) > 4:
            token = token[:-3] + "y"
        elif token.endswith("s") and not token.endswith("ss") and len(token) > 4:
            token = token[:-1]
        result.add(token)
    return result


def _query_terms(query):
    terms = _tokens(query)
    expanded = set(terms)
    for term in terms:
        expanded.update(_SYNONYMS.get(term, ()))
    return expanded


def _family_filter(incident_family):
    config = _FAMILY_METADATA.get(str(incident_family or "").lower())
    if not config:
        return None
    clauses = [{"section": value} for value in config["section"]]
    clauses.extend({"component": value} for value in config["component"])
    return {"$or": clauses} if len(clauses) > 1 else (clauses[0] if clauses else None)


def _family_match(metadata, incident_family):
    config = _FAMILY_METADATA.get(str(incident_family or "").lower())
    if not config:
        return False
    section = _normalise(metadata.get("section")).replace("-", "_").replace(" ", "_")
    component = _normalise(metadata.get("component")).replace("-", "_").replace(" ", "_")
    return section in config["section"] or component in config["component"]


def _candidate_from_chroma(results):
    candidates = []
    if not isinstance(results, dict):
        return candidates

    documents = results.get("documents") or []
    metadatas = results.get("metadatas") or []
    distances = results.get("distances") or []
    ids = results.get("ids") or []
    for group_index, group in enumerate(documents):
        metadata_group = metadatas[group_index] if group_index < len(metadatas) else []
        distance_group = distances[group_index] if group_index < len(distances) else []
        id_group = ids[group_index] if group_index < len(ids) else []
        for item_index, document in enumerate(group or []):
            if not isinstance(document, str) or not document.strip():
                continue
            metadata = (
                metadata_group[item_index]
                if item_index < len(metadata_group) and isinstance(metadata_group[item_index], dict)
                else {}
            )
            raw_id = str(id_group[item_index]) if item_index < len(id_group) else ""
            document_id = metadata.get("document_id")
            if document_id is None and ":" in raw_id:
                document_id = raw_id.split(":", 1)[0]
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                document_id = None
            chunk_index = metadata.get("chunk")
            if chunk_index is None and ":" in raw_id:
                chunk_index = raw_id.rsplit(":", 1)[1]
            distance = distance_group[item_index] if item_index < len(distance_group) else None
            try:
                distance = float(distance) if distance is not None else None
            except (TypeError, ValueError):
                distance = None

            candidates.append({
                "text": document.strip(),
                "title": str(metadata.get("title") or "Runbook"),
                "document_id": document_id,
                "chunk": chunk_index,
                "section": str(metadata.get("section") or ""),
                "component": str(metadata.get("component") or ""),
                "keywords": str(metadata.get("keywords") or ""),
                "heading_path": str(metadata.get("heading_path") or ""),
                "distance": distance,
                "retrieval_source": "chroma",
                "_id": raw_id or f"{document_id}:{metadata.get('chunk', item_index)}",
            })
    return candidates


def _chroma_candidates(collection, query, incident_family, limit):
    try:
        count = collection.count()
        if not count:
            return []
        n_results = min(int(count), max(12, limit * 8))
        where = _family_filter(incident_family)
        if where:
            try:
                filtered = collection.query(
                    query_texts=[query],
                    n_results=n_results,
                    where=where,
                )
                candidates = _candidate_from_chroma(filtered)
                if candidates:
                    return candidates
            except Exception:
                logger.info("Chroma metadata-filtered retrieval unavailable; using unfiltered retrieval.", exc_info=True)

        results = collection.query(query_texts=[query], n_results=n_results)
        return _candidate_from_chroma(results)
    except Exception:
        logger.exception("Chroma retrieval failed")
        return []


def _postgres_candidates(query, limit=80):
    terms = _query_terms(query)
    if not terms:
        return []

    condition = Q()
    for word in sorted(terms, key=len, reverse=True)[:16]:
        condition |= Q(title__icontains=word) | Q(content__icontains=word)

    rows = (
        KnowledgeDocument.objects
        .filter(archived_at__isnull=True)
        .filter(condition)
        .order_by("-updated_at")[:limit]
    )
    candidates = []
    for row in rows:
        metadata = row.metadata if isinstance(row.metadata, dict) else {}
        try:
            front_matter, body = parse_front_matter(row.content)
        except ValueError:
            logger.warning("Skipping front matter parsing for legacy document %s", row.pk, exc_info=True)
            front_matter, body = {}, row.content
        metadata = {**front_matter, **metadata}
        chunks = chunk_markdown(body)
        for index, chunk in enumerate(chunks):
            prefix = [
                f"Title: {row.title}",
                f"Section: {metadata.get('section', '')}",
                f"Component: {metadata.get('component', '')}",
                f"Keywords: {', '.join(metadata.get('keywords', [])) if isinstance(metadata.get('keywords'), list) else metadata.get('keywords', '')}",
            ]
            text = "\n".join(item for item in prefix if item.strip()) + "\n\n" + chunk
            candidates.append({
                "text": text,
                "title": row.title,
                "document_id": row.pk,
                "chunk": index,
                "section": str(metadata.get("section") or ""),
                "component": str(metadata.get("component") or ""),
                "keywords": " ".join(str(item) for item in metadata.get("keywords", []))
                    if isinstance(metadata.get("keywords"), list)
                    else str(metadata.get("keywords") or ""),
                "heading_path": "",
                "distance": None,
                "retrieval_source": "postgres",
                "_id": f"pg:{row.pk}:{index}",
            })
    return candidates


def _score_candidate(candidate, query_terms, incident_family):
    title_terms = _tokens(candidate.get("title"))
    keyword_terms = _tokens(candidate.get("keywords"))
    heading_terms = _tokens(candidate.get("heading_path"))
    text_terms = _tokens(candidate.get("text"))
    matched = query_terms & (title_terms | keyword_terms | heading_terms | text_terms)
    if not matched:
        return None

    title_hits = len(query_terms & title_terms)
    keyword_hits = len(query_terms & keyword_terms)
    heading_hits = len(query_terms & heading_terms)
    body_hits = len(query_terms & text_terms)
    family_match = _family_match(candidate, incident_family)
    lexical_score = (title_hits * 6) + (keyword_hits * 5) + (heading_hits * 3) + body_hits
    if family_match:
        lexical_score += 2

    candidate["lexical_score"] = lexical_score
    candidate["matched_terms"] = sorted(matched)
    candidate["family_match"] = family_match
    return candidate


def retrieve_runbooks(query, incident_family=None, limit=3):
    """Hybrid metadata-aware retrieval with a lexical relevance gate."""
    query_terms = _query_terms(query)
    if not query_terms:
        return {
            "results": [],
            "source": "none",
            "candidate_count": 0,
            "filters": [],
        }

    chroma_candidates = []
    collection = get_chroma_collection()
    if collection is not None:
        chroma_candidates = _chroma_candidates(collection, query, incident_family, limit)

    postgres_candidates = _postgres_candidates(query)
    candidates = []
    seen = set()
    for candidate in [*chroma_candidates, *postgres_candidates]:
        document_id = candidate.get("document_id")
        chunk_index = candidate.get("chunk")
        key = (
            f"{document_id}:{chunk_index}"
            if document_id is not None and chunk_index is not None
            else candidate.get("_id")
        )
        if key in seen:
            continue
        seen.add(key)
        scored = _score_candidate(candidate, query_terms, incident_family)
        if scored is not None:
            candidates.append(scored)

    # Reciprocal-rank fusion combines vector order and lexical relevance without
    # assuming that Chroma distances have a universal threshold across embeddings.
    vector_rank = {}
    vector_items = sorted(
        [item for item in candidates if item.get("distance") is not None],
        key=lambda item: item["distance"],
    )
    for rank, item in enumerate(vector_items, start=1):
        vector_rank[item["_id"]] = rank

    lexical_items = sorted(
        candidates,
        key=lambda item: item.get("lexical_score", 0),
        reverse=True,
    )
    lexical_rank = {item["_id"]: rank for rank, item in enumerate(lexical_items, start=1)}

    for item in candidates:
        rank_score = 0.0
        if item["_id"] in vector_rank:
            rank_score += 0.4 / (60 + vector_rank[item["_id"]])
        rank_score += 0.6 / (60 + lexical_rank[item["_id"]])
        if item.get("family_match"):
            rank_score += 0.0005
        item["relevance_score"] = round(rank_score, 6)

    candidates.sort(
        key=lambda item: (item["relevance_score"], item.get("lexical_score", 0)),
        reverse=True,
    )

    selected = []
    per_document = {}
    for item in candidates:
        document_id = item.get("document_id")
        document_key = document_id if document_id is not None else item["_id"]
        if per_document.get(document_key, 0) >= 2:
            continue
        per_document[document_key] = per_document.get(document_key, 0) + 1
        selected.append({
            "text": item["text"],
            "title": item["title"],
            "document_id": item.get("document_id"),
            "chunk": item.get("chunk"),
            "section": item.get("section"),
            "component": item.get("component"),
            "distance": item.get("distance"),
            "lexical_score": item.get("lexical_score"),
            "relevance_score": item.get("relevance_score"),
            "matched_terms": item.get("matched_terms", []),
            "retrieval_source": item.get("retrieval_source"),
        })
        if len(selected) >= limit:
            break

    candidate_sources = {item["retrieval_source"] for item in candidates}
    if candidate_sources == {"chroma", "postgres"}:
        source = "hybrid"
    elif candidate_sources == {"chroma"}:
        source = "chroma"
    elif candidate_sources == {"postgres"}:
        source = "postgres_fallback"
    else:
        source = "none"

    family_config = _FAMILY_METADATA.get(str(incident_family or "").lower(), {})
    filters = {
        "section": list(family_config.get("section", ())),
        "component": list(family_config.get("component", ())),
    }
    return {
        "results": selected,
        "source": source,
        "candidate_count": len(candidates),
        "filters": filters,
    }
