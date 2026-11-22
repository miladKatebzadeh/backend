from unittest.mock import patch

from django.test import SimpleTestCase

from apps.knowledge.chroma import index_document
from apps.knowledge.ingestion import (
    chunk_markdown,
    content_fingerprint,
    parse_front_matter,
)
from apps.knowledge.retrieval import _query_terms, _score_candidate


class FrontMatterTests(SimpleTestCase):
    def test_parses_runbook_metadata_and_removes_header_from_body(self):
        content = """---
id: release-deployment-failed-rollback
section: release
component: deploy
title: Deployment failed, decide and roll back
keywords: [deployment failed, rollback, release failed]
---

# Deployment failed

Rollback instructions.
"""
        metadata, body = parse_front_matter(content)

        self.assertEqual(metadata["id"], "release-deployment-failed-rollback")
        self.assertEqual(metadata["section"], "release")
        self.assertEqual(metadata["component"], "deploy")
        self.assertIn("rollback", metadata["keywords"])
        self.assertTrue(body.startswith("# Deployment failed"))
        self.assertNotIn("id: release-deployment-failed-rollback", body)

    def test_rejects_invalid_yaml_front_matter(self):
        with self.assertRaises(ValueError):
            parse_front_matter("---\nsection: [unterminated\n---\n# Runbook")

    def test_content_fingerprint_ignores_whitespace_only_changes(self):
        self.assertEqual(
            content_fingerprint("one\n two"),
            content_fingerprint("one   two"),
        )


class MarkdownChunkingTests(SimpleTestCase):
    def test_preserves_heading_context_and_fenced_code(self):
        fence = chr(96) * 3
        markdown = (
            "# Operations\n\n"
            "## Restart service\n\n"
            "Run the command below.\n\n"
            f"{fence}bash\n"
            "docker compose restart api\n"
            f"{fence}\n"
        )

        chunks = chunk_markdown(markdown, size=300)

        self.assertEqual(len(chunks), 1)
        self.assertIn("# Operations\n## Restart service", chunks[0])
        self.assertIn(f"{fence}bash\ndocker compose restart api\n{fence}", chunks[0])

    def test_splits_long_sections_without_cutting_words(self):
        paragraph = " ".join(f"operation{i}" for i in range(120))
        chunks = chunk_markdown(f"# Long section\n\n{paragraph}", size=180, overlap=20)

        self.assertGreater(len(chunks), 1)
        self.assertTrue(all(chunk.startswith("# Long section") for chunk in chunks))
        self.assertTrue(all(not chunk.endswith("operation") for chunk in chunks))


class RetrievalRelevanceTests(SimpleTestCase):
    def test_rejects_deployment_rollback_runbook_for_exited_container(self):
        candidate = {
            "title": "Deployment failed, decide and roll back",
            "keywords": "deployment failed rollback release failed",
            "heading_path": "Release / Rollback",
            "section": "release",
            "component": "deploy",
            "text": (
                "Docker Compose pull the previous image tag and recreate "
                "the service after a failed release."
            ),
        }

        scored = _score_candidate(
            candidate,
            _query_terms("System Alert: Container grafana status exited"),
            "container_runtime",
        )

        self.assertIsNone(scored)

    def test_accepts_runbook_that_matches_container_exit_symptoms(self):
        candidate = {
            "title": "Container exited unexpectedly",
            "keywords": "container exited exit code oom",
            "heading_path": "Container runtime / Exit diagnosis",
            "section": "container_runtime",
            "component": "docker",
            "text": "Inspect the exit code and OOMKilled state for the container.",
        }

        scored = _score_candidate(
            candidate,
            _query_terms("System Alert: Container grafana status exited"),
            "container_runtime",
        )

        self.assertIsNotNone(scored)
        self.assertTrue(scored["family_match"])


class ChromaIndexingTests(SimpleTestCase):
    def test_stores_front_matter_as_scalar_chroma_metadata(self):
        class FakeCollection:
            def upsert(self, **kwargs):
                self.payload = kwargs

        collection = FakeCollection()
        content = """---
id: test-runbook
section: container_runtime
component: docker
title: Container exit diagnosis
keywords: [container exited, oom]
---

# Diagnose exit

Inspect the exit code.
"""
        with patch("apps.knowledge.chroma.delete_document_vectors"):
            count = index_document(
                collection,
                document_id=42,
                title="Container exit diagnosis",
                content=content,
                metadata={
                    "id": "test-runbook",
                    "section": "container_runtime",
                    "component": "docker",
                    "keywords": ["container exited", "oom"],
                },
                collection_id=3,
            )

        self.assertEqual(count, 1)
        metadata = collection.payload["metadatas"][0]
        self.assertEqual(metadata["document_id"], "42")
        self.assertEqual(metadata["section"], "container_runtime")
        self.assertEqual(metadata["component"], "docker")
        self.assertEqual(metadata["collection_id"], 3)
        self.assertIn("container exited", metadata["keywords"])
        self.assertIn("Title: Container exit diagnosis", collection.payload["documents"][0])
