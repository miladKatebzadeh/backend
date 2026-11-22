from django.core.management.base import BaseCommand, CommandError

from apps.knowledge.chroma import rebuild_knowledge_index


class Command(BaseCommand):
    help = "Rebuild the Chroma knowledge index from active PostgreSQL runbooks."

    def handle(self, *args, **options):
        result = rebuild_knowledge_index()
        if not result.get("reindexed"):
            raise CommandError("Knowledge index rebuild failed; check the backend logs.")

        self.stdout.write(
            self.style.SUCCESS(
                "Rebuilt Chroma index: "
                f"{result.get('count', 0)} documents, "
                f"{result.get('chunks', 0)} chunks."
            )
        )
