import hashlib
import re

import yaml


_FRONT_MATTER = re.compile(
    r"\A(?:\ufeff)?---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|$)",
    re.DOTALL,
)
_HEADING = re.compile(r"^(#{1,6})[ \t]+(.+?)\s*#*\s*$")
_FENCE = re.compile(r"^\s*(\x60{3,}|~{3,})")


def parse_front_matter(content):
    """Return safe YAML front matter and the Markdown body.

    Content without a front-matter block is returned unchanged. Invalid YAML is
    rejected rather than silently indexed as if its metadata had been parsed.
    """
    text = content or ""
    match = _FRONT_MATTER.match(text)
    if not match:
        return {}, text

    try:
        metadata = yaml.safe_load(match.group(1)) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML front matter: {exc}") from exc

    if not isinstance(metadata, dict):
        raise ValueError("YAML front matter must be a mapping of keys to values.")

    normalized = {}
    for key, value in metadata.items():
        name = str(key).strip().lower()
        if not name:
            continue
        if name in ("section", "component"):
            value = re.sub(r"[\s-]+", "_", str(value or "").strip().lower())
        elif name in ("id", "title"):
            value = str(value or "").strip()
        elif name == "keywords":
            if isinstance(value, str):
                value = [item.strip() for item in re.split(r"[,;]", value) if item.strip()]
            elif isinstance(value, (tuple, set)):
                value = list(value)
            elif not isinstance(value, list):
                value = []
            value = [str(item).strip() for item in value if str(item).strip()]
        normalized[name] = value

    body = text[match.end():].lstrip("\r\n")
    return normalized, body


def content_fingerprint(content):
    """Stable content hash used to avoid duplicate ingestion."""
    normalized = re.sub(r"\s+", " ", (content or "").strip()).encode("utf-8")
    return hashlib.sha256(normalized).hexdigest()


def _split_sections(text):
    lines = (text or "").splitlines()
    sections = []
    heading_stack = []
    body = []
    fence = None

    def flush():
        nonlocal body
        if any(line.strip() for line in body):
            sections.append(([line for _, line in heading_stack], body))
        body = []

    for line in lines:
        if fence:
            body.append(line)
            if line.lstrip().startswith(fence):
                fence = None
            continue

        fence_match = _FENCE.match(line)
        if fence_match:
            fence = fence_match.group(1)
            body.append(line)
            continue

        heading = _HEADING.match(line)
        if heading:
            flush()
            level = len(heading.group(1))
            heading_stack = heading_stack[:level - 1]
            heading_stack.append((level, line.strip()))
            continue

        body.append(line)

    flush()
    if not sections and heading_stack:
        sections.append(([line for _, line in heading_stack], []))
    return sections


def _markdown_blocks(lines):
    """Split section content into paragraphs, fenced code blocks, and tables."""
    blocks = []
    index = 0
    while index < len(lines):
        if not lines[index].strip():
            index += 1
            continue

        fence_match = _FENCE.match(lines[index])
        if fence_match:
            marker = fence_match.group(1)
            block = [lines[index]]
            index += 1
            while index < len(lines):
                block.append(lines[index])
                if lines[index].lstrip().startswith(marker):
                    index += 1
                    break
                index += 1
            blocks.append("\n".join(block).strip())
            continue

        if lines[index].lstrip().startswith("|"):
            block = []
            while index < len(lines) and lines[index].lstrip().startswith("|"):
                block.append(lines[index])
                index += 1
            blocks.append("\n".join(block).strip())
            continue

        block = []
        while index < len(lines) and lines[index].strip():
            if _FENCE.match(lines[index]) or lines[index].lstrip().startswith("|"):
                break
            block.append(lines[index])
            index += 1
        if block:
            blocks.append("\n".join(block).strip())

    return [block for block in blocks if block]


def _split_plain_text(text, size, overlap):
    pieces = []
    remaining = text.strip()
    while len(remaining) > size:
        cut = remaining.rfind(" ", 1, size + 1)
        if cut < 1:
            cut = size
        pieces.append(remaining[:cut].strip())
        next_start = max(0, cut - max(0, overlap))
        while next_start < cut and next_start > 0 and not remaining[next_start - 1].isspace():
            next_start += 1
        if next_start <= 0 or next_start >= cut:
            next_start = cut
        remaining = remaining[next_start:].strip()
    if remaining:
        pieces.append(remaining)
    return pieces


def _split_large_block(block, size, overlap):
    if len(block) <= size:
        return [block]

    lines = block.splitlines()
    fence_match = _FENCE.match(lines[0]) if lines else None
    if fence_match:
        marker = fence_match.group(1)
        closing = len(lines) > 1 and lines[-1].lstrip().startswith(marker)
        body = lines[1:-1] if closing else lines[1:]
        groups = []
        current = []
        current_size = 0
        for line in body:
            if current and current_size + len(line) + 1 > max(1, size - len(lines[0]) - len(marker)):
                groups.append(current)
                current, current_size = [], 0
            current.append(line)
            current_size += len(line) + 1
        if current:
            groups.append(current)
        return [
            "\n".join([lines[0], *group, marker])
            for group in groups
        ] or [block]

    if len(lines) >= 3 and lines[0].lstrip().startswith("|") and lines[1].lstrip().startswith("|"):
        header = lines[:2]
        rows = lines[2:]
        groups = []
        current = []
        current_size = sum(len(line) for line in header)
        for line in rows:
            if current and current_size + len(line) + 1 > size:
                groups.append(current)
                current, current_size = [], sum(len(item) for item in header)
            current.append(line)
            current_size += len(line) + 1
        if current:
            groups.append(current)
        return ["\n".join([*header, *group]) for group in groups] or [block]

    return _split_plain_text(block, size, overlap)


def chunk_markdown(text, size=1000, overlap=150):
    """Chunk Markdown on heading and block boundaries, preserving local context."""
    text = (text or "").strip()
    if not text:
        return []

    size = max(128, int(size))
    overlap = max(0, int(overlap))
    chunks = []

    for heading_path, section_lines in _split_sections(text):
        prefix = "\n".join(heading_path).strip()
        blocks = _markdown_blocks(section_lines)
        if not blocks and prefix:
            blocks = [prefix]
            prefix = ""

        current = []
        block_size = max(128, size - len(prefix) - 2) if prefix else size
        for block in blocks:
            parts = _split_large_block(block, block_size, overlap)
            for part in parts:
                candidate = "\n\n".join([*current, part]).strip()
                rendered = f"{prefix}\n\n{candidate}".strip() if prefix else candidate
                if current and len(rendered) > size:
                    chunks.append(f"{prefix}\n\n" + "\n\n".join(current) if prefix else "\n\n".join(current))
                    current = [part]
                else:
                    current.append(part)

        if current:
            chunks.append(f"{prefix}\n\n" + "\n\n".join(current) if prefix else "\n\n".join(current))
        elif prefix:
            chunks.append(prefix)

    return [chunk.strip() for chunk in chunks if chunk.strip()]
