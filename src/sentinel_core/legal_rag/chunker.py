"""Split statute markdown into paragraph-level chunks."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from sentinel_core.legal_rag.hashing import chunk_hash
from sentinel_core.legal_rag.models import NormChunk

ARTICLE_RE = re.compile(
    r"(?P<article>§\s*\d+[a-z]?)\s*(?P<title>[^\n]*)\n(?P<body>.*?)(?=\n§\s*\d+[a-z]?|\Z)",
    re.DOTALL,
)
ABSATZ_RE = re.compile(r"\((\d+[a-z]?)\)\s+")


def split_norm(
    raw: str,
    *,
    law: str,
    source_url: str,
    source_name: str,
    language: str = "de",
    retrieved_at: str | None = None,
) -> list[NormChunk]:
    stamp = retrieved_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    chunks: list[NormChunk] = []
    haystack = "\n" + raw.strip() + "\n"
    for match in ARTICLE_RE.finditer(haystack):
        article = re.sub(r"\s+", " ", match.group("article")).strip()
        title = match.group("title").strip()
        body = match.group("body").strip()
        parts = list(ABSATZ_RE.finditer(body))
        if not parts:
            chunks.append(
                _make(law, article, None, title, body, source_url, source_name, language, stamp)
            )
            continue
        for i, part in enumerate(parts):
            start = part.end()
            end = parts[i + 1].start() if i + 1 < len(parts) else len(body)
            text = f"({part.group(1)}) {body[start:end].strip()}"
            chunks.append(
                _make(
                    law,
                    article,
                    f"Abs. {part.group(1)}",
                    title,
                    text,
                    source_url,
                    source_name,
                    language,
                    stamp,
                )
            )
    return chunks


def _make(
    law: str,
    article: str,
    absatz: str | None,
    title: str,
    text: str,
    source_url: str,
    source_name: str,
    language: str,
    retrieved_at: str,
) -> NormChunk:
    digest = chunk_hash(law, article, absatz, text)
    slug = f"{law}:{article}:{absatz or 'voll'}".replace(" ", "")
    return NormChunk(
        chunk_id=digest.replace("sha256:", "")[:16] + ":" + slug,
        law=law,
        article=article,
        absatz=absatz,
        title=title,
        text=text,
        source_url=source_url,
        source_name=source_name,
        retrieved_at=retrieved_at,
        content_hash=digest,
        language=language,
    )
