"""Ingest statute markdown into LegalStore."""

from __future__ import annotations

from pathlib import Path

from sentinel_core.legal_rag.chunker import split_norm
from sentinel_core.legal_rag.embedder import Embedder, pack_f32
from sentinel_core.legal_rag.store import LegalStore


def ingest_text(
    raw: str,
    *,
    law: str,
    source_url: str,
    source_name: str,
    store: LegalStore,
    embedder: Embedder | None = None,
) -> int:
    chunks = split_norm(
        raw, law=law, source_url=source_url, source_name=source_name
    )
    for chunk in chunks:
        blob = None
        card = None
        if embedder is not None:
            if hasattr(embedder, "embed_legal_passage"):
                vec = embedder.embed_legal_passage(
                    law=chunk.law,
                    article=chunk.article,
                    absatz=chunk.absatz,
                    text=chunk.text,
                )
            else:
                vec = embedder.embed_passage(chunk.passage_text())
            blob = pack_f32(vec)
            card = embedder.card
        store.upsert(chunk, embedding=blob, card=card)
    return len(chunks)


def ingest_file(path: str | Path, **kwargs) -> int:
    return ingest_text(Path(path).read_text(encoding="utf-8"), **kwargs)
