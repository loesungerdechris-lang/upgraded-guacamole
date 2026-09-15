"""Hybrid retrieval: exact paragraph, BM25, then dense ranking bonus."""

from __future__ import annotations

import re

from sentinel_core.legal_rag.embedder import Embedder, cosine, unpack_f32
from sentinel_core.legal_rag.models import Hit, NormChunk
from sentinel_core.legal_rag.store import LegalStore

ARTICLE_QUERY_RE = re.compile(r"§\s*(\d+[a-z]?)", re.I)


class LegalRetriever:
    def __init__(self, store: LegalStore, embedder: Embedder | None = None):
        self.store = store
        self.embedder = embedder

    def search(self, query: str, law: str | None = None, k: int = 6) -> list[Hit]:
        hits: dict[str, Hit] = {}
        guessed = law or _guess_law(query)

        for num in ARTICLE_QUERY_RE.findall(query):
            article = f"§ {num}"
            for chunk in self.store.get_exact(guessed, article):
                hits[chunk.chunk_id] = Hit(
                    chunk, 1.0, "exact", f"exakter Treffer {article}"
                )

        for chunk, score in self.store.bm25(query, k=k * 3):
            if law and chunk.law != law:
                continue
            prev = hits.get(chunk.chunk_id)
            if prev is None or score > prev.score:
                hits[chunk.chunk_id] = Hit(chunk, score, "bm25", "FTS5/BM25")

        if self.embedder is not None:
            card = self.store.model_card()
            if card is not None:
                card.assert_compatible(self.embedder.card)
            qvec = self.embedder.embed_query(query)
            scored: list[tuple[float, NormChunk]] = []
            for chunk, blob in self.store.all_with_embeddings():
                if law and chunk.law != law:
                    continue
                scored.append((cosine(qvec, unpack_f32(blob)), chunk))
            scored.sort(key=lambda item: item[0], reverse=True)
            for score, chunk in scored[:k]:
                if score < 0.35:
                    continue
                prev = hits.get(chunk.chunk_id)
                hybrid = score if prev is None else min(1.0, prev.score * 0.6 + score * 0.4)
                hits[chunk.chunk_id] = Hit(
                    chunk,
                    hybrid,
                    "hybrid" if prev else "vector",
                    "cosine + bm25",
                )

        ranked = sorted(hits.values(), key=lambda h: h.score, reverse=True)
        return ranked[:k]

    def citation_pack(self, query: str, law: str | None = None, k: int = 6) -> dict:
        found = self.search(query, law=law, k=k)
        return {
            "query": query,
            "hits": [
                {
                    "law": h.chunk.law,
                    "article": h.chunk.article,
                    "absatz": h.chunk.absatz,
                    "text": h.chunk.text,
                    "source_url": h.chunk.source_url,
                    "source_name": h.chunk.source_name,
                    "content_hash": h.chunk.content_hash,
                    "score": round(h.score, 4),
                    "ranker": h.ranker,
                }
                for h in found
            ],
            "rule": (
                "Generator darf nur texts[] wörtlich zitieren. "
                "Fehlt ein Treffer, gilt: nicht belegt."
            ),
        }


def _guess_law(query: str) -> str:
    q = query.lower()
    if "thüruig" in q or "thueruig" in q or "umweltinformation" in q:
        return "ThürUIG"
    return "VwGO"
