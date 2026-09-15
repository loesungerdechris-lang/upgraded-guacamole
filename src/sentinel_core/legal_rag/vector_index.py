"""In-memory dense index bound to a single EmbeddingModelCard."""

from __future__ import annotations

from dataclasses import dataclass

from sentinel_core.legal_rag.embedder import (
    EmbeddingMismatchError,
    EmbeddingModelCard,
    Embedder,
    cosine,
    pack_f32,
    unpack_f32,
)


@dataclass(frozen=True)
class VectorHit:
    chunk_id: str
    score: float


class VectorIndex:
    """Stores packed float32 vectors. Refuses mixed model cards."""

    def __init__(self, card: EmbeddingModelCard):
        self.card = card
        self._items: dict[str, bytes] = {}

    def add(self, chunk_id: str, vector: list[float], card: EmbeddingModelCard) -> None:
        self.card.assert_compatible(card)
        if len(vector) != self.card.dim:
            raise EmbeddingMismatchError(
                f"vector dim {len(vector)} != card dim {self.card.dim}"
            )
        self._items[chunk_id] = pack_f32(vector)

    def add_passage(
        self,
        chunk_id: str,
        text: str,
        embedder: Embedder,
    ) -> None:
        self.add(chunk_id, embedder.embed_passage(text), embedder.card)

    def search(self, query_vec: list[float], k: int = 8, min_score: float = 0.35) -> list[VectorHit]:
        if len(query_vec) != self.card.dim:
            raise EmbeddingMismatchError(
                f"query dim {len(query_vec)} != card dim {self.card.dim}"
            )
        scored = [
            VectorHit(chunk_id, cosine(query_vec, unpack_f32(blob)))
            for chunk_id, blob in self._items.items()
        ]
        scored.sort(key=lambda h: h.score, reverse=True)
        return [h for h in scored if h.score >= min_score][:k]

    def search_query(self, query: str, embedder: Embedder, k: int = 8) -> list[VectorHit]:
        self.card.assert_compatible(embedder.card)
        return self.search(embedder.embed_query(query), k=k)

    def __len__(self) -> int:
        return len(self._items)
