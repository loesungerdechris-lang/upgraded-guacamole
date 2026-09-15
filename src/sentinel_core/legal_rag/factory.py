"""Build embedders and optional ColBERT rerankers from short names."""

from __future__ import annotations

from sentinel_core.legal_rag.embedder import (
    DEFAULT_ST_MODEL,
    Embedder,
    HashingEmbedder,
    SentenceTransformerEmbedder,
)
from sentinel_core.legal_rag.rerank import (
    BgeM3ColbertReranker,
    HashingColbertReranker,
    Reranker,
)

BGE_M3_MODEL = "BAAI/bge-m3"
E5_SMALL_MODEL = DEFAULT_ST_MODEL


def build_embedder(
    backend: str = "e5-small",
    *,
    model_name: str | None = None,
    device: str | None = None,
    revision: str | None = None,
    dim: int = 256,
) -> Embedder:
    """Return a hashing or SentenceTransformer embedder.

    ``backend`` values:
    - ``hashing`` — no extra dependency, CI default
    - ``e5`` / ``e5-small`` / ``sentence-transformers`` — multilingual-e5-small
    - ``bge-m3`` / ``m3`` — BAAI/bge-m3 dense only (Phase 2)
    """

    key = backend.strip().lower()
    if key in {"hashing", "hash", "fallback"}:
        return HashingEmbedder(dim=dim)
    if key in {"bge-m3", "m3", "bge"}:
        return SentenceTransformerEmbedder(
            model_name=model_name or BGE_M3_MODEL,
            device=device,
            revision=revision,
        )
    if key in {"sentence-transformers", "st", "e5", "e5-small", "dense"}:
        return SentenceTransformerEmbedder(
            model_name=model_name or E5_SMALL_MODEL,
            device=device,
            revision=revision,
        )
    raise ValueError(f"unknown embedder backend: {backend!r}")


def build_reranker(
    backend: str = "none",
    *,
    device: str | None = None,
    dim: int = 32,
) -> Reranker | None:
    """Return an optional ColBERT reranker.

    ``backend`` values:
    - ``none`` / ``off`` — no rerank
    - ``hashing`` — deterministic MaxSim, tests
    - ``bge-m3`` / ``colbert`` / ``m3`` — FlagEmbedding BGE-M3 multi-vector
    """

    key = backend.strip().lower()
    if key in {"", "none", "off", "false"}:
        return None
    if key in {"hashing", "hash", "colbert-hashing"}:
        return HashingColbertReranker(dim=dim)
    if key in {"bge-m3", "colbert", "m3", "colbert-bge-m3"}:
        return BgeM3ColbertReranker(device=device)
    raise ValueError(f"unknown reranker backend: {backend!r}")
