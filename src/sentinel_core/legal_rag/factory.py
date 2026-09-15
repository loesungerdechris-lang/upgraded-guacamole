"""Build an embedder from a short backend name."""

from __future__ import annotations

from sentinel_core.legal_rag.embedder import (
    DEFAULT_ST_MODEL,
    Embedder,
    HashingEmbedder,
    SentenceTransformerEmbedder,
)


def build_embedder(
    backend: str = "sentence-transformers",
    *,
    model_name: str = DEFAULT_ST_MODEL,
    device: str | None = None,
    revision: str | None = None,
    dim: int = 256,
) -> Embedder:
    """Return a hashing or SentenceTransformer embedder.

    ``backend`` values:
    - ``hashing`` — no extra dependency
    - ``sentence-transformers`` / ``st`` / ``e5`` — dense model
    """

    key = backend.strip().lower()
    if key in {"hashing", "hash", "fallback"}:
        return HashingEmbedder(dim=dim)
    if key in {"sentence-transformers", "st", "e5", "dense"}:
        return SentenceTransformerEmbedder(
            model_name=model_name,
            device=device,
            revision=revision,
        )
    raise ValueError(f"unknown embedder backend: {backend!r}")
