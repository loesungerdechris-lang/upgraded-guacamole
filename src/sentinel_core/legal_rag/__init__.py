"""Legal-Core retrieval embeddings.

SentenceTransformer is an optional extra. The core package must import
without torch or sentence-transformers installed.
"""

from sentinel_core.legal_rag.embedder import (
    DEFAULT_ST_MODEL,
    EmbeddingMismatchError,
    EmbeddingModelCard,
    Embedder,
    HashingEmbedder,
    MissingEmbeddingDependencyError,
    SentenceTransformerEmbedder,
    cosine,
    pack_f32,
    unpack_f32,
)
from sentinel_core.legal_rag.factory import build_embedder
from sentinel_core.legal_rag.vector_index import VectorHit, VectorIndex

__all__ = [
    "DEFAULT_ST_MODEL",
    "EmbeddingMismatchError",
    "EmbeddingModelCard",
    "Embedder",
    "HashingEmbedder",
    "MissingEmbeddingDependencyError",
    "SentenceTransformerEmbedder",
    "VectorHit",
    "VectorIndex",
    "build_embedder",
    "cosine",
    "pack_f32",
    "unpack_f32",
]
