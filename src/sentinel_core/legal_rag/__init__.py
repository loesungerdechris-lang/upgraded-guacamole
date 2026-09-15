"""Legal-Core retrieval embeddings and SQLite store.

SentenceTransformer and FlagEmbedding are optional extras.
The core package must import without torch.
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
from sentinel_core.legal_rag.factory import build_embedder, build_reranker
from sentinel_core.legal_rag.ingest import ingest_file, ingest_text
from sentinel_core.legal_rag.models import Hit, NormChunk
from sentinel_core.legal_rag.rerank import (
    BgeM3ColbertReranker,
    HashingColbertReranker,
    MissingColbertDependencyError,
    maxsim,
    rerank_hits,
)
from sentinel_core.legal_rag.retrieve import LegalRetriever
from sentinel_core.legal_rag.store import LegalStore
from sentinel_core.legal_rag.vector_index import VectorHit, VectorIndex

__all__ = [
    "BgeM3ColbertReranker",
    "DEFAULT_ST_MODEL",
    "EmbeddingMismatchError",
    "EmbeddingModelCard",
    "Embedder",
    "HashingColbertReranker",
    "HashingEmbedder",
    "Hit",
    "LegalRetriever",
    "LegalStore",
    "MissingColbertDependencyError",
    "MissingEmbeddingDependencyError",
    "NormChunk",
    "SentenceTransformerEmbedder",
    "VectorHit",
    "VectorIndex",
    "build_embedder",
    "build_reranker",
    "cosine",
    "ingest_file",
    "ingest_text",
    "maxsim",
    "pack_f32",
    "rerank_hits",
    "unpack_f32",
]
