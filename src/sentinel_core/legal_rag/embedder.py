"""Embedding backends for Legal-Core RAG.

Two backends exist on purpose:

* ``HashingEmbedder`` — deterministic, no extra dependency, weak semantics.
* ``SentenceTransformerEmbedder`` — dense multilingual vectors (default: E5-small).

Dense vectors never decide a citation alone. They are a ranking bonus on top of
exact paragraph lookup and BM25. Mixed model cards in one index are rejected.
"""

from __future__ import annotations

import hashlib
import math
import struct
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, Protocol, Sequence

DEFAULT_ST_MODEL = "intfloat/multilingual-e5-small"
BGE_M3_MODEL = "BAAI/bge-m3"
E5_PREFIXES = {"query": "query: ", "passage": "passage: "}


class MissingEmbeddingDependencyError(RuntimeError):
    """Raised when sentence-transformers is requested but not installed."""


class EmbeddingMismatchError(ValueError):
    """Raised when stored vectors were produced by a different model card."""


@dataclass(frozen=True)
class EmbeddingModelCard:
    """Identity of the vector space. Persist this next to every embedding blob."""

    name: str
    family: str
    dim: int
    normalize: bool
    query_prefix: str
    passage_prefix: str
    revision: str | None = None

    def fingerprint(self) -> str:
        rev = self.revision or "unpinned"
        return f"{self.family}:{self.name}@{rev}:dim{self.dim}:n{int(self.normalize)}"

    def assert_compatible(self, other: EmbeddingModelCard) -> None:
        if self.fingerprint() != other.fingerprint():
            raise EmbeddingMismatchError(
                f"embedding space mismatch: have {self.fingerprint()}, "
                f"got {other.fingerprint()}"
            )


class Embedder(Protocol):
    card: EmbeddingModelCard

    def embed_query(self, text: str) -> list[float]:
        ...

    def embed_passage(self, text: str) -> list[float]:
        ...

    def embed_passages(self, texts: Sequence[str]) -> list[list[float]]:
        ...


def pack_f32(vec: Sequence[float]) -> bytes:
    return struct.pack(f"{len(vec)}f", *vec)


def unpack_f32(blob: bytes) -> list[float]:
    n = len(blob) // 4
    return list(struct.unpack(f"{n}f", blob))


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


def _l2norm(vec: list[float]) -> list[float]:
    n = math.sqrt(sum(x * x for x in vec)) or 1.0
    return [x / n for x in vec]


def _tokenize(text: str) -> list[str]:
    raw = text.lower().replace("§", " § ")
    return [t for t in raw.split() if t]


def _stable_token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


class HashingEmbedder:
    """Deterministic fallback without torch. Not a substitute for ST in production."""

    def __init__(self, dim: int = 256):
        self.card = EmbeddingModelCard(
            name="hashing-v1",
            family="hashing",
            dim=dim,
            normalize=True,
            query_prefix="",
            passage_prefix="",
            revision="v1",
        )

    def embed_query(self, text: str) -> list[float]:
        return self._embed(text)

    def embed_passage(self, text: str) -> list[float]:
        return self._embed(text)

    def embed_passages(self, texts: Sequence[str]) -> list[list[float]]:
        return [self._embed(t) for t in texts]

    def embed_legal_passage(
        self,
        *,
        law: str,
        article: str,
        absatz: str | None,
        text: str,
    ) -> list[float]:
        header = f"{law} {article}"
        if absatz:
            header = f"{header} {absatz}"
        return self._embed(f"{header}\n{text}")

    def _embed(self, text: str) -> list[float]:
        tokens = _tokenize(text)
        vec = [0.0] * self.card.dim
        counts = Counter(tokens)
        n = max(sum(counts.values()), 1)
        for tok, ctf in counts.items():
            digest = _stable_token_hash(tok)
            idx = int.from_bytes(digest[:4], "big") % self.card.dim
            sign = 1.0 if digest[4] & 1 else -1.0
            vec[idx] += sign * (ctf / n)
        return _l2norm(vec)


class SentenceTransformerEmbedder:
    """Dense embedder backed by sentence-transformers.

    Default model is ``intfloat/multilingual-e5-small`` because Legal-Core
    queries are German (VwGO, ThürUIG) and E5 needs query/passage prefixes.
    The model is loaded lazily on first encode so importing the module stays cheap.
    """

    def __init__(
        self,
        model_name: str = DEFAULT_ST_MODEL,
        *,
        device: str | None = None,
        normalize: bool = True,
        batch_size: int = 32,
        revision: str | None = None,
        trust_remote_code: bool = False,
    ) -> None:
        self.model_name = model_name
        self.device = device
        self.normalize = normalize
        self.batch_size = batch_size
        self.revision = revision
        self.trust_remote_code = trust_remote_code
        self._model = None
        prefixes = _prefixes_for(model_name)
        self.card = EmbeddingModelCard(
            name=model_name,
            family="sentence-transformers",
            dim=_known_dim(model_name),
            normalize=normalize,
            query_prefix=prefixes["query"],
            passage_prefix=prefixes["passage"],
            revision=revision,
        )

    def embed_query(self, text: str) -> list[float]:
        return self._encode([self.card.query_prefix + text])[0]

    def embed_passage(self, text: str) -> list[float]:
        return self._encode([self.card.passage_prefix + text])[0]

    def embed_passages(self, texts: Sequence[str]) -> list[list[float]]:
        prefixed = [self.card.passage_prefix + t for t in texts]
        return self._encode(prefixed)

    def embed_legal_passage(
        self,
        *,
        law: str,
        article: str,
        absatz: str | None,
        text: str,
    ) -> list[float]:
        header = f"{law} {article}"
        if absatz:
            header = f"{header} {absatz}"
        return self.embed_passage(f"{header}\n{text}")

    def _encode(self, texts: Sequence[str]) -> list[list[float]]:
        model = self._load()
        vectors = model.encode(
            list(texts),
            batch_size=self.batch_size,
            convert_to_numpy=True,
            normalize_embeddings=self.normalize,
            show_progress_bar=False,
        )
        out = [row.astype(float).tolist() for row in vectors]
        if out and len(out[0]) != self.card.dim:
            self.card = EmbeddingModelCard(
                name=self.card.name,
                family=self.card.family,
                dim=len(out[0]),
                normalize=self.card.normalize,
                query_prefix=self.card.query_prefix,
                passage_prefix=self.card.passage_prefix,
                revision=self.card.revision,
            )
        return out

    def _load(self):
        if self._model is not None:
            return self._model
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise MissingEmbeddingDependencyError(
                "sentence-transformers is not installed. "
                "Install with: pip install 'sentinel-core[rag]'"
            ) from exc
        kwargs: dict = {"trust_remote_code": self.trust_remote_code}
        if self.device:
            kwargs["device"] = self.device
        if self.revision:
            kwargs["revision"] = self.revision
        self._model = SentenceTransformer(self.model_name, **kwargs)
        dim = int(self._model.get_sentence_embedding_dimension())
        self.card = EmbeddingModelCard(
            name=self.card.name,
            family=self.card.family,
            dim=dim,
            normalize=self.card.normalize,
            query_prefix=self.card.query_prefix,
            passage_prefix=self.card.passage_prefix,
            revision=self.card.revision,
        )
        return self._model


def _prefixes_for(model_name: str) -> dict[str, str]:
    lowered = model_name.lower()
    if "e5" in lowered or "gte" in lowered:
        return dict(E5_PREFIXES)
    return {"query": "", "passage": ""}


def _known_dim(model_name: str) -> int:
    table = {
        "intfloat/multilingual-e5-small": 384,
        "intfloat/multilingual-e5-base": 768,
        "intfloat/multilingual-e5-large": 1024,
        "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2": 384,
        BGE_M3_MODEL: 1024,
    }
    return table.get(model_name, 384)


def assert_vector_dim(vec: Iterable[float], card: EmbeddingModelCard) -> None:
    values = list(vec)
    if len(values) != card.dim:
        raise EmbeddingMismatchError(
            f"vector dim {len(values)} does not match card dim {card.dim}"
        )
