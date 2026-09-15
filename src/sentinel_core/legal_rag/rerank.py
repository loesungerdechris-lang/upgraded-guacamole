"""Optional ColBERT late-interaction rerank of hybrid candidates.

ColBERT vectors are not stored in SQLite. They are computed only for the
short candidate list (default Top-20). The core package imports without
FlagEmbedding or torch.
"""

from __future__ import annotations

import hashlib
import math
from typing import Protocol, Sequence

from sentinel_core.legal_rag.models import Hit, NormChunk

BGE_M3_MODEL = "BAAI/bge-m3"


class MissingColbertDependencyError(RuntimeError):
    """Raised when FlagEmbedding is requested but not installed."""


class Reranker(Protocol):
    name: str

    def score(self, query: str, passage: str) -> float:
        ...

    def score_many(self, query: str, passages: Sequence[str]) -> list[float]:
        ...


def l2norm(vec: list[float]) -> list[float]:
    n = math.sqrt(sum(x * x for x in vec)) or 1.0
    return [x / n for x in vec]


def maxsim(query_toks: Sequence[Sequence[float]], doc_toks: Sequence[Sequence[float]]) -> float:
    """ColBERT late interaction: mean over query tokens of max cosine vs doc tokens."""
    if not query_toks or not doc_toks:
        return 0.0
    total = 0.0
    for qv in query_toks:
        best = 0.0
        for dv in doc_toks:
            if len(qv) != len(dv):
                continue
            dot = sum(a * b for a, b in zip(qv, dv))
            if dot > best:
                best = dot
        total += best
    return total / len(query_toks)


def _tokenize(text: str) -> list[str]:
    raw = text.lower().replace("§", " § ")
    return [t for t in raw.split() if t]


def _token_vector(token: str, dim: int) -> list[float]:
    digest = hashlib.sha256(token.encode("utf-8")).digest()
    raw = [(digest[i % len(digest)] / 127.5) - 1.0 for i in range(dim)]
    return l2norm(raw)


class HashingColbertReranker:
    """Deterministic token-level MaxSim. Tests and CPU bootstrap only."""

    name = "colbert-hashing-v1"

    def __init__(self, dim: int = 32):
        self.dim = dim

    def encode(self, text: str) -> list[list[float]]:
        tokens = _tokenize(text)
        if not tokens:
            return [l2norm([1.0] + [0.0] * (self.dim - 1))]
        return [_token_vector(tok, self.dim) for tok in tokens]

    def score(self, query: str, passage: str) -> float:
        return maxsim(self.encode(query), self.encode(passage))

    def score_many(self, query: str, passages: Sequence[str]) -> list[float]:
        qv = self.encode(query)
        return [maxsim(qv, self.encode(p)) for p in passages]


class BgeM3ColbertReranker:
    """BGE-M3 multi-vector head via FlagEmbedding. Loaded lazily."""

    name = "colbert-bge-m3"

    def __init__(
        self,
        model_name: str = BGE_M3_MODEL,
        *,
        use_fp16: bool = True,
        device: str | None = None,
    ) -> None:
        self.model_name = model_name
        self.use_fp16 = use_fp16
        self.device = device
        self._model = None

    def score(self, query: str, passage: str) -> float:
        return self.score_many(query, [passage])[0]

    def score_many(self, query: str, passages: Sequence[str]) -> list[float]:
        model = self._load()
        q_out = model.encode(
            [query],
            return_dense=False,
            return_sparse=False,
            return_colbert_vecs=True,
        )
        p_out = model.encode(
            list(passages),
            return_dense=False,
            return_sparse=False,
            return_colbert_vecs=True,
        )
        q_vec = q_out["colbert_vecs"][0]
        scores: list[float] = []
        for p_vec in p_out["colbert_vecs"]:
            raw = model.colbert_score(q_vec, p_vec)
            scores.append(float(raw.item() if hasattr(raw, "item") else raw))
        return scores

    def _load(self):
        if self._model is not None:
            return self._model
        try:
            from FlagEmbedding import BGEM3FlagModel
        except ImportError as exc:
            raise MissingColbertDependencyError(
                "FlagEmbedding is not installed. "
                "Install with: pip install 'sentinel-core[colbert]'"
            ) from exc
        kwargs: dict = {"use_fp16": self.use_fp16}
        if self.device:
            kwargs["devices"] = self.device
        self._model = BGEM3FlagModel(self.model_name, **kwargs)
        return self._model


def rerank_hits(
    query: str,
    hits: Sequence[Hit],
    reranker: Reranker,
    *,
    k: int,
    blend: float = 0.7,
) -> list[Hit]:
    """Reorder candidates. ``blend`` is the weight of the ColBERT score."""
    if not hits:
        return []
    passages = [h.chunk.passage_text() for h in hits]
    colbert_scores = reranker.score_many(query, passages)
    blended: list[Hit] = []
    for hit, cscore in zip(hits, colbert_scores):
        score = (1.0 - blend) * hit.score + blend * cscore
        blended.append(
            Hit(
                chunk=hit.chunk,
                score=score,
                ranker="colbert",
                reason=f"{reranker.name} after {hit.ranker}",
            )
        )
    blended.sort(key=lambda h: h.score, reverse=True)
    return blended[:k]
