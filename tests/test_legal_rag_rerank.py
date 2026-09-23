from __future__ import annotations

from sentinel_core.legal_rag.factory import build_reranker
from sentinel_core.legal_rag.models import Hit, NormChunk
from sentinel_core.legal_rag.rerank import HashingColbertReranker, maxsim, rerank_hits


def _chunk(chunk_id: str, law: str, article: str, text: str) -> NormChunk:
    return NormChunk(
        chunk_id=chunk_id,
        law=law,
        article=article,
        absatz="Abs. 1",
        title="",
        text=text,
        source_url="https://example.invalid",
        source_name="test",
        retrieved_at="2026-09-15T00:00:00+00:00",
        content_hash="sha256:" + chunk_id,
    )


def test_maxsim_identical_tokens_is_high() -> None:
    vec = [[1.0, 0.0], [0.0, 1.0]]
    assert maxsim(vec, vec) == 1.0


def test_hashing_colbert_prefers_overlapping_legal_terms() -> None:
    rr = HashingColbertReranker(dim=16)
    query = "Frist Verpflichtungsklage nach Zustellung Widerspruchsbescheid"
    related = rr.score(
        query,
        "VwGO § 74 Abs. 1 Die Anfechtungsklage muss innerhalb eines Monats nach Zustellung des Widerspruchsbescheids erhoben werden.",
    )
    unrelated = rr.score(
        query,
        "ThürUIG § 3 Abs. 1 Jede Person hat Anspruch auf Zugang zu Umweltinformationen.",
    )
    assert related > unrelated


def test_rerank_hits_moves_better_passage_first() -> None:
    rr = HashingColbertReranker(dim=16)
    weak = Hit(
        _chunk("a", "ThürUIG", "§ 3", "Anspruch auf Zugang zu Umweltinformationen."),
        0.99,
        "bm25",
        "bm25",
    )
    strong = Hit(
        _chunk(
            "b",
            "VwGO",
            "§ 74",
            "Die Klage muss innerhalb eines Monats nach Zustellung des Widerspruchsbescheids erhoben werden.",
        ),
        0.10,
        "bm25",
        "bm25",
    )
    out = rerank_hits(
        "Klagefrist nach Zustellung des Widerspruchsbescheids",
        [weak, strong],
        rr,
        k=2,
        blend=1.0,
    )
    assert out[0].chunk.chunk_id == "b"
    assert out[0].ranker == "colbert"


def test_factory_none_and_hashing() -> None:
    assert build_reranker("none") is None
    rr = build_reranker("hashing")
    assert rr is not None
    assert rr.name == "colbert-hashing-v1"
