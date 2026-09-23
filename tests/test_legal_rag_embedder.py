from __future__ import annotations

import math
from types import SimpleNamespace

import pytest

from sentinel_core.legal_rag.embedder import (
    EmbeddingMismatchError,
    EmbeddingModelCard,
    HashingEmbedder,
    SentenceTransformerEmbedder,
    cosine,
    pack_f32,
    unpack_f32,
)
from sentinel_core.legal_rag.factory import build_embedder
from sentinel_core.legal_rag.vector_index import VectorIndex


def test_hashing_embedder_is_normalized_and_stable() -> None:
    enc = HashingEmbedder(dim=64)
    a = enc.embed_query("§ 74 VwGO Frist Verpflichtungsklage")
    b = enc.embed_query("§ 74 VwGO Frist Verpflichtungsklage")
    assert a == b
    assert len(a) == 64
    assert math.isclose(math.sqrt(sum(x * x for x in a)), 1.0, rel_tol=1e-6)


def test_cosine_identical_is_one() -> None:
    v = [0.0, 1.0, 0.0]
    assert cosine(v, v) == pytest.approx(1.0)


def test_pack_roundtrip() -> None:
    src = [0.25, -0.5, 0.75]
    assert unpack_f32(pack_f32(src)) == pytest.approx(src)


def test_model_card_rejects_mixed_spaces() -> None:
    a = EmbeddingModelCard(
        name="intfloat/multilingual-e5-small",
        family="sentence-transformers",
        dim=384,
        normalize=True,
        query_prefix="query: ",
        passage_prefix="passage: ",
        revision="abc",
    )
    b = EmbeddingModelCard(
        name="intfloat/multilingual-e5-small",
        family="sentence-transformers",
        dim=384,
        normalize=True,
        query_prefix="query: ",
        passage_prefix="passage: ",
        revision="def",
    )
    with pytest.raises(EmbeddingMismatchError):
        a.assert_compatible(b)


def test_factory_hashing() -> None:
    enc = build_embedder("hashing", dim=32)
    assert enc.card.family == "hashing"
    assert len(enc.embed_passage("ThürUIG § 3")) == 32


def test_factory_rejects_unknown() -> None:
    with pytest.raises(ValueError):
        build_embedder("openai")


def test_vector_index_ranks_closer_text_higher() -> None:
    enc = HashingEmbedder(dim=128)
    index = VectorIndex(enc.card)
    index.add_passage("vwgo-74", "§ 74 VwGO Klagefrist ein Monat nach Zustellung", enc)
    index.add_passage("thueruig-3", "ThürUIG Anspruch auf Umweltinformationen", enc)
    hits = index.search_query("Klagefrist nach Zustellung des Widerspruchsbescheids", enc, k=2)
    assert hits
    assert hits[0].chunk_id == "vwgo-74"


class _FakeSTModel:
    def __init__(self, dim: int = 8):
        self.dim = dim

    def get_sentence_embedding_dimension(self) -> int:
        return self.dim

    def encode(self, texts, **kwargs):
        import array

        rows = []
        for text in texts:
            seed = sum(ord(ch) for ch in text) or 1
            vec = [(seed + i) % 13 / 13.0 for i in range(self.dim)]
            rows.append(_FakeArray(vec))
        return rows


class _FakeArray(list):
    def astype(self, _typ):
        return self


def test_sentence_transformer_uses_e5_prefixes(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[list[str]] = []

    class Recording(_FakeSTModel):
        def encode(self, texts, **kwargs):
            captured.append(list(texts))
            return super().encode(texts, **kwargs)

    enc = SentenceTransformerEmbedder("intfloat/multilingual-e5-small")
    enc._model = Recording(dim=8)
    enc.card = EmbeddingModelCard(
        name=enc.card.name,
        family=enc.card.family,
        dim=8,
        normalize=True,
        query_prefix="query: ",
        passage_prefix="passage: ",
        revision=None,
    )
    enc.embed_query("Frist § 74 VwGO")
    enc.embed_passage("Die Klage ist innerhalb eines Monats zu erheben.")
    assert captured[0][0].startswith("query: ")
    assert captured[1][0].startswith("passage: ")
    vec = enc.embed_legal_passage(
        law="VwGO", article="§ 74", absatz="Abs. 1", text="Die Frist beträgt einen Monat."
    )
    assert len(vec) == 8
