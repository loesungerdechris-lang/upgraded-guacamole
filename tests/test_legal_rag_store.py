from __future__ import annotations

from pathlib import Path

import pytest

from sentinel_core.legal_rag.embedder import EmbeddingMismatchError, HashingEmbedder
from sentinel_core.legal_rag.factory import build_embedder
from sentinel_core.legal_rag.ingest import ingest_file
from sentinel_core.legal_rag.retrieve import LegalRetriever
from sentinel_core.legal_rag.store import LegalStore

ROOT = Path(__file__).resolve().parents[1]
VWGO = ROOT / "corpus" / "legal" / "vwgo_seed.md"
THUER = ROOT / "corpus" / "legal" / "thueruig_seed.md"


@pytest.fixture
def store(tmp_path: Path) -> LegalStore:
    return LegalStore(tmp_path / "legal_core.sqlite")


def _ingest(store: LegalStore) -> HashingEmbedder:
    enc = HashingEmbedder(dim=64)
    ingest_file(
        VWGO,
        law="VwGO",
        source_url="https://www.gesetze-im-internet.de/vwgo/",
        source_name="Gesetze im Internet",
        store=store,
        embedder=enc,
    )
    ingest_file(
        THUER,
        law="ThürUIG",
        source_url="https://landesrecht.thueringen.de/",
        source_name="Landesrecht Thüringen",
        store=store,
        embedder=enc,
    )
    return enc


def test_ingest_seeds_and_exact_paragraph(store: LegalStore) -> None:
    _ingest(store)
    assert store.count() >= 8
    hits = store.get_exact("VwGO", "§ 74", "Abs. 1")
    assert hits
    assert "eines Monats" in hits[0].text
    assert hits[0].content_hash.startswith("sha256:")
    card = store.model_card()
    assert card is not None
    assert card.family == "hashing"


def test_rejects_second_embedding_space(store: LegalStore) -> None:
    _ingest(store)
    other = HashingEmbedder(dim=32)
    with pytest.raises(EmbeddingMismatchError):
        ingest_file(
            VWGO,
            law="VwGO",
            source_url="https://www.gesetze-im-internet.de/vwgo/",
            source_name="Gesetze im Internet",
            store=store,
            embedder=other,
        )


def test_citation_pack_finds_frist(store: LegalStore) -> None:
    enc = _ingest(store)
    pack = LegalRetriever(store, enc).citation_pack(
        "Frist Verpflichtungsklage nach Widerspruchsbescheid § 74 VwGO",
        law="VwGO",
    )
    articles = {hit["article"] for hit in pack["hits"]}
    assert any(item.startswith("§ 74") for item in articles)
    assert pack["hits"][0]["source_url"]


def test_factory_knows_bge_m3() -> None:
    enc = build_embedder("bge-m3")
    assert enc.card.name == "BAAI/bge-m3"
    assert enc.card.dim == 1024
