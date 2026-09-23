from __future__ import annotations

from pathlib import Path

from sentinel_core.legal_rag.court import court_pack, load_case

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "cases" / "vg_weimar_fischerhuette.json"


def test_vg_weimar_anchor_has_public_seat() -> None:
    case = load_case(CASE)
    assert case["court"]["name"] == "Verwaltungsgericht Weimar"
    assert "99425 Weimar" in case["court"]["address"]
    assert "Ilm-Kreis" in case["court"]["district_includes"]
    assert case["evidence_status"]["aktenzeichen"] is None
    assert case["evidence_status"]["filed"] is False
    assert case["deadlines"]["pzu_date"] is None


def test_court_pack_binds_citations() -> None:
    pack = court_pack(
        {"hits": [{"law": "VwGO", "article": "§ 74"}]},
        case_path=CASE,
    )
    assert pack["court"]["name"] == "Verwaltungsgericht Weimar"
    assert pack["citations"][0]["article"] == "§ 74"
    assert pack["deadlines"]["pzu_status"] == "unbekannt"
