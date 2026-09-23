"""Bind a public court/case anchor to Legal-Core citation packs.

This module does not file a lawsuit and does not invent an Aktenzeichen.
It only attaches venue, filing form and deadline *rules* to retrieved norms.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DEFAULT_CASE = Path("cases/vg_weimar_fischerhuette.json")


def load_case(path: str | Path = DEFAULT_CASE) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("case file must be a JSON object")
    return data


def court_pack(
    citation: dict[str, Any] | None = None,
    *,
    case_path: str | Path = DEFAULT_CASE,
) -> dict[str, Any]:
    case = load_case(case_path)
    court = case.get("court", {})
    procedure = case.get("procedure", {})
    deadlines = case.get("deadlines", {})
    return {
        "court": {
            "name": court.get("name"),
            "address": court.get("address"),
            "source_url": court.get("source_url"),
            "district_includes": court.get("district_includes", []),
        },
        "procedure": procedure,
        "deadlines": {
            "rule": deadlines.get("rule"),
            "pzu_date": deadlines.get("pzu_date"),
            "pzu_status": deadlines.get("pzu_status"),
            "court_receipt_status": deadlines.get("court_receipt_status"),
            "warning": deadlines.get("warning"),
        },
        "evidence_status": case.get("evidence_status", {}),
        "citations": None if citation is None else citation.get("hits", []),
        "rule": (
            "Gericht und Fristregel sind angekoppelt. "
            "Ohne PZU-Datum und ohne Eingangsnachweis ist nichts eingereicht."
        ),
    }
