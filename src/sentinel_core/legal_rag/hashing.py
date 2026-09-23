"""Content hashes for Legal-Core chunks."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def sha256_prefixed(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonicalize_json(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def chunk_hash(law: str, article: str, absatz: str | None, text: str) -> str:
    payload = canonicalize_json(
        {"absatz": absatz or "", "article": article, "law": law, "text": text}
    )
    return sha256_prefixed(payload)
