"""Data objects for Legal-Core retrieval."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class NormChunk:
    chunk_id: str
    law: str
    article: str
    absatz: str | None
    title: str
    text: str
    source_url: str
    source_name: str
    retrieved_at: str
    content_hash: str
    language: str = "de"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def passage_text(self) -> str:
        header = f"{self.law} {self.article}"
        if self.absatz:
            header = f"{header} {self.absatz}"
        return f"{header}\n{self.text}"


@dataclass(frozen=True)
class Hit:
    chunk: NormChunk
    score: float
    ranker: str
    reason: str
