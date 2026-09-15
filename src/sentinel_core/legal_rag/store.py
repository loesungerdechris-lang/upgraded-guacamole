"""SQLite store for norm chunks, FTS5 and one embedding space."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from sentinel_core.legal_rag.embedder import EmbeddingMismatchError, EmbeddingModelCard
from sentinel_core.legal_rag.models import NormChunk

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chunks (
    chunk_id TEXT PRIMARY KEY,
    law TEXT NOT NULL,
    article TEXT NOT NULL,
    absatz TEXT,
    title TEXT,
    text TEXT NOT NULL,
    source_url TEXT NOT NULL,
    source_name TEXT NOT NULL,
    retrieved_at TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    language TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    model_card TEXT,
    embedding BLOB
);
CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
    chunk_id UNINDEXED,
    law,
    article,
    absatz,
    title,
    text,
    content='chunks',
    content_rowid='rowid'
);
CREATE TRIGGER IF NOT EXISTS chunks_ai AFTER INSERT ON chunks BEGIN
  INSERT INTO chunks_fts(rowid, chunk_id, law, article, absatz, title, text)
  VALUES (new.rowid, new.chunk_id, new.law, new.article, new.absatz, new.title, new.text);
END;
CREATE TRIGGER IF NOT EXISTS chunks_ad AFTER DELETE ON chunks BEGIN
  INSERT INTO chunks_fts(chunks_fts, rowid, chunk_id, law, article, absatz, title, text)
  VALUES ('delete', old.rowid, old.chunk_id, old.law, old.article, old.absatz, old.title, old.text);
END;
CREATE TRIGGER IF NOT EXISTS chunks_au AFTER UPDATE ON chunks BEGIN
  INSERT INTO chunks_fts(chunks_fts, rowid, chunk_id, law, article, absatz, title, text)
  VALUES ('delete', old.rowid, old.chunk_id, old.law, old.article, old.absatz, old.title, old.text);
  INSERT INTO chunks_fts(rowid, chunk_id, law, article, absatz, title, text)
  VALUES (new.rowid, new.chunk_id, new.law, new.article, new.absatz, new.title, new.text);
END;
"""


class LegalStore:
    """One SQLite file = one model card. Mixed embedding spaces are rejected."""

    def __init__(self, path: str | Path = "data/legal_core.sqlite"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def model_card(self) -> EmbeddingModelCard | None:
        row = self.conn.execute(
            "SELECT value FROM meta WHERE key = 'model_card'"
        ).fetchone()
        if row is None:
            return None
        data = json.loads(row["value"])
        return EmbeddingModelCard(**data)

    def set_model_card(self, card: EmbeddingModelCard) -> None:
        existing = self.model_card()
        if existing is not None:
            existing.assert_compatible(card)
        payload = {
            "name": card.name,
            "family": card.family,
            "dim": card.dim,
            "normalize": card.normalize,
            "query_prefix": card.query_prefix,
            "passage_prefix": card.passage_prefix,
            "revision": card.revision,
        }
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES('model_card', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (json.dumps(payload, ensure_ascii=False, sort_keys=True),),
        )
        self.conn.commit()

    def upsert(
        self,
        chunk: NormChunk,
        embedding: bytes | None = None,
        card: EmbeddingModelCard | None = None,
    ) -> None:
        if embedding is not None:
            if card is None:
                raise EmbeddingMismatchError("embedding blob requires a model card")
            self.set_model_card(card)
            stored = self.model_card()
            assert stored is not None
            stored.assert_compatible(card)
            expected = stored.dim * 4
            if len(embedding) != expected:
                raise EmbeddingMismatchError(
                    f"embedding bytes {len(embedding)} != {expected} for dim {stored.dim}"
                )
        d = chunk.to_dict()
        self.conn.execute(
            """
            INSERT INTO chunks (
                chunk_id, law, article, absatz, title, text, source_url,
                source_name, retrieved_at, content_hash, language, metadata_json,
                model_card, embedding
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(chunk_id) DO UPDATE SET
                text=excluded.text,
                content_hash=excluded.content_hash,
                retrieved_at=excluded.retrieved_at,
                embedding=COALESCE(excluded.embedding, chunks.embedding),
                model_card=COALESCE(excluded.model_card, chunks.model_card)
            """,
            (
                d["chunk_id"],
                d["law"],
                d["article"],
                d["absatz"],
                d["title"],
                d["text"],
                d["source_url"],
                d["source_name"],
                d["retrieved_at"],
                d["content_hash"],
                d["language"],
                json.dumps(d["metadata"], ensure_ascii=False),
                card.fingerprint() if card else None,
                embedding,
            ),
        )
        self.conn.commit()

    def get_exact(
        self, law: str, article: str, absatz: str | None = None
    ) -> list[NormChunk]:
        needle = article.replace(" ", "")
        query = (
            "SELECT * FROM chunks WHERE law = ? "
            "AND replace(article, ' ', '') LIKE ?"
        )
        args: list[object] = [law, f"%{needle}%"]
        if absatz:
            query += " AND absatz = ?"
            args.append(absatz)
        return [self._row(r) for r in self.conn.execute(query, args)]

    def bm25(self, query: str, k: int = 8) -> list[tuple[NormChunk, float]]:
        fts = _fts_query(query)
        if not fts:
            return []
        rows = self.conn.execute(
            """
            SELECT chunks.*, bm25(chunks_fts) AS rank
            FROM chunks_fts
            JOIN chunks ON chunks.chunk_id = chunks_fts.chunk_id
            WHERE chunks_fts MATCH ?
            ORDER BY rank
            LIMIT ?
            """,
            (fts, k),
        )
        out = []
        for row in rows:
            score = 1.0 / (1.0 + max(float(row["rank"]), 0.0))
            out.append((self._row(row), score))
        return out

    def all_with_embeddings(self) -> list[tuple[NormChunk, bytes]]:
        rows = self.conn.execute("SELECT * FROM chunks WHERE embedding IS NOT NULL")
        return [(self._row(r), r["embedding"]) for r in rows]

    def count(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) AS n FROM chunks").fetchone()
        return int(row["n"])

    def close(self) -> None:
        self.conn.close()

    def _row(self, row: sqlite3.Row) -> NormChunk:
        meta = json.loads(row["metadata_json"] or "{}")
        return NormChunk(
            chunk_id=row["chunk_id"],
            law=row["law"],
            article=row["article"],
            absatz=row["absatz"],
            title=row["title"] or "",
            text=row["text"],
            source_url=row["source_url"],
            source_name=row["source_name"],
            retrieved_at=row["retrieved_at"],
            content_hash=row["content_hash"],
            language=row["language"],
            metadata=meta,
        )


def _fts_query(query: str) -> str:
    tokens = []
    for raw in query.replace("§", " ").split():
        tok = "".join(ch for ch in raw if ch.isalnum())
        if tok:
            tokens.append(tok)
    return " OR ".join(tokens)
