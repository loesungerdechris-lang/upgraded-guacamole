#!/usr/bin/env python3
"""Ingest and query Legal-Core without a local Windows workstation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sentinel_core.legal_rag.court import court_pack
from sentinel_core.legal_rag.factory import build_embedder, build_reranker
from sentinel_core.legal_rag.ingest import ingest_file
from sentinel_core.legal_rag.retrieve import LegalRetriever
from sentinel_core.legal_rag.store import LegalStore

SEEDS = (
    {
        "file": Path("corpus/legal/vwgo_seed.md"),
        "law": "VwGO",
        "source_url": "https://www.gesetze-im-internet.de/vwgo/",
        "source_name": "Gesetze im Internet (konsolidiert, nicht amtlich)",
    },
    {
        "file": Path("corpus/legal/thueruig_seed.md"),
        "law": "ThürUIG",
        "source_url": "https://landesrecht.thueringen.de/bsth/document/jlr-UIGTHrahmen",
        "source_name": "Landesrecht Thüringen (konsolidiert, nicht amtlich)",
    },
)

DEFAULT_CASE = Path("cases/vg_weimar_fischerhuette.json")


def main() -> None:
    parser = argparse.ArgumentParser(description="Legal-Core SQLite RAG")
    parser.add_argument("--db", default="data/legal_core.sqlite")
    parser.add_argument(
        "--backend",
        default="hashing",
        help="hashing | e5-small | bge-m3",
    )
    parser.add_argument(
        "--rerank",
        default="none",
        help="none | hashing | bge-m3",
    )
    parser.add_argument("--candidates", type=int, default=20)
    parser.add_argument("--case", default=str(DEFAULT_CASE))
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("ingest-seeds", help="Ingest VwGO + ThürUIG seed markdown")

    ing = sub.add_parser("ingest")
    ing.add_argument("file")
    ing.add_argument("--law", required=True)
    ing.add_argument("--source-url", required=True)
    ing.add_argument("--source-name", required=True)

    q = sub.add_parser("query")
    q.add_argument("question")
    q.add_argument("--law")
    q.add_argument("-k", type=int, default=6)
    q.add_argument("--with-court", action="store_true")

    sub.add_parser("court-pack", help="Print VG Weimar venue and deadline anchor")

    args = parser.parse_args()
    store = LegalStore(args.db)
    embedder = build_embedder(args.backend)

    if args.cmd == "ingest-seeds":
        total = 0
        for spec in SEEDS:
            n = ingest_file(
                spec["file"],
                law=spec["law"],
                source_url=spec["source_url"],
                source_name=spec["source_name"],
                store=store,
                embedder=embedder,
            )
            total += n
            print(json.dumps({"file": str(spec["file"]), "ingested": n}, ensure_ascii=False))
        card = store.model_card()
        print(
            json.dumps(
                {
                    "db": str(store.path),
                    "chunks": store.count(),
                    "ingested": total,
                    "model_card": None if card is None else card.fingerprint(),
                },
                ensure_ascii=False,
            )
        )
        return

    if args.cmd == "ingest":
        n = ingest_file(
            args.file,
            law=args.law,
            source_url=args.source_url,
            source_name=args.source_name,
            store=store,
            embedder=embedder,
        )
        print(json.dumps({"ingested": n, "chunks": store.count()}, ensure_ascii=False))
        return

    if args.cmd == "court-pack":
        print(json.dumps(court_pack(case_path=args.case), ensure_ascii=False, indent=2))
        return

    reranker = build_reranker(args.rerank)
    pack = LegalRetriever(
        store,
        embedder,
        reranker=reranker,
        candidate_n=args.candidates,
    ).citation_pack(args.question, law=args.law, k=args.k)
    if args.with_court:
        pack = court_pack(pack, case_path=args.case)
    print(json.dumps(pack, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
