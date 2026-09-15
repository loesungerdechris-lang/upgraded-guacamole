# Legal-Core Embeddings and Store

Dense retrieval is a ranking bonus, never the citation authority.
One SQLite file holds one model card. Mixed spaces are rejected.

## Backends

| `build_embedder(...)` | Model | Dim | Use |
| --- | --- | --- | --- |
| `hashing` | hashing-v1 | 256 default | CI, no torch |
| `e5-small` | `intfloat/multilingual-e5-small` | 384 | Phase 1 default |
| `bge-m3` | `BAAI/bge-m3` | 1024 | Phase 2 dense only |

E5 queries use `query: `, passages `passage: `. BGE-M3 needs no prefix.
BGE-M3 Sparse and ColBERT are not stored in this phase.

## Decentral ingest (no Windows workstation)

```bash
pip install -e ".[dev]"
python scripts/legal_rag_cli.py --backend hashing ingest-seeds
python scripts/legal_rag_cli.py --backend hashing query \
  "Frist Verpflichtungsklage nach Widerspruchsbescheid § 74 VwGO" --law VwGO
```

With GPU / Hugging Face cache:

```bash
pip install -e ".[rag]"
python scripts/legal_rag_cli.py --backend e5-small ingest-seeds
```

Generated file: `data/legal_core.sqlite` (gitignored).
Seed sources live in `corpus/legal/` and cite Gesetze-im-Internet / Landesrecht Thüringen.

## Rules

1. Do not mix model cards in one SQLite file.
2. Re-embed after any model or revision change.
3. Exact `§`-lookup and BM25 remain mandatory.
4. Texts in the store are not the official BGBl./GVBl. publication.
