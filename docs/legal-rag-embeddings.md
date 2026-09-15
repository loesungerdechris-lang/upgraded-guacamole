# Legal-Core Embeddings, Store, Rerank

Dense retrieval is a ranking bonus, never the citation authority.
One SQLite file holds one model card. Mixed spaces are rejected.
ColBERT vectors are **not** stored. They are computed only for the candidate shortlist.

## Backends

| `build_embedder(...)` | Model | Dim | Use |
| --- | --- | --- | --- |
| `hashing` | hashing-v1 | 256 default | CI, no torch |
| `e5-small` | `intfloat/multilingual-e5-small` | 384 | Phase 1 default |
| `bge-m3` | `BAAI/bge-m3` | 1024 | Phase 2 dense only |

| `build_reranker(...)` | Implementation | Use |
| --- | --- | --- |
| `none` | off | default |
| `hashing` | token MaxSim | tests |
| `bge-m3` | FlagEmbedding multi-vector | Phase 3, Top-20 |

## Pipeline

1. Exact `§` lookup
2. SQLite FTS5 / BM25
3. Dense cosine (optional)
4. ColBERT MaxSim on `candidate_n` (default 20) → top `k`

## Decentral commands

```bash
pip install -e ".[dev]"
python scripts/legal_rag_cli.py --backend hashing ingest-seeds
python scripts/legal_rag_cli.py --backend hashing --rerank hashing query \
  "Frist Verpflichtungsklage nach Widerspruchsbescheid § 74 VwGO" --law VwGO
```

Production ColBERT (GPU / large RAM, not Windows-required):

```bash
pip install -e ".[rag,colbert]"
python scripts/legal_rag_cli.py --backend bge-m3 --rerank bge-m3 query \
  "Welche Frist folgt aus diesem Widerspruchsbescheid?" --law VwGO
```

## Rules

1. Do not mix model cards in one SQLite file.
2. Re-embed after any model or revision change.
3. Exact `§`-lookup and BM25 remain mandatory.
4. ColBERT may reorder, it may not invent a paragraph.
5. Texts in the store are not the official BGBl./GVBl. publication.
