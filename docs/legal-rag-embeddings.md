# Legal-Core Embeddings

Dense retrieval is a ranking bonus, never the citation authority.

## Backends

| Backend | Extra | Use |
| --- | --- | --- |
| `HashingEmbedder` | none | tests, offline bootstrap |
| `SentenceTransformerEmbedder` | `sentinel-core[rag]` | production ranking |

Default dense model: `intfloat/multilingual-e5-small` (384-d, DE/EN).
E5 queries are prefixed with `query: `, passages with `passage: `.

## Install

```bash
pip install -e ".[rag]"
```

First run downloads the model from Hugging Face into the local cache.
Pin a `revision` in production and store `EmbeddingModelCard.fingerprint()` next to every vector blob.

## Usage

```python
from sentinel_core.legal_rag import SentenceTransformerEmbedder, build_embedder
from sentinel_core.legal_rag.vector_index import VectorIndex

enc = build_embedder("sentence-transformers")
index = VectorIndex(enc.card)
index.add(
    "vwgo-74-1",
    enc.embed_legal_passage(
        law="VwGO",
        article="§ 74",
        absatz="Abs. 1",
        text="Die Frist für die Erhebung der Klage beträgt einen Monat.",
    ),
    enc.card,
)
hits = index.search_query("Klagefrist nach Widerspruchsbescheid", enc)
```

## Rules

1. Do not mix model cards in one SQLite / memory index.
2. Re-embed the corpus after any model or revision change.
3. Exact `§`-lookup and BM25 remain mandatory; cosine similarity cannot invent a paragraph.
