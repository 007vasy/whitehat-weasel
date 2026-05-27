"""Embedding backend abstraction.

Two backends, selected by `WHW_EMBEDDING_BACKEND` env:

  - "nomic": sentence-transformers + nomic-ai/nomic-embed-text-v1.5 (~250 MB, 768-dim).
    Matches the family cbm uses (Nomic), so Function-embedding ⇄ Finding-embedding cosine
    is meaningful out of the box.

  - "noop": returns a deterministic zero vector. Lets the MCP run without downloading the
    model in dev/test; vector queries return nothing (degrades gracefully).

Cached process-wide via lru_cache; first encode loads weights, subsequent calls are fast.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Sequence

from whw.config import get_settings

EMBED_DIM = 768


def embed(text: str) -> list[float]:
    """Return a 768-dim list-of-float embedding suitable for Neo4j vector index storage."""
    if not text:
        return [0.0] * EMBED_DIM
    backend = get_settings().whw_embedding_backend.lower().strip()
    if backend == "noop":
        return [0.0] * EMBED_DIM
    if backend == "nomic":
        return _nomic_embed(text)
    raise ValueError(f"unknown WHW_EMBEDDING_BACKEND: {backend!r}")


def embed_many(texts: Sequence[str]) -> list[list[float]]:
    """Batch embedding; the model is loaded once and reused."""
    if not texts:
        return []
    backend = get_settings().whw_embedding_backend.lower().strip()
    if backend == "noop":
        return [[0.0] * EMBED_DIM for _ in texts]
    if backend == "nomic":
        model = _load_nomic_model()
        # nomic-embed-text-v1.5 expects task-prefix-style inputs. For finding/asset text
        # we treat them as documents.
        prefixed = [f"search_document: {t}" if t else "search_document: (empty)" for t in texts]
        vecs = model.encode(prefixed, convert_to_numpy=True, normalize_embeddings=True)
        return [list(map(float, v)) for v in vecs]
    raise ValueError(f"unknown WHW_EMBEDDING_BACKEND: {backend!r}")


def _nomic_embed(text: str) -> list[float]:
    return embed_many([text])[0]


@lru_cache(maxsize=1)
def _load_nomic_model():
    # Lazy: importing sentence_transformers at module-load time would pull torch even
    # when backend=noop.
    from sentence_transformers import SentenceTransformer  # noqa: PLC0415

    s = get_settings()
    return SentenceTransformer(s.whw_nomic_model, trust_remote_code=True)
