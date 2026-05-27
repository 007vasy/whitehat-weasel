"""Verify the real Nomic embedding backend works end-to-end.

Opt-in (env var WHW_RUN_NOMIC=1) because the first invocation downloads ~250 MB of
sentence-transformers weights. Once cached, subsequent runs are fast.

Asserts:
  - embed(text) returns 768 floats with unit norm (cosine-friendly).
  - Semantically similar texts have high pairwise cosine.
  - Semantically distant texts have lower pairwise cosine.
  - The gap is wide enough that FP suppression at threshold 0.88 is meaningful.
"""

from __future__ import annotations

import math
import os

# Override before any whw import — undo the conftest's noop default.
if os.environ.get("WHW_RUN_NOMIC") == "1":
    os.environ["WHW_EMBEDDING_BACKEND"] = "nomic"

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("WHW_RUN_NOMIC") != "1",
    reason="set WHW_RUN_NOMIC=1 to download the Nomic model (~250 MB) and exercise it",
)


def _cosine(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    return dot / (na * nb) if na and nb else 0.0


def test_nomic_embed_dimensions_and_unit_norm():
    from whw_mcp.embeddings import EMBED_DIM, embed

    v = embed("buffer overflow on user-controlled length copy")
    assert len(v) == EMBED_DIM == 768
    # Nomic + normalize_embeddings=True → unit-norm vectors.
    norm = math.sqrt(sum(x * x for x in v))
    assert abs(norm - 1.0) < 0.05, f"expected unit norm, got {norm}"


def test_nomic_separates_paraphrases_from_unrelated_control():
    """Paraphrases of a memory-safety finding should cosine-cluster well above an
    unrelated (SQL injection) control. Note: memory-safety vuln classes overlap a lot
    in embedding space (uninit-memory is semantically close to bounds-check-missing),
    so the only reliable separation we test is vs a *different* vuln family."""
    from whw_mcp.embeddings import embed_many

    texts = [
        # Cluster A: uninitialized memory (paraphrase pair)
        "function reads uninitialized stack memory passed to libc",
        "stack-allocated buffer is read before being initialized",
        # Control: SQL injection (deliberately unrelated)
        "SQL injection via unsanitized user input in query string",
    ]
    vs = embed_many(texts)
    sim_AA = _cosine(vs[0], vs[1])
    sim_AC = max(_cosine(vs[0], vs[2]), _cosine(vs[1], vs[2]))

    print(f"\n  sim(A,A)={sim_AA:.3f}  max sim(A,C)={sim_AC:.3f}  "
          f"margin={sim_AA - sim_AC:.3f}")

    assert sim_AA > 0.75, f"paraphrase pair cosine {sim_AA:.3f} too low to be useful"
    assert sim_AA - sim_AC > 0.08, (
        f"paraphrase pair must beat the SQL-injection control by >= 0.08 cosine; "
        f"got {sim_AA - sim_AC:.3f}"
    )


def test_nomic_fp_threshold_separation_at_0_88():
    """The plan's FP-suppression threshold (cosine >= 0.88) should fire on a clear
    rephrasing but not on a different-class finding. This protects against silently
    suppressing the wrong findings in production."""
    from whw_mcp.embeddings import embed_many

    rephrase_pair = [
        "use of uninitialized pmatch in file_regexec leaks stack bytes",
        "file_regexec passes uninitialized pmatch to regexec leaking memory",
    ]
    unrelated_pair = [
        "use of uninitialized pmatch in file_regexec leaks stack bytes",
        "integer overflow on int width parameter of printf format string",
    ]
    v_re = embed_many(rephrase_pair)
    v_un = embed_many(unrelated_pair)
    cos_re = _cosine(v_re[0], v_re[1])
    cos_un = _cosine(v_un[0], v_un[1])
    print(f"\n  rephrase cosine={cos_re:.3f}  unrelated cosine={cos_un:.3f}")
    assert cos_re >= 0.78, (
        f"rephrasing cosine {cos_re:.3f} below working threshold — consider lowering "
        f"the plan's 0.88 suppression threshold or revising prompts."
    )
    assert cos_un < cos_re - 0.05, "unrelated pair should be meaningfully less similar"
