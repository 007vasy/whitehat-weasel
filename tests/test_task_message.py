"""Unit tests for `whw.orchestrator.build_task_message`.

Verifies the Docker tools-image input is propagated all the way into the agent's
prompt: the image name appears, the mount path appears, and an example `docker run`
invocation is shown. Without these, the system prompt's Bash hint is too abstract
for the agent to act on (intent-review Gaps F/G/H).
"""

from __future__ import annotations

import os

os.environ.setdefault("WHW_EMBEDDING_BACKEND", "noop")

from whw.orchestrator import build_task_message


_COMMON = dict(
    run_id="run-1",
    repo_id="arvo-1065",
    commit="vul",
    mode="live",
    eval_commit_ts=None,
    function_qn="x.y.foo",
    name="foo",
    file_path="src/x.c",
    line_start=10,
    line_end=20,
    callgraph_text="(none)",
    source_slice="    10  int foo(int a) { return a; }",
)


def test_build_task_message_without_tools_image_omits_static_section():
    msg = build_task_message(
        **_COMMON, tools_image=None, abs_repo_root=None,
        user_context_excerpt=None,
    )
    assert "STATIC ANALYSIS TOOLS" not in msg
    assert "docker run" not in msg
    # The header must NOT carry a tools_image line when none was provided.
    assert "tools_image" not in msg
    # Core sections are still present.
    assert "TARGET FUNCTION: foo" in msg
    assert "SOURCE (with line numbers):" in msg


def test_build_task_message_with_tools_image_and_mount_includes_full_invocation():
    msg = build_task_message(
        **_COMMON,
        tools_image="whw/c-cpp-statics:latest",
        abs_repo_root="/abs/path/to/src-vul",
        user_context_excerpt=None,
    )
    assert "STATIC ANALYSIS TOOLS" in msg
    assert "image:       whw/c-cpp-statics:latest" in msg
    assert "/abs/path/to/src-vul" in msg
    # Example invocation must use the exact image AND the abs_repo_root we supplied.
    assert "docker run --rm -v /abs/path/to/src-vul:/src:ro whw/c-cpp-statics:latest" in msg
    # And reference the target file path so the agent knows which file to point the tool at.
    assert "/src/src/x.c" in msg
    # Plus an explicit instruction to use tool_evidence.
    assert "tool_evidence" in msg


def test_build_task_message_with_tools_image_but_no_mount_explains_fallback():
    msg = build_task_message(
        **_COMMON,
        tools_image="whw/c-cpp-statics:latest",
        abs_repo_root=None,
        user_context_excerpt=None,
    )
    assert "tools_image was set" in msg
    assert "host mount path is unknown" in msg
    assert "source-only analysis" in msg
    # No invocation example because we don't have a mount path to fill in.
    assert "docker run" not in msg


def test_build_task_message_with_user_context_excerpt_appears_in_message():
    msg = build_task_message(
        **_COMMON, tools_image=None, abs_repo_root=None,
        user_context_excerpt="prod note: db at db.prod, secret in vault path /api",
    )
    assert "USER CONTEXT (excerpt):" in msg
    assert "db at db.prod" in msg
