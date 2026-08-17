# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Adversarial tests for bounded large-file patch hunks."""
import hashlib
import os
from pathlib import Path
from unittest.mock import patch

import pytest

import cve_agent.openai_tools as openai_tools
from cve_agent.openai_deadline import SessionDeadline
from cve_agent.openai_loop import JSONLTranscript
from cve_agent.openai_tools import (
    MAX_MODEL_RESULT_BYTES,
    MAX_PATCH_CHANGED_LINES,
    MAX_PATCH_CONTEXT_BYTES,
    MAX_PATCH_DIFF_BYTES,
    MAX_PATCH_HUNKS,
    MAX_WRITE_BYTES,
    FileToolLimits,
    FileToolRuntime,
    openai_tool_schemas,
)


@pytest.fixture
def patch_roots(tmp_path):
    workspace = tmp_path / "workspace"
    agent = tmp_path / "agent"
    outside = tmp_path / "outside"
    workspace.mkdir()
    agent.mkdir()
    outside.mkdir()
    return workspace, agent, outside


def _runtime(patch_roots, allowed, **kwargs):
    workspace, agent, _ = patch_roots
    return FileToolRuntime(
        workspace, allowed, agent_root=agent, **kwargs)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _arguments(path: Path, old: str, new: str):
    return {
        "path": path.name,
        "expected_sha256": _sha(path),
        "hunks": [{"old_text": old, "replacement": new}],
    }


def test_large_file_patch_succeeds_while_full_replacement_stays_bounded(patch_roots):
    workspace, _, _ = patch_roots
    target = workspace / "large.c"
    target.write_text(
        "/* padding */\n" * (MAX_WRITE_BYTES // 14 + 100)
        + "int vulnerable = 1;\n",
        encoding="utf-8",
    )
    assert target.stat().st_size > MAX_WRITE_BYTES
    runtime = _runtime(patch_roots, {"large.c"})
    full = runtime.dispatch("write_file", {
        "path": "large.c",
        "content": target.read_text(encoding="utf-8"),
        "mode": "replace_only",
    })
    result = runtime.dispatch(
        "apply_patch_hunks",
        _arguments(target, "int vulnerable = 1;\n", "int vulnerable = 0;\n"),
    )
    assert not full.success and full.error_kind == "validation"
    assert result.success and result.mutated
    assert result.payload["old_sha256"] != result.payload["new_sha256"]
    assert result.payload["hunks_applied"] == 1
    assert result.payload["mutation_generation"] == 1
    assert runtime.mutation_generation == 1
    assert target.read_text(encoding="utf-8").endswith("int vulnerable = 0;\n")


def test_hash_context_and_ambiguity_fail_without_mutation(patch_roots):
    workspace, _, _ = patch_roots
    target = workspace / "target.c"
    target.write_text("same\nsame\nunique\n", encoding="utf-8")
    original = target.read_bytes()
    runtime = _runtime(patch_roots, {"target.c"})
    wrong_hash = runtime.dispatch("apply_patch_hunks", {
        **_arguments(target, "unique\n", "fixed\n"),
        "expected_sha256": "0" * 64,
    })
    mismatch = runtime.dispatch(
        "apply_patch_hunks", _arguments(target, "missing\n", "fixed\n"))
    ambiguous = runtime.dispatch(
        "apply_patch_hunks", _arguments(target, "same\n", "fixed\n"))
    assert "SHA-256 mismatch" in wrong_hash.payload["error"]
    assert "context mismatch" in mismatch.payload["error"]
    assert "ambiguous" in ambiguous.payload["error"]
    assert target.read_bytes() == original
    assert runtime.mutation_generation == 0


def test_hash_guard_detects_change_after_arguments_are_prepared(patch_roots):
    workspace, _, _ = patch_roots
    target = workspace / "target.c"
    target.write_text("old\n", encoding="utf-8")
    arguments = _arguments(target, "old\n", "new\n")
    target.write_text("changed externally\n", encoding="utf-8")
    result = _runtime(patch_roots, {"target.c"}).dispatch(
        "apply_patch_hunks", arguments)
    assert not result.success
    assert "SHA-256 mismatch" in result.payload["error"]
    assert target.read_text(encoding="utf-8") == "changed externally\n"


@pytest.mark.parametrize("order", ["reverse", "overlap"])
def test_out_of_order_and_overlapping_hunks_are_rejected(patch_roots, order):
    workspace, _, _ = patch_roots
    target = workspace / "target.c"
    target.write_text("first\nmiddle\nlast\n", encoding="utf-8")
    if order == "reverse":
        hunks = [
            {"old_text": "last\n", "replacement": "LAST\n"},
            {"old_text": "first\n", "replacement": "FIRST\n"},
        ]
    else:
        hunks = [
            {"old_text": "first\nmiddle\n", "replacement": "FIRST\n"},
            {"old_text": "middle\nlast\n", "replacement": "LAST\n"},
        ]
    result = _runtime(patch_roots, {"target.c"}).dispatch(
        "apply_patch_hunks", {
            "path": "target.c", "expected_sha256": _sha(target), "hunks": hunks,
        })
    assert not result.success and result.error_kind == "validation"
    assert "overlap or are out of source order" in result.payload["error"]
    assert target.read_text(encoding="utf-8") == "first\nmiddle\nlast\n"


def test_patch_count_byte_line_and_output_limits(patch_roots):
    workspace, _, _ = patch_roots
    target = workspace / "target.c"
    target.write_text("old\n", encoding="utf-8")
    base = {"path": "target.c", "expected_sha256": _sha(target)}
    runtime = _runtime(patch_roots, {"target.c"})
    too_many = runtime.dispatch("apply_patch_hunks", {
        **base,
        "hunks": [
            {"old_text": f"old-{index}", "replacement": "new"}
            for index in range(MAX_PATCH_HUNKS + 1)
        ],
    })
    too_large = runtime.dispatch("apply_patch_hunks", {
        **base,
        "hunks": [{
            "old_text": "x" * (MAX_PATCH_CONTEXT_BYTES + 1),
            "replacement": "new",
        }],
    })
    too_many_lines = runtime.dispatch("apply_patch_hunks", {
        **base,
        "hunks": [{
            "old_text": "x\n" * (MAX_PATCH_CHANGED_LINES + 1),
            "replacement": "new",
        }],
    })
    small_runtime = _runtime(
        patch_roots, {"target.c"},
        limits=FileToolLimits(max_patch_file_bytes=8))
    output_limit = small_runtime.dispatch(
        "apply_patch_hunks", _arguments(target, "old\n", "0123456789\n"))
    assert all(not result.success for result in (
        too_many, too_large, too_many_lines, output_limit))
    assert "item limit" in too_many.payload["error"]
    assert "length limit" in too_large.payload["error"]
    assert "changed-line" in too_many_lines.payload["error"]
    assert "output" in output_limit.payload["error"]
    assert target.read_text(encoding="utf-8") == "old\n"


def test_patch_rejects_unsafe_file_types_and_paths(patch_roots):
    workspace, _, outside = patch_roots
    regular = workspace / "regular.c"
    regular.write_text("old\n", encoding="utf-8")
    hardlink = workspace / "hard.c"
    os.link(regular, hardlink)
    final_link = workspace / "link.c"
    final_link.symlink_to(outside / "outside.c")
    (outside / "outside.c").write_text("old\n", encoding="utf-8")
    directory = workspace / "directory"
    directory.mkdir()
    fifo = workspace / "fifo"
    os.mkfifo(fifo)
    real_parent = workspace / "real"
    real_parent.mkdir()
    (real_parent / "nested.c").write_text("old\n", encoding="utf-8")
    link_parent = workspace / "linked"
    link_parent.symlink_to(real_parent, target_is_directory=True)
    runtime = _runtime(patch_roots, {
        "hard.c", "link.c", "directory", "fifo", "linked/nested.c",
    })
    attempts = [
        ("hard.c", hardlink), ("link.c", final_link),
        ("directory", directory), ("fifo", fifo),
        ("linked/nested.c", real_parent / "nested.c"),
    ]
    for path, hash_target in attempts:
        result = runtime.dispatch("apply_patch_hunks", {
            "path": path,
            "expected_sha256": _sha(hash_target) if hash_target.is_file() else "0" * 64,
            "hunks": [{"old_text": "old\n", "replacement": "new\n"}],
        })
        assert not result.success and result.error_kind == "policy"
    git_path = runtime.dispatch("apply_patch_hunks", {
        "path": ".git/config", "expected_sha256": "0" * 64,
        "hunks": [{"old_text": "x", "replacement": "y"}],
    })
    assert not git_path.success and git_path.error_kind == "policy"


def test_target_race_and_atomic_failures_leave_no_temp_residue(patch_roots):
    workspace, _, _ = patch_roots
    target = workspace / "target.c"
    target.write_text("old\n", encoding="utf-8")

    def replace_target(_path):
        raced = workspace / "raced.c"
        raced.write_text("raced\n", encoding="utf-8")
        os.replace(raced, target)

    raced = _runtime(
        patch_roots, {"target.c"}, before_replace=replace_target).dispatch(
            "apply_patch_hunks", _arguments(target, "old\n", "new\n"))
    assert not raced.success
    assert target.read_text(encoding="utf-8") == "raced\n"
    assert not list(workspace.glob(".cve-agent-*.tmp"))

    target.write_text("old\n", encoding="utf-8")
    original_replace = openai_tools.os.replace

    def fail_replace(*args, **kwargs):
        raise OSError("injected rename failure")

    with patch.object(openai_tools.os, "replace", side_effect=fail_replace):
        renamed = _runtime(patch_roots, {"target.c"}).dispatch(
            "apply_patch_hunks", _arguments(target, "old\n", "new\n"))
    assert not renamed.success and target.read_text(encoding="utf-8") == "old\n"
    assert not list(workspace.glob(".cve-agent-*.tmp"))

    def fail_fsync(_fd):
        raise OSError("injected fsync failure")

    with patch.object(openai_tools.os, "fsync", side_effect=fail_fsync):
        synced = _runtime(patch_roots, {"target.c"}).dispatch(
            "apply_patch_hunks", _arguments(target, "old\n", "new\n"))
    assert not synced.success and target.read_text(encoding="utf-8") == "old\n"
    assert not list(workspace.glob(".cve-agent-*.tmp"))
    assert original_replace is not None

    with patch.object(
            FileToolRuntime, "_write_all",
            side_effect=openai_tools.ToolOperationalError("injected write failure")):
        written = _runtime(patch_roots, {"target.c"}).dispatch(
            "apply_patch_hunks", _arguments(target, "old\n", "new\n"))
    assert not written.success and target.read_text(encoding="utf-8") == "old\n"
    assert not list(workspace.glob(".cve-agent-*.tmp"))


def test_postcondition_failure_restores_original(patch_roots):
    workspace, _, _ = patch_roots
    target = workspace / "target.c"
    target.write_text("old\n", encoding="utf-8")
    runtime = _runtime(patch_roots, {"target.c"})
    with patch.object(
            runtime, "_verify_patch_postcondition",
            side_effect=openai_tools.ToolOperationalError("injected postcondition")):
        result = runtime.dispatch(
            "apply_patch_hunks", _arguments(target, "old\n", "new\n"))
    assert not result.success and result.error_kind == "operation"
    assert target.read_text(encoding="utf-8") == "old\n"
    assert not list(workspace.glob(".cve-agent-*.tmp"))


def test_patch_result_diff_is_bounded(patch_roots):
    workspace, _, _ = patch_roots
    target = workspace / "target.c"
    old = "old value\n" * 300
    new = "new value\n" * 300
    target.write_text(f"prefix\n{old}suffix\n", encoding="utf-8")
    result = _runtime(patch_roots, {"target.c"}).dispatch(
        "apply_patch_hunks", _arguments(target, old, new))
    assert result.success
    assert len(result.payload["diff_excerpt"].encode("utf-8")) <= MAX_PATCH_DIFF_BYTES
    assert result.payload["diff_truncated"] is True
    encoded = str(result.to_dict()).encode("utf-8")
    assert len(encoded) < MAX_MODEL_RESULT_BYTES


def test_patch_schema_is_closed_and_transcript_redacts_bounded_diff(patch_roots):
    schemas = {
        item["function"]["name"]: item["function"]["parameters"]
        for item in openai_tool_schemas()
    }
    hunk_items = schemas["apply_patch_hunks"]["properties"]["hunks"]["items"]
    assert hunk_items["additionalProperties"] is False
    assert set(hunk_items["properties"]) == {"old_text", "replacement"}

    _, agent, _ = patch_roots
    secret = "never-record-this-secret"
    transcript = JSONLTranscript.create(
        agent, "patch-model", SessionDeadline.from_timeout(30), (secret,))
    transcript.write(
        "tool_result", tool="apply_patch_hunks",
        payload={"diff_excerpt": f"-old\n+{secret}\n"})
    transcript.close()
    recorded = transcript.path.read_text(encoding="utf-8")
    assert secret not in recorded
    assert "[REDACTED]" in recorded


@pytest.mark.parametrize("content", [b"old\r\n", b"old\xff\n"])
def test_patch_rejects_non_lf_or_invalid_utf8_text(patch_roots, content):
    workspace, _, _ = patch_roots
    target = workspace / "target.c"
    target.write_bytes(content)
    result = _runtime(patch_roots, {"target.c"}).dispatch(
        "apply_patch_hunks", {
            "path": "target.c", "expected_sha256": _sha(target),
            "hunks": [{"old_text": "old", "replacement": "new"}],
        })
    assert not result.success and result.error_kind == "operation"
    assert target.read_bytes() == content


def test_no_generic_patch_or_shell_execution_is_introduced():
    source = Path(openai_tools.__file__).read_text(encoding="utf-8")
    assert "git apply" not in source
    assert "import subprocess" not in source
    assert "subprocess.run" not in source
    assert "shell=True" not in source
