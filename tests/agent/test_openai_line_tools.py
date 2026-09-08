# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for line-addressed inspection and editing in the native backend.

These cover the tooling gap observed in a real benchmark session, where a model
spent 51 of 61 tool calls probing one conflicted file for its byte-exact
indentation because no tool could return numbered lines or accept a positional
edit.
"""
import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from cve_agent.openai_git_tools import (
    MAX_CONFLICT_REGIONS,
    MAX_CONFLICT_SIDE_LINES,
    GitToolRuntime,
)
from cve_agent.openai_tools import (
    MAX_MODEL_RESULT_BYTES,
    MAX_PATCH_CHANGED_LINES,
    MAX_RANGE_LINE_CHARS,
    MAX_RANGE_LINES,
    MAX_WRITE_BYTES,
    FileToolLimits,
    FileToolRuntime,
)

CONFLICTED_SOURCE = (
    "static bool\n"
    "_bfd_elf_link_keep_memory (void)\n"
    "{\n"
    "      if (size >= info->max_cache_size)\n"
    "\t{\n"
    "\t  /* Over the limit.  */\n"
    "\t  return false;\n"
    "\t}\n"
    "\tbreak;\n"
    "}\n"
)


@pytest.fixture
def roots(tmp_path):
    workspace = tmp_path / "workspace"
    agent = tmp_path / "agent"
    workspace.mkdir()
    agent.mkdir()
    return workspace, agent


def _runtime(roots, allowed=(), **kwargs):
    workspace, agent = roots
    return FileToolRuntime(workspace, set(allowed), agent_root=agent, **kwargs)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _assert_bounded(result):
    encoded = json.dumps(
        result.to_dict(), ensure_ascii=False, allow_nan=False).encode("utf-8")
    assert len(encoded) <= MAX_MODEL_RESULT_BYTES


def test_read_file_range_returns_byte_exact_indentation_and_numbers(roots):
    workspace, _ = roots
    target = workspace / "elflink.c"
    target.write_text(CONFLICTED_SOURCE, encoding="utf-8")
    runtime = _runtime(roots)

    result = runtime.dispatch(
        "read_file_range", {"path": "elflink.c", "start_line": 4, "line_count": 6})

    assert result.success is True
    payload = result.payload
    assert payload["lines"] == [
        {"line": 4, "text": "      if (size >= info->max_cache_size)",
         "truncated": False},
        {"line": 5, "text": "\t{", "truncated": False},
        {"line": 6, "text": "\t  /* Over the limit.  */", "truncated": False},
        {"line": 7, "text": "\t  return false;", "truncated": False},
        {"line": 8, "text": "\t}", "truncated": False},
        {"line": 9, "text": "\tbreak;", "truncated": False},
    ]
    assert payload["start_line"] == 4
    assert payload["end_line"] == 9
    assert payload["file_lines"] == 10
    assert payload["final_newline"] is True
    assert payload["truncated"] is True
    assert payload["next_line"] == 10
    assert payload["sha256"] == _sha(target)
    _assert_bounded(result)


def test_read_file_range_defaults_bounds_and_continuation(roots):
    workspace, _ = roots
    target = workspace / "many.c"
    target.write_text(
        "".join(f"line {index}\n" for index in range(1, MAX_RANGE_LINES + 20)),
        encoding="utf-8")
    runtime = _runtime(roots)

    first = runtime.dispatch("read_file_range", {"path": "many.c"})
    second = runtime.dispatch(
        "read_file_range",
        {"path": "many.c", "start_line": first.payload["next_line"]})

    assert first.payload["line_count"] == MAX_RANGE_LINES
    assert first.payload["next_line"] == MAX_RANGE_LINES + 1
    assert second.payload["lines"][0]["line"] == MAX_RANGE_LINES + 1
    assert second.payload["truncated"] is False
    assert second.payload["next_line"] is None
    _assert_bounded(first)


def test_read_file_range_truncates_one_long_line_and_stays_bounded(roots):
    workspace, _ = roots
    target = workspace / "long.c"
    target.write_text("x" * (MAX_RANGE_LINE_CHARS + 50) + "\n", encoding="utf-8")
    runtime = _runtime(roots)

    result = runtime.dispatch("read_file_range", {"path": "long.c"})

    assert result.payload["lines"][0]["truncated"] is True
    assert len(result.payload["lines"][0]["text"]) == MAX_RANGE_LINE_CHARS
    _assert_bounded(result)


def test_read_file_range_byte_budget_stops_before_the_line_limit(roots):
    workspace, _ = roots
    target = workspace / "wide.c"
    target.write_text("".join("y" * 400 + "\n" for _ in range(50)),
                      encoding="utf-8")
    runtime = _runtime(roots, limits=FileToolLimits(max_file_read_bytes=4096))

    result = runtime.dispatch("read_file_range", {"path": "wide.c"})

    assert result.payload["line_count"] < 50
    assert result.payload["truncated"] is True
    assert result.payload["next_line"] == result.payload["line_count"] + 1


def test_read_file_range_rejects_out_of_range_binary_and_denied_paths(roots):
    workspace, _ = roots
    (workspace / "small.c").write_text("one\n", encoding="utf-8")
    (workspace / "binary.bin").write_bytes(b"\x00\x01\x02binary")
    runtime = _runtime(roots)

    beyond = runtime.dispatch(
        "read_file_range", {"path": "small.c", "start_line": 5})
    binary = runtime.dispatch("read_file_range", {"path": "binary.bin"})
    denied = runtime.dispatch(
        "read_file_range", {"path": "../outside/secret"})

    assert beyond.error_kind == "operation"
    assert binary.error_kind == "operation"
    assert denied.error_kind == "policy"


def test_read_file_range_reports_size_limit_with_an_alternative(roots):
    workspace, _ = roots
    (workspace / "huge.c").write_text("z" * 5000, encoding="utf-8")
    runtime = _runtime(
        roots, limits=FileToolLimits(
            max_inspectable_file_bytes=4096, max_file_read_bytes=4096))

    result = runtime.dispatch("read_file_range", {"path": "huge.c"})

    assert result.error_kind == "operation"
    assert result.payload["file_size"] == 5000
    assert result.payload["size_limit"] == 4096
    assert "search_text" in result.payload["alternative"]


def test_empty_file_range_is_not_an_error(roots):
    workspace, _ = roots
    (workspace / "empty.c").write_text("", encoding="utf-8")

    result = _runtime(roots).dispatch("read_file_range", {"path": "empty.c"})

    assert result.success is True
    assert result.payload["lines"] == []
    assert result.payload["file_lines"] == 0
    assert result.payload["end_line"] is None


def test_replace_lines_resolves_a_region_without_any_text_context(roots):
    workspace, _ = roots
    target = workspace / "elflink.c"
    target.write_text(CONFLICTED_SOURCE, encoding="utf-8")
    runtime = _runtime(roots, {"elflink.c"})

    result = runtime.dispatch("replace_lines", {
        "path": "elflink.c",
        "start_line": 1,
        "end_line": 9,
        "expected_sha256": _sha(target),
        "replacement": (
            "static struct elf_link_hash_entry *\n"
            "get_ext_sym_hash (void)\n"),
    })

    assert result.success is True and result.mutated is True
    assert target.read_text(encoding="utf-8") == (
        "static struct elf_link_hash_entry *\nget_ext_sym_hash (void)\n}\n")
    assert result.payload["lines_removed"] == 9
    assert result.payload["lines_added"] == 2
    assert result.payload["start_line"] == 1
    assert result.payload["end_line"] == 9
    assert result.payload["new_sha256"] == _sha(target)
    assert result.payload["mutation_generation"] == 1
    assert runtime.mutation_generation == 1
    _assert_bounded(result)


def test_replace_lines_deletes_a_range_and_adds_a_missing_newline(roots):
    workspace, _ = roots
    target = workspace / "file.c"
    target.write_text("one\ntwo\nthree\n", encoding="utf-8")
    runtime = _runtime(roots, {"file.c"})

    deleted = runtime.dispatch("replace_lines", {
        "path": "file.c", "start_line": 2, "end_line": 2,
        "expected_sha256": _sha(target), "replacement": "",
    })
    assert deleted.success is True
    assert target.read_text(encoding="utf-8") == "one\nthree\n"

    joined = runtime.dispatch("replace_lines", {
        "path": "file.c", "start_line": 1, "end_line": 1,
        "expected_sha256": _sha(target), "replacement": "first",
    })
    assert joined.success is True
    assert target.read_text(encoding="utf-8") == "first\nthree\n"


def test_replace_lines_preserves_an_unterminated_final_line(roots):
    workspace, _ = roots
    target = workspace / "file.c"
    target.write_text("one\ntwo", encoding="utf-8")
    runtime = _runtime(roots, {"file.c"})

    result = runtime.dispatch("replace_lines", {
        "path": "file.c", "start_line": 2, "end_line": 2,
        "expected_sha256": _sha(target), "replacement": "second",
    })

    assert result.success is True
    assert target.read_text(encoding="utf-8") == "one\nsecond"


def test_replace_lines_rejects_stale_hash_and_names_the_current_one(roots):
    workspace, _ = roots
    target = workspace / "file.c"
    target.write_text("one\ntwo\n", encoding="utf-8")
    runtime = _runtime(roots, {"file.c"})

    result = runtime.dispatch("replace_lines", {
        "path": "file.c", "start_line": 1, "end_line": 1,
        "expected_sha256": "0" * 64, "replacement": "changed\n",
    })

    assert result.error_kind == "operation"
    assert result.payload["current_sha256"] == _sha(target)
    assert target.read_text(encoding="utf-8") == "one\ntwo\n"
    assert runtime.mutation_generation == 0


@pytest.mark.parametrize("arguments,expected", [
    ({"start_line": 2, "end_line": 1, "replacement": "x\n"}, "validation"),
    ({"start_line": 1, "end_line": 9, "replacement": "x\n"}, "operation"),
    ({"start_line": 1, "end_line": 1, "replacement": "one\n"}, "validation"),
    ({"start_line": 1, "end_line": 1, "replacement": "bad\r\n"}, "validation"),
])
def test_replace_lines_rejects_unsafe_or_useless_ranges(roots, arguments, expected):
    workspace, _ = roots
    target = workspace / "file.c"
    target.write_text("one\ntwo\n", encoding="utf-8")
    runtime = _runtime(roots, {"file.c"})

    result = runtime.dispatch("replace_lines", {
        "path": "file.c", "expected_sha256": _sha(target), **arguments})

    assert result.error_kind == expected
    assert target.read_text(encoding="utf-8") == "one\ntwo\n"
    assert runtime.mutation_generation == 0


def test_replace_lines_rejects_crlf_targets_and_unauthorized_paths(roots):
    workspace, _ = roots
    crlf = workspace / "crlf.c"
    crlf.write_bytes(b"one\r\ntwo\r\n")
    other = workspace / "other.c"
    other.write_text("one\n", encoding="utf-8")
    runtime = _runtime(roots, {"crlf.c"})

    windows = runtime.dispatch("replace_lines", {
        "path": "crlf.c", "start_line": 1, "end_line": 1,
        "expected_sha256": _sha(crlf), "replacement": "changed\n",
    })
    denied = runtime.dispatch("replace_lines", {
        "path": "other.c", "start_line": 1, "end_line": 1,
        "expected_sha256": _sha(other), "replacement": "changed\n",
    })

    assert windows.error_kind == "operation"
    assert denied.error_kind == "policy"
    assert crlf.read_bytes() == b"one\r\ntwo\r\n"


def test_replace_lines_edits_a_file_above_the_full_rewrite_limit(roots):
    workspace, _ = roots
    target = workspace / "large.c"
    padding = "/* padding */\n" * (MAX_WRITE_BYTES // 14 + 100)
    target.write_text(padding + "int vulnerable = 1;\n", encoding="utf-8")
    assert target.stat().st_size > MAX_WRITE_BYTES
    runtime = _runtime(roots, {"large.c"})
    line_count = padding.count("\n") + 1

    rewrite = runtime.dispatch("write_file", {
        "path": "large.c",
        "content": target.read_text(encoding="utf-8"),
        "mode": "replace_only",
    })
    result = runtime.dispatch("replace_lines", {
        "path": "large.c",
        "start_line": line_count,
        "end_line": line_count,
        "expected_sha256": _sha(target),
        "replacement": "int vulnerable = 0;\n",
    })

    assert rewrite.error_kind == "validation"
    assert rewrite.payload["size_limit"] == MAX_WRITE_BYTES
    assert "replace_lines" in rewrite.payload["alternative"]
    assert result.success is True and result.mutated is True
    assert target.read_text(encoding="utf-8").endswith("int vulnerable = 0;\n")
    _assert_bounded(result)


def test_replace_in_file_now_accepts_a_large_target(roots):
    workspace, _ = roots
    target = workspace / "large.c"
    target.write_text(
        "/* padding */\n" * (MAX_WRITE_BYTES // 14 + 100)
        + "int vulnerable = 1;\n",
        encoding="utf-8")
    assert target.stat().st_size > MAX_WRITE_BYTES
    runtime = _runtime(roots, {"large.c"})

    result = runtime.dispatch("replace_in_file", {
        "path": "large.c",
        "old_text": "int vulnerable = 1;\n",
        "new_text": "int vulnerable = 0;\n",
        "expected_count": 1,
    })

    assert result.success is True and result.mutated is True
    assert target.read_text(encoding="utf-8").endswith("int vulnerable = 0;\n")


def test_replace_in_file_size_rejection_names_the_working_alternative(roots):
    workspace, _ = roots
    target = workspace / "big.c"
    target.write_text("x" * 5000, encoding="utf-8")
    runtime = _runtime(
        roots, {"big.c"}, limits=FileToolLimits(max_patch_file_bytes=4096))

    result = runtime.dispatch("replace_in_file", {
        "path": "big.c", "old_text": "x", "new_text": "y",
        "expected_count": 5000,
    })

    assert result.error_kind == "operation"
    assert result.payload["file_size"] == 5000
    assert result.payload["size_limit"] == 4096
    assert result.payload["alternative"] == "replace_lines or apply_patch_hunks"


def test_replace_lines_rejects_a_malformed_hash_before_touching_the_file(roots):
    workspace, _ = roots
    target = workspace / "file.c"
    target.write_text("one\ntwo\n", encoding="utf-8")
    runtime = _runtime(roots, {"file.c"})

    result = runtime.dispatch("replace_lines", {
        "path": "file.c", "start_line": 1, "end_line": 1,
        "expected_sha256": "Z" * 64, "replacement": "changed\n",
    })

    assert result.error_kind == "validation"
    assert "hexadecimal" in result.payload["error"]
    assert target.read_text(encoding="utf-8") == "one\ntwo\n"


def test_replace_lines_enforces_the_changed_line_ceiling(roots):
    workspace, _ = roots
    target = workspace / "file.c"
    target.write_text("line\n" * (MAX_PATCH_CHANGED_LINES + 10), encoding="utf-8")
    runtime = _runtime(roots, {"file.c"})

    result = runtime.dispatch("replace_lines", {
        "path": "file.c",
        "start_line": 1,
        "end_line": MAX_PATCH_CHANGED_LINES + 1,
        "expected_sha256": _sha(target),
        "replacement": "one\n",
    })

    assert result.error_kind == "validation"
    assert "exceeds its limit" in result.payload["error"]
    assert runtime.mutation_generation == 0


def test_replace_lines_refuses_to_grow_a_file_past_its_output_limit(roots):
    workspace, _ = roots
    target = workspace / "file.c"
    target.write_text("one\ntwo\n", encoding="utf-8")
    runtime = _runtime(
        roots, {"file.c"}, limits=FileToolLimits(max_patch_file_bytes=64))

    result = runtime.dispatch("replace_lines", {
        "path": "file.c", "start_line": 1, "end_line": 1,
        "expected_sha256": _sha(target), "replacement": "x" * 200 + "\n",
    })

    assert result.error_kind == "validation"
    assert target.read_text(encoding="utf-8") == "one\ntwo\n"


def test_search_text_rejects_a_multi_line_query_with_guidance(roots):
    workspace, _ = roots
    (workspace / "file.c").write_text("alpha\nbeta\n", encoding="utf-8")
    runtime = _runtime(roots)

    multi_line = runtime.dispatch(
        "search_text", {"query": "alpha\nbeta", "paths": ["file.c"]})
    carriage = runtime.dispatch(
        "search_text", {"query": "alpha\r", "paths": ["file.c"]})
    single = runtime.dispatch(
        "search_text", {"query": "alpha", "paths": ["file.c"]})

    assert multi_line.error_kind == "validation"
    assert "single line" in multi_line.payload["error"]
    assert "read_file_range" in multi_line.payload["error"]
    assert carriage.error_kind == "validation"
    assert single.success is True and single.payload["match_count"] == 1


def test_search_text_contract_documents_single_line_matching():
    from cve_agent.openai_tools import TOOL_CONTRACTS

    contract = TOOL_CONTRACTS["search_text"]
    assert "single-line" in contract.description
    assert "newline" in contract.fields["query"].description


# --- typed Git conflict-region inspection -----------------------------------


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    result = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, encoding="utf-8",
        errors="replace", check=False,
        env={**os.environ, "GIT_EDITOR": "true", "GIT_TERMINAL_PROMPT": "0"})
    if result.returncode not in {0, 1}:
        raise AssertionError(f"git {' '.join(args)}: {result.stderr}")
    return result


@pytest.fixture
def conflicted(tmp_path):
    """Build the shape of the real binutils conflict: one adapted region."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "CVE Test")
    _git(repo, "config", "user.email", "cve@example.com")
    (repo / "elflink.c").write_text(
        "static bool\nkeep (void)\n{\n\t  return false;\n}\nint tail = 1;\n",
        encoding="utf-8")
    (repo / "other.c").write_text("clean\n", encoding="utf-8")
    _git(repo, "add", "--", "elflink.c", "other.c")
    _git(repo, "commit", "-qm", "base")
    branch = _git(repo, "branch", "--show-current").stdout.strip()
    _git(repo, "checkout", "-q", "-b", "upstream")
    (repo / "elflink.c").write_text(
        "static struct elf_link_hash_entry *\nget_ext_sym_hash (void)\n{\n"
        "\treturn NULL;\n}\nint tail = 1;\n",
        encoding="utf-8")
    _git(repo, "commit", "-qam", "upstream fix")
    source = _git(repo, "rev-parse", "HEAD").stdout.strip()
    _git(repo, "checkout", "-q", branch)
    (repo / "elflink.c").write_text(
        "static bool\nkeep (void)\n{\n\t  return false;  /* stable */\n}\n"
        "int tail = 1;\n",
        encoding="utf-8")
    _git(repo, "commit", "-qam", "stable divergence")
    return repo, source, branch


def _git_runtime(repo: Path, allowed) -> GitToolRuntime:
    return GitToolRuntime(
        repo, set(allowed), model="gpt-test", timeout_seconds=30)


def test_conflict_regions_return_exact_sides_with_line_numbers(conflicted):
    repo, source, _ = conflicted
    runtime = _git_runtime(repo, {"elflink.c"})
    assert runtime.dispatch(
        "git_cherry_pick_start", {"revision": source}).payload["conflicted"] is True

    result = runtime.dispatch("git_conflict_regions", {})

    assert result.success is True
    files = result.payload["files"]
    assert len(files) == 1
    assert files[0]["path"] == "elflink.c"
    assert files[0]["malformed_markers"] is False
    assert files[0]["truncated"] is False
    region = files[0]["regions"][0]
    assert region["index"] == 1
    assert region["ours_label"] == "HEAD"
    assert region["theirs_label"].endswith("(upstream fix)")
    assert region["ours"]["text"] == "\t  return false;  /* stable */\n"
    assert region["theirs"]["text"] == "\treturn NULL;\n"
    assert region["base"] is None
    assert region["ours"]["start_line"] == region["start_line"] + 1
    assert region["end_line"] > region["theirs"]["end_line"]
    lines = Path(repo / "elflink.c").read_text(encoding="utf-8").split("\n")
    assert lines[region["start_line"] - 1].startswith("<<<<<<<")
    assert lines[region["end_line"] - 1].startswith(">>>>>>>")
    _assert_bounded(result)


def test_conflict_regions_expose_the_base_side_in_diff3_style(conflicted):
    repo, source, _ = conflicted
    _git(repo, "config", "merge.conflictStyle", "diff3")
    runtime = _git_runtime(repo, {"elflink.c"})
    runtime.dispatch("git_cherry_pick_start", {"revision": source})

    region = runtime.dispatch(
        "git_conflict_regions", {}).payload["files"][0]["regions"][0]

    assert region["base"] is not None
    assert region["base"]["text"] == "\t  return false;\n"
    assert region["theirs"]["text"] == "\treturn NULL;\n"


def test_conflict_regions_skip_clean_and_reject_escaping_paths(conflicted):
    repo, source, _ = conflicted
    runtime = _git_runtime(repo, {"elflink.c", "other.c"})
    runtime.dispatch("git_cherry_pick_start", {"revision": source})

    clean = runtime.dispatch("git_conflict_regions", {"paths": ["other.c"]})
    denied = runtime.dispatch(
        "git_conflict_regions", {"paths": ["../outside/secret.c"]})

    assert clean.success is True
    assert clean.payload["files"] == []
    assert clean.payload["skipped"] == [
        {"path": "other.c", "reason": "not_conflicted"}]
    assert clean.payload["conflicted_files"] == 1
    assert denied.error_kind == "policy"


def test_conflict_regions_report_malformed_markers_without_failing(conflicted):
    repo, source, _ = conflicted
    runtime = _git_runtime(repo, {"elflink.c"})
    runtime.dispatch("git_cherry_pick_start", {"revision": source})
    target = repo / "elflink.c"
    target.write_text(
        "<<<<<<< HEAD\nours only\n=======\ntheirs\n>>>>>>> commit\n"
        "<<<<<<< HEAD\nnever closed\n",
        encoding="utf-8")

    files = runtime.dispatch("git_conflict_regions", {}).payload["files"]

    assert files[0]["region_count"] == 1
    assert files[0]["malformed_markers"] is True


def test_conflict_regions_report_a_nested_start_marker_as_malformed(conflicted):
    repo, source, _ = conflicted
    runtime = _git_runtime(repo, {"elflink.c"})
    runtime.dispatch("git_cherry_pick_start", {"revision": source})
    (repo / "elflink.c").write_text(
        "<<<<<<< HEAD\nours\n<<<<<<< HEAD\nnested\n=======\ntheirs\n"
        ">>>>>>> commit\n",
        encoding="utf-8")

    entry = runtime.dispatch("git_conflict_regions", {}).payload["files"][0]

    assert entry["malformed_markers"] is True
    # Parsing restarts at the nested marker instead of swallowing the rest of
    # the file, so the well-formed inner region is still reported.
    assert entry["region_count"] == 1
    assert entry["regions"][0]["ours"]["text"] == "nested\n"
    assert entry["regions"][0]["theirs"]["text"] == "theirs\n"


def test_conflict_regions_cap_region_count_and_total_text(conflicted):
    repo, source, _ = conflicted
    runtime = _git_runtime(repo, {"elflink.c"})
    runtime.dispatch("git_cherry_pick_start", {"revision": source})
    wide = "w" * 200
    region = (
        "<<<<<<< HEAD\n" + f"{wide}\n" * 60 + "=======\n"
        + f"{wide}\n" * 60 + ">>>>>>> commit\n")
    (repo / "elflink.c").write_text(
        region * (MAX_CONFLICT_REGIONS + 4), encoding="utf-8")

    result = runtime.dispatch("git_conflict_regions", {})

    entry = result.payload["files"][0]
    assert entry["region_count"] <= MAX_CONFLICT_REGIONS
    assert entry["truncated"] is True
    side = entry["regions"][0]["ours"]
    assert side["truncated"] is True
    assert side["line_count"] == 60
    assert len(side["text"]) < 60 * len(wide)
    _assert_bounded(result)


def test_conflict_regions_cap_a_very_tall_side_by_line_count(conflicted):
    repo, source, _ = conflicted
    runtime = _git_runtime(repo, {"elflink.c"})
    runtime.dispatch("git_cherry_pick_start", {"revision": source})
    (repo / "elflink.c").write_text(
        "<<<<<<< HEAD\n" + "ours\n" * 400 + "=======\n"
        + "theirs\n" * 400 + ">>>>>>> commit\n",
        encoding="utf-8")

    entry = runtime.dispatch("git_conflict_regions", {}).payload["files"][0]

    side = entry["regions"][0]["ours"]
    assert side["line_count"] == 400
    assert side["truncated"] is True
    assert side["text"].count("\n") == MAX_CONFLICT_SIDE_LINES


def test_conflict_regions_then_replace_lines_completes_the_cherry_pick(conflicted):
    """The whole benchmark task, expressed as two inspections and one edit."""
    repo, source, _ = conflicted
    runtime = _git_runtime(repo, {"elflink.c"})
    runtime.dispatch("git_cherry_pick_start", {"revision": source})

    region = runtime.dispatch(
        "git_conflict_regions", {}).payload["files"][0]["regions"][0]
    current = runtime.dispatch(
        "read_file_range", {"path": "elflink.c", "start_line": 1})
    replaced = runtime.dispatch("replace_lines", {
        "path": "elflink.c",
        "start_line": region["start_line"],
        "end_line": region["end_line"],
        "expected_sha256": current.payload["sha256"],
        "replacement": region["theirs"]["text"],
    })
    staged = runtime.dispatch("git_stage", {"paths": ["elflink.c"]})
    continued = runtime.dispatch(
        "git_cherry_pick_continue", {"resolution_note": "kept upstream helper"})

    assert replaced.success is True
    assert continued.success is True
    resolved = (repo / "elflink.c").read_text(encoding="utf-8")
    assert "<<<<<<<" not in resolved
    assert resolved == (
        "static struct elf_link_hash_entry *\nget_ext_sym_hash (void)\n{\n"
        "\treturn NULL;\n}\nint tail = 1;\n")
    assert staged.success is True
    assert not _git(repo, "ls-files", "-u").stdout.strip()
