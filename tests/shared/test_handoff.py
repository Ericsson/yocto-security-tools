# SPDX-License-Identifier: MIT
"""Tests for shared.handoff capture helpers."""
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from shared.handoff import HandoffError, _git_fingerprint, capture_handoff_state


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "user.email", "test@example.com")
    return repo


def test_git_fingerprint_matches_direct_hash_of_stdout(tmp_path):
    repo = _repo(tmp_path)
    (repo / "file.txt").write_text("hello\n")
    _commit(repo, "base")

    digest = _git_fingerprint(repo, "ls-files", "--stage", "-z")

    expected_stdout = subprocess.run(
        ["git", "ls-files", "--stage", "-z"], cwd=repo,
        capture_output=True, check=True).stdout
    assert digest == hashlib.sha256(expected_stdout).hexdigest()


def test_git_fingerprint_raises_on_git_failure(tmp_path):
    repo = _repo(tmp_path)
    (repo / "file.txt").write_text("hello\n")
    _commit(repo, "base")

    with pytest.raises(HandoffError) as raised:
        _git_fingerprint(repo, "this-is-not-a-git-command")
    assert raised.value.code == "HANDOFF_GIT_FAILED"


def test_git_fingerprint_does_not_cap_output_past_the_bounded_git_helper_limit(tmp_path):
    """A git command whose stdout exceeds the fixed byte cap `_git` enforces
    (8MB) must still produce a digest instead of raising
    HANDOFF_CAPTURE_LIMIT — the limit exists for output that is parsed as
    text, not for a value that is only ever hashed. This is what previously
    crashed capture_handoff_state on repositories with enough tracked
    files that `git ls-files --stage` exceeds the cap (qemu, which vendors
    several large subtrees as regular tracked files), surfacing downstream
    as HANDOFF_MISSING since nothing caught the unhandled HandoffError."""
    repo = _repo(tmp_path)
    large = "x" * (9 * 1024 * 1024)
    (repo / "big.txt").write_text(large)
    _commit(repo, "add large tracked file")

    digest = _git_fingerprint(repo, "cat-file", "blob", "HEAD:big.txt")

    assert digest == hashlib.sha256(large.encode("utf-8")).hexdigest()


def test_capture_handoff_state_succeeds_with_large_tracked_index(tmp_path):
    """capture_handoff_state's index_fingerprint must not depend on the
    index listing fitting the generic `_git` byte cap (regression:
    qemu CVE-2026-0665, HANDOFF_CAPTURE_LIMIT crashed the corrector before
    any handoff was written)."""
    repo = _repo(tmp_path)
    # Many small tracked files, not one large one, so this also exercises
    # the real ls-files listing path (one record per file) rather than a
    # single blob's content.
    for i in range(200):
        path = repo / f"file_{i}.txt"
        path.write_text(f"content {i}\n" * 50)
    _commit(repo, "many tracked files")

    captured = capture_handoff_state(repo)

    assert len(captured.index_fingerprint) == 64
    assert captured.tracked_paths == ()
    assert captured.operation_state == "clean"
