# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""A submodule dirtied outside the CVE fix must not fail the retry handoff.

gnutls CVE-2025-6395 ended as ``HANDOFF_RETRY_SCOPE_DRIFT``: after an
unresolved session, ``gnulib`` and ``devel/libtasn1`` were reported as
modified (``S.M.``). Git lists a modified submodule as a tracked path, and no
fix ever authorises one, so the refresh judged them out of scope. The
corrector's own handoff resets submodule worktrees first; the agent's refresh
did not. The reset must restore tracked content only: files the corrector
copied in from the release tarball are untracked and have to survive.
"""
from __future__ import annotations

import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from cve_agent.handoff import refresh_repository_handoff
from cve_corrector.handoff import emit_handoff
from cve_corrector.state import WorkflowState
from shared.git_runner import reset_submodule_worktrees
from shared.handoff import HandoffError, read_handoff, write_handoff

CVE_ID = "CVE-2026-06395"
FIXED = "lib/handshake.c"
SUB = "gnulib"


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-c", "protocol.file.allow=always", *args], cwd=repo, check=True,
        capture_output=True, text=True)
    return result.stdout.strip()


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _init(repo: Path) -> None:
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    for key, value in (("user.name", "T"), ("user.email", "t@t.com"),
                       ("commit.gpgsign", "false")):
        _git(repo, "config", key, value)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """Workspace with a submodule, tagged ``original-version``, one fix committed."""
    upstream = tmp_path / "gnulib-upstream"
    _init(upstream)
    _write(upstream, "lib/gl.c", "pinned\n")
    _git(upstream, "add", "-A")
    _git(upstream, "commit", "-q", "-m", "gnulib")

    root = tmp_path / "build" / "workspace" / "sources" / "gnutls"
    _init(root)
    _write(root, FIXED, "base\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    _git(root, "submodule", "add", str(upstream), SUB)
    _git(root, "commit", "-q", "-m", "add gnulib")
    _git(root, "checkout", "-q", "-b", CVE_ID)
    _git(root, "tag", "-f", "original-version")

    _write(root, FIXED, "fixed\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "handshake: fix")
    return root


def _manifest(repo: Path):
    state = WorkflowState(
        workspace_path=repo, cve_id=CVE_ID, recipe="gnutls",
        commit_hash=_git(repo, "rev-parse", "HEAD"), hash_details=[],
        meta_layer=None, skip_build=True, skip_ptest=True)
    state_dir = repo.parent.parent / "cve_corrector"
    manifest = emit_handoff(state, state_dir)
    manifest = replace(manifest, allowed_paths=(FIXED,)).with_digest()
    path = state_dir / "handoffs" / "gnutls.json"
    write_handoff(path, manifest)
    return read_handoff(path)


def _refresh(repo: Path, manifest):
    return refresh_repository_handoff(
        repo, manifest, {FIXED}, session_root_head=_git(repo, "rev-parse", "HEAD"))


def test_modified_submodule_does_not_fail_the_retry_handoff(repo: Path) -> None:
    manifest = _manifest(repo)
    _write(repo, f"{SUB}/lib/gl.c", "bootstrap rewrote this\n")
    assert "M gnulib" in _git(repo, "status", "--porcelain")

    refreshed = _refresh(repo, manifest)

    assert refreshed.current_head == _git(repo, "rev-parse", "HEAD")
    assert (repo / SUB / "lib" / "gl.c").read_text() == "pinned\n"


def test_without_the_reset_the_modified_submodule_is_out_of_scope(repo: Path) -> None:
    """Characterises the bug through the same refresh, bypassing the reset."""
    from cve_agent import handoff

    manifest = _manifest(repo)
    _write(repo, f"{SUB}/lib/gl.c", "bootstrap rewrote this\n")
    original = handoff.reset_submodule_worktrees
    handoff.reset_submodule_worktrees = lambda _path: None
    try:
        with pytest.raises(HandoffError, match="HANDOFF_RETRY_SCOPE_DRIFT"):
            _refresh(repo, manifest)
    finally:
        handoff.reset_submodule_worktrees = original


def test_submodule_left_on_another_commit_is_re_pinned(repo: Path) -> None:
    manifest = _manifest(repo)
    sub = repo / SUB
    pinned = _git(sub, "rev-parse", "HEAD")
    _write(sub, "lib/new.c", "later\n")
    _git(sub, "add", "-A")
    _git(sub, "commit", "-q", "-m", "moved on")
    assert _git(sub, "rev-parse", "HEAD") != pinned

    _refresh(repo, manifest)

    assert _git(sub, "rev-parse", "HEAD") == pinned


def test_untracked_files_in_a_submodule_survive_the_reset(repo: Path) -> None:
    """Tarball-only files copied into a submodule are untracked and excluded."""
    sub = repo / SUB
    _write(sub, "build/generated.h", "from the tarball\n")
    exclude = Path(_git(sub, "rev-parse", "--path-format=absolute",
                        "--git-path", "info/exclude"))
    exclude.write_text("/build/generated.h\n", encoding="utf-8")
    _write(sub, "lib/gl.c", "dirty\n")

    reset_submodule_worktrees(repo)

    assert (sub / "build" / "generated.h").read_text() == "from the tarball\n"
    assert (sub / "lib" / "gl.c").read_text() == "pinned\n"


def test_reset_is_a_noop_without_submodules(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    _init(plain)
    _write(plain, "a.c", "x\n")
    _git(plain, "add", "-A")
    _git(plain, "commit", "-q", "-m", "x")

    reset_submodule_worktrees(plain)

    assert (plain / "a.c").read_text() == "x\n"


def test_uninitialised_submodule_is_left_alone(repo: Path) -> None:
    _git(repo, "submodule", "deinit", "-f", SUB)

    reset_submodule_worktrees(repo)

    assert not (repo / SUB / ".git").exists()
