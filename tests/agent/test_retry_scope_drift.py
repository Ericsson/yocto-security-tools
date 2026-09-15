# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""A no-progress retry must not lose an earlier attempt's committed work.

Regression test for a real benchmark session (bench_20260915_120616,
CVE-2024-52532 / libsoup): attempt 1 resolved a conflict and committed its one
allowed file. The cherry-pick sequencer then advanced to the next commit in
the series and re-reported a conflict, so attempt 2 started with a narrower
``allowed`` set scoped only to *that* commit's file — attempt 1's file is no
longer in scope for attempt 2, even though it is already committed, already
authorized, and already durable.

Attempt 2's backend made zero tool calls that touched the repository (a
model that never produced a working file edit) and was killed for no
progress. Cleanup still ran: ``revert_unauthorized_changes`` saw attempt 1's
file in ``original-version..HEAD`` outside attempt 2's narrow ``allowed``
set, squashed it back out, and printed the "unauthorized file" warning.
``refresh_repository_handoff`` then diffed the session's start head against
the post-revert head, saw that regression, and raised
``HANDOFF_RETRY_SCOPE_DRIFT`` — crashing the whole CVE run on a retry that
never touched the repository at all.
"""
from __future__ import annotations

import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from cve_agent.git import revert_unauthorized_changes
from cve_agent.handoff import refresh_repository_handoff
from cve_corrector.handoff import emit_handoff
from cve_corrector.state import WorkflowState
from shared.handoff import HandoffError, read_handoff, write_handoff

CVE_ID = "CVE-2026-52532"
FIRST = "libsoup/soup-websocket-connection.c"
SECOND = "libsoup/other-file.c"


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, check=True,
                            capture_output=True, text=True)
    return result.stdout.strip()


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def _write(repo: Path, path: str, content: str) -> None:
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


@pytest.fixture
def two_file_repo(tmp_path: Path) -> Path:
    """A repo with two files, tagged as an original-version baseline."""
    repo = tmp_path / "build" / "workspace" / "sources" / "libsoup-2.4"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "upstream-history")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "commit.gpgsign", "false")

    _write(repo, FIRST, "base one\n")
    _write(repo, SECOND, "base two\n")
    _commit(repo, "base")

    _git(repo, "checkout", "-q", "-b", CVE_ID)
    _git(repo, "tag", "-f", "original-version")

    return repo


def _emit_and_reload(repo: Path, commit_hash: str, allowed_paths=None):
    """Round-trip a handoff through disk so path fields are real tuples.

    Mirrors what ``validate_repository_handoff`` does in production:
    ``emit_handoff`` returns a fresh dataclass with narrowed tuples, but
    tests overriding fields via ``to_dict()`` get JSON lists back, which
    trip the sorted/unique tuple check in ``validate()``. Reloading through
    ``read_handoff`` (as the real pipeline does) avoids that entirely.
    """
    state = WorkflowState(
        workspace_path=repo, cve_id=CVE_ID, recipe="libsoup-2.4",
        commit_hash=commit_hash, hash_details=[], meta_layer=None,
        skip_build=True, skip_ptest=True,
    )
    state_dir = repo.parent.parent / "cve_corrector"
    manifest = emit_handoff(state, state_dir)
    if allowed_paths is not None:
        manifest = replace(manifest, allowed_paths=tuple(sorted(allowed_paths)))
        manifest = manifest.with_digest()
    path = state_dir / "handoffs" / "libsoup-2.4.json"
    write_handoff(path, manifest)
    return read_handoff(path)


def test_second_attempt_with_no_progress_keeps_first_attempts_commit(
    two_file_repo: Path,
) -> None:
    """Zero-change retry cleanup must not strip a prior attempt's fix."""
    repo = two_file_repo

    # --- Attempt 1: resolves FIRST, commits it, matching that attempt's
    # narrow handoff scope. ---
    _write(repo, FIRST, "fixed one\n")
    first_head = _commit(repo, "websocket: fix the first conflict")
    manifest1 = _emit_and_reload(repo, first_head)
    assert manifest1.allowed_paths == (FIRST,)

    # Attempt 1's own cleanup: nothing unauthorized, nothing reverted.
    revert_unauthorized_changes(repo, {FIRST})
    assert _git(repo, "rev-parse", "HEAD") == first_head
    assert (repo / FIRST).read_text(encoding="utf-8") == "fixed one\n"

    # --- Attempt 2: a fresh handoff scoped only to SECOND's conflict — it
    # does not include attempt 1's already-committed file. ---
    manifest2 = _emit_and_reload(repo, first_head, allowed_paths={SECOND})
    pre_session_head = first_head  # HEAD at the start of attempt 2

    # Attempt 2's backend makes zero repository changes (the no-progress
    # crash scenario) — HEAD is unchanged going into cleanup.
    assert _git(repo, "rev-parse", "HEAD") == pre_session_head

    previously_committed = set(_git(
        repo, "diff", "--name-only", "original-version.." + pre_session_head,
    ).splitlines())
    assert previously_committed == {FIRST}

    # Cleanup must treat FIRST as authorized carry-over, not strip it.
    revert_unauthorized_changes(repo, {SECOND}, None, previously_committed)

    assert _git(repo, "rev-parse", "HEAD") == first_head, (
        "attempt 1's commit must survive a no-op attempt 2 cleanup")
    assert (repo / FIRST).read_text(encoding="utf-8") == "fixed one\n"

    # The handoff refresh for attempt 2 must not raise HANDOFF_RETRY_SCOPE_DRIFT.
    refreshed = refresh_repository_handoff(
        repo, manifest2, {SECOND},
        session_root_head=pre_session_head,
        previously_committed=previously_committed,
    )
    assert refreshed.current_head == _git(repo, "rev-parse", "HEAD")


def test_without_the_fix_a_noop_retry_strips_the_prior_commit(
    two_file_repo: Path,
) -> None:
    """Characterizes the bug: omitting previously_committed loses attempt 1."""
    repo = two_file_repo

    _write(repo, FIRST, "fixed one\n")
    first_head = _commit(repo, "websocket: fix the first conflict")
    pre_session_head = first_head

    # No previously_committed passed: mirrors the pre-fix call sites.
    revert_unauthorized_changes(repo, {SECOND})

    assert (repo / FIRST).read_text(encoding="utf-8") == "base one\n", (
        "demonstrates the bug: attempt 1's fix is reverted without the guard")

    manifest2 = _emit_and_reload(repo, first_head, allowed_paths={SECOND})

    with pytest.raises(HandoffError, match="HANDOFF_RETRY_SCOPE_DRIFT"):
        refresh_repository_handoff(
            repo, manifest2, {SECOND}, session_root_head=pre_session_head)
