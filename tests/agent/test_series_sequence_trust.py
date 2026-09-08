# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Trusted accounting for host-driven cherry-pick sequences.

Models the CVE-2024-52532 / libsoup deadlock with real git: a 3-commit fix
series whose follow-up commits touch a test file outside the model's writable
scope. ``git cherry-pick --continue`` applies every remaining commit in one
command, so the typed layer must account for the whole chain — and must undo
Git's commits when it refuses them, or the session is stranded on an untrusted
HEAD with no typed way back.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from cve_agent.git import revert_unauthorized_changes
from cve_agent.handoff import (
    activate_validated_handoff,
    deactivate_validated_handoff,
    validate_repository_handoff,
)
from cve_agent.openai_git_tools import GitToolRuntime
from cve_agent.openai_tools import ToolPolicyError
from cve_corrector.handoff import emit_handoff
from cve_corrector.state import WorkflowState

CVE_ID = "CVE-2026-52532"
SOURCE = "libsoup/soup-websocket-connection.c"
TESTS = "tests/websocket-test.c"


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
def series(tmp_path: Path) -> tuple[Path, list[str]]:
    """A conflicted 3-commit series: one source commit, two test commits."""
    repo = tmp_path / "build" / "workspace" / "sources" / "libsoup-2.4"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "upstream-history")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "commit.gpgsign", "false")

    _write(repo, SOURCE, "one\nprocess_incoming\ntwo\n")
    _write(repo, TESTS, "test-one\n")
    base = _commit(repo, "base")

    _write(repo, SOURCE, "one\nprocess_incoming(self)\ntwo\n")
    first = _commit(repo, "websocket: move process_incoming into the loop")
    _write(repo, TESTS, "test-one\ntest-two\n")
    second = _commit(repo, "websocket-test: add a regression test")
    _write(repo, TESTS, "test-one\ntest-two\ntest-three\n")
    third = _commit(repo, "websocket-test: disconnect the error signal")

    # Stable branch: the same region differs, so the first commit conflicts.
    _git(repo, "checkout", "-q", "-b", CVE_ID, base)
    _write(repo, SOURCE, "one\npv->process_incoming\ntwo\n")
    _commit(repo, "stable divergence")
    _git(repo, "tag", "-f", "original-version")
    assert subprocess.run(["git", "cherry-pick", first, second, third],
                          cwd=repo, capture_output=True).returncode != 0
    return repo, [first, second, third]


def _handoff(repo: Path, commits: list[str]):
    state = WorkflowState(
        workspace_path=repo, cve_id=CVE_ID, recipe="libsoup-2.4",
        commit_hash=commits[0], hash_details=[], meta_layer=None,
        skip_build=True, skip_ptest=True,
        series_state={"commits": commits},
    )
    manifest = emit_handoff(state, repo.parent.parent / "cve_corrector")
    validated = validate_repository_handoff(repo, CVE_ID, required=True)
    assert validated is not None
    return manifest, validated


def _resolve_conflict(repo: Path) -> None:
    _write(repo, SOURCE, "one\npv->process_incoming(self)\ntwo\n")
    _git(repo, "add", "--", SOURCE)


def test_corrector_declares_series_paths_outside_the_writable_scope(series) -> None:
    """The remaining commits' paths are authorized separately, not as allowed."""
    repo, commits = series
    manifest, _ = _handoff(repo, commits)

    assert manifest.allowed_paths == (SOURCE,)
    assert manifest.sequence_paths == (TESTS,)


def test_sequence_advance_is_trusted_and_scope_stays_narrow(series) -> None:
    """A multi-commit --continue is accounted for, without widening writes."""
    repo, commits = series
    _, validated = _handoff(repo, commits)
    _resolve_conflict(repo)
    token = activate_validated_handoff(validated)
    try:
        runtime = GitToolRuntime(repo, {SOURCE}, "gpt-test", 60)
        before = runtime.trusted_git_state.trusted_head
        result = runtime.dispatch("git_cherry_pick_continue", {})
    finally:
        deactivate_validated_handoff(token)

    assert result.success, result.payload
    transition = result.payload["trusted_transition"]
    assert len(transition["sequence_commits"]) == 3
    head = _git(repo, "rev-parse", "HEAD")
    assert transition["new_head"] == head
    assert transition["old_head"] == before
    assert runtime.trusted_git_state.trusted_head == head
    # The whole series landed, including the test-only follow-up commits.
    assert (repo / TESTS).read_text(encoding="utf-8").splitlines() == [
        "test-one", "test-two", "test-three"]
    assert _git(repo, "log", "--oneline", f"{before}..HEAD", "--format=%s").count("\n") == 2
    # The model's writable scope was not widened by the sequence authorization.
    with pytest.raises(ToolPolicyError):
        runtime.policy.authorize_write(TESTS)


def test_rejected_advance_rolls_back_instead_of_stranding_the_session(series) -> None:
    """Without sequence authorization the commits are undone, not left behind."""
    repo, commits = series
    _, validated = _handoff(repo, commits)
    # Simulate the pre-fix manifest: the series' follow-up paths are unauthorized.
    stripped = validated.__class__(
        **{**validated.to_dict(), "sequence_paths": (), "critical_sha256": ""},
    ).with_digest()
    _resolve_conflict(repo)
    token = activate_validated_handoff(stripped)
    try:
        runtime = GitToolRuntime(repo, {SOURCE}, "gpt-test", 60)
        before = runtime.trusted_git_state.trusted_head
        rejected = runtime.dispatch("git_cherry_pick_continue", {})
        # The session is still usable: HEAD is trusted again, so typed
        # operations are accepted rather than permanently refused.
        status = runtime.dispatch("git_status", {})
    finally:
        deactivate_validated_handoff(token)

    assert rejected.success is False
    assert rejected.error_kind == "policy"
    assert TESTS in rejected.payload["rejected_paths"]
    assert _git(repo, "rev-parse", "HEAD") == before
    assert runtime.trusted_git_state.trusted_head == before
    assert not (repo / ".git" / "CHERRY_PICK_HEAD").exists()
    assert not (repo / ".git" / "sequencer").exists()
    assert status.success is True


def test_cleanup_keeps_sequence_paths_and_the_fix_subject(series) -> None:
    """The post-session cleanup must not mutilate an applied series."""
    repo, commits = series
    _, validated = _handoff(repo, commits)
    _resolve_conflict(repo)
    token = activate_validated_handoff(validated)
    try:
        runtime = GitToolRuntime(repo, {SOURCE}, "gpt-test", 60)
        assert runtime.dispatch("git_cherry_pick_continue", {}).success
    finally:
        deactivate_validated_handoff(token)

    revert_unauthorized_changes(repo, {SOURCE}, set(validated.sequence_paths))

    # Nothing was squashed or stripped: all three commits and both files remain.
    assert len(_git(repo, "rev-list", "original-version..HEAD").split()) == 3
    assert (repo / TESTS).read_text(encoding="utf-8").count("test-") == 3


def test_cleanup_squash_uses_the_first_commit_subject(series) -> None:
    """When a squash is unavoidable, keep the fix's subject, not the last one."""
    repo, commits = series
    _, validated = _handoff(repo, commits)
    _resolve_conflict(repo)
    token = activate_validated_handoff(validated)
    try:
        runtime = GitToolRuntime(repo, {SOURCE}, "gpt-test", 60)
        assert runtime.dispatch("git_cherry_pick_continue", {}).success
    finally:
        deactivate_validated_handoff(token)
    first_subject = _git(repo, "log", "--format=%s", "-1",
                         _git(repo, "rev-list", "original-version..HEAD").split()[-1])

    # No sequence authorization here, so the test file is stripped and the
    # remaining commits are squashed into one.
    revert_unauthorized_changes(repo, {SOURCE})

    assert len(_git(repo, "rev-list", "original-version..HEAD").split()) == 1
    assert _git(repo, "log", "-1", "--format=%s") == first_subject
    assert "process_incoming(self)" in (repo / SOURCE).read_text(encoding="utf-8")
    assert (repo / TESTS).read_text(encoding="utf-8") == "test-one\n"
