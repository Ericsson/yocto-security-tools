# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""A failed handoff leaves its manifest and the failing check's facts behind.

ncurses CVE-2025-69720 and xwayland CVE-2025-26594 both ended as
``HANDOFF_REFERENCE_DRIFT``. The manifest that failed was the one the agent had
refreshed after an earlier attempt, it lived only in the workspace (deleted
when the CVE ended), and ``corrector-handoff.json`` is written only after a
*successful* validation, so the cause had to be reconstructed from code. The
failure itself now produces ``handoff-failure.json``, and a refresh produces
``corrector-handoff-refreshed.json``.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from cve_agent import session
from cve_agent.artifacts import RunArtifacts
from cve_agent.backend import SessionResult
from cve_agent.handoff import (
    MAX_FAILURE_PATHS,
    handoff_failure_record,
    refresh_repository_handoff,
    repository_handoff_path,
    validate_repository_handoff,
)
from cve_corrector.handoff import emit_handoff
from cve_corrector.state import WorkflowState
from shared.handoff import HandoffError, read_handoff, write_handoff

CVE_ID = "CVE-2026-26594"
FIXED = "dix/dispatch.c"
OTHER = "dix/main.c"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True,
                          capture_output=True, text=True).stdout.strip()


def _write(repo: Path, path: str, text: str) -> None:
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "build" / "workspace" / "sources" / "xwayland"
    root.mkdir(parents=True)
    _git(root, "init", "-q", "-b", "main")
    for key, value in (("user.name", "T"), ("user.email", "t@t.com"),
                       ("commit.gpgsign", "false")):
        _git(root, "config", key, value)
    _write(root, FIXED, "base\n")
    _write(root, OTHER, "base\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    _git(root, "checkout", "-q", "-b", CVE_ID)
    _git(root, "tag", "-f", "original-version")
    _write(root, FIXED, "fixed\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "dix: fix")
    return root


def _manifest(repo: Path, **changes):
    state = WorkflowState(
        workspace_path=repo, cve_id=CVE_ID, recipe="xwayland",
        commit_hash=_git(repo, "rev-parse", "HEAD"), hash_details=[],
        meta_layer=None, skip_build=True, skip_ptest=True)
    state_dir = repo.parent.parent / "cve_corrector"
    manifest = emit_handoff(state, state_dir)
    if changes:
        manifest = replace(manifest, **changes).with_digest()
    path = state_dir / "handoffs" / "xwayland.json"
    write_handoff(path, manifest)
    return read_handoff(path)


@pytest.fixture
def artifacts(tmp_path: Path):
    run = RunArtifacts.create("CVE-1", "openai", None, "model", root=tmp_path / "out")
    token = run.activate()
    yield run
    RunArtifacts.deactivate(token)


def _session(repo: Path):
    return session.guarded_session(
        repo / "ctx.md", repo, "0" * 40, {}, cve_id=CVE_ID, require_handoff=True)


def _failure(run: RunArtifacts) -> dict:
    return json.loads((run.path / "handoff-failure.json").read_text())


def test_reference_drift_records_the_paths_that_disagree(
        repo: Path, artifacts: RunArtifacts) -> None:
    """The very state a refresh leaves behind: allowed_paths out of step."""
    _manifest(repo, allowed_paths=(FIXED, OTHER))

    result = _session(repo)

    assert result.outcome is not None
    assert result.outcome.failure_code == "HANDOFF_REFERENCE_DRIFT"
    record = _failure(artifacts)
    assert record["phase"] == "validate"
    assert record["code"] == "HANDOFF_REFERENCE_DRIFT"
    details = record["details"]
    assert details["allowed_not_expected"]["paths"] == [OTHER]
    assert details["expected_not_allowed"]["paths"] == []
    assert details["reference_paths"]["paths"] == [FIXED]
    assert details["selected_commit"] == record["manifest"]["selected_commit"]
    assert record["manifest"]["allowed_paths"] == [FIXED, OTHER]


def test_failure_record_code_matches_the_logged_failure_event(
        repo: Path, artifacts: RunArtifacts) -> None:
    _manifest(repo, allowed_paths=(FIXED, OTHER))

    _session(repo)

    events = [json.loads(line) for line in
              (artifacts.path / "agent-transcript.jsonl").read_text().splitlines()]
    failed = [e for e in events if e["event"] == "corrector_handoff_failed"]
    assert [e["failure_code"] for e in failed] == [_failure(artifacts)["code"]]


def test_a_successful_validation_writes_no_failure_record(
        repo: Path, artifacts: RunArtifacts) -> None:
    _manifest(repo)
    assert validate_repository_handoff(repo, CVE_ID, required=True) is not None
    assert not (artifacts.path / "handoff-failure.json").exists()


def test_record_survives_an_unreadable_manifest(repo: Path) -> None:
    error = HandoffError("HANDOFF_MISSING", "corrector manifest is unavailable")
    path = repository_handoff_path(repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")

    record = handoff_failure_record(repo, "validate", error)

    assert record["code"] == "HANDOFF_MISSING"
    assert record["manifest"] is None
    assert record["manifest_error"]


def test_scope_drift_details_name_the_unauthorized_paths(repo: Path) -> None:
    manifest = _manifest(repo)
    _write(repo, OTHER, "changed outside the fix\n")
    _git(repo, "add", OTHER)

    with pytest.raises(HandoffError) as raised:
        refresh_repository_handoff(
            repo, manifest, {FIXED},
            session_root_head=_git(repo, "rev-parse", "HEAD"))

    assert raised.value.code == "HANDOFF_RETRY_SCOPE_DRIFT"
    assert raised.value.details["unauthorized_tracked_paths"] == {
        "count": 1, "paths": [OTHER]}


def test_path_lists_in_a_record_are_bounded(repo: Path) -> None:
    extra = tuple(f"gen/f{index:04d}.c" for index in range(MAX_FAILURE_PATHS + 30))
    _manifest(repo, allowed_paths=tuple(sorted((FIXED, *extra))))

    with pytest.raises(HandoffError) as raised:
        validate_repository_handoff(repo, CVE_ID, required=True)

    listed = raised.value.details["allowed_not_expected"]
    assert listed["count"] == len(extra)
    assert len(listed["paths"]) == MAX_FAILURE_PATHS


class _UnresolvedBackend:
    """A backend whose session ends unresolved without touching the repo."""

    def run_session(self, *_args, **_kwargs) -> SessionResult:
        return SessionResult(resolved=False, duration=1.0, failure_reason="stub")


def test_refresh_after_an_unresolved_session_keeps_the_refreshed_manifest(
        repo: Path, artifacts: RunArtifacts) -> None:
    _manifest(repo)
    with patch.object(session, "get_backend", return_value=_UnresolvedBackend()):
        result = _session(repo)

    assert result.failure_reason == "stub"
    saved = json.loads((artifacts.path / "corrector-handoff-refreshed.json").read_text())
    assert saved["current_head"] == _git(repo, "rev-parse", "HEAD")
    assert saved["cve"] == CVE_ID
