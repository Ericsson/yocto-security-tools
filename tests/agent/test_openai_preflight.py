# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Deterministic repository preflight and large dirty-state regressions."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from cve_agent.artifacts import ArtifactError
from cve_agent.openai_deadline import SessionDeadline
from cve_agent.openai_git_tools import (
    GitCommandExecutor,
    GitCommandResult,
    GitToolLimits,
)
from cve_agent.openai_preflight import (
    PreflightErrorCode,
    PreflightPhase,
    PreflightResult,
    RepositoryPreflight,
)
from cve_agent.session import guarded_session


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True,
        text=True, encoding="utf-8",
    ).stdout.strip()


def _repo(path: Path) -> Path:
    path.mkdir()
    _git(path, "init", "-q")
    _git(path, "config", "user.name", "Test User")
    _git(path, "config", "user.email", "test@example.invalid")
    (path / "allowed.c").write_text("base\n", encoding="utf-8")
    _git(path, "add", "allowed.c")
    _git(path, "commit", "-qm", "base")
    return path


def _preflight(repo: Path, allowed: tuple[str, ...] = ("allowed.c",), **kwargs):
    return RepositoryPreflight(
        repo, allowed, SessionDeadline.from_timeout(30), **kwargs).run()


def test_large_vim_style_tracked_state_exceeds_old_status_limit_but_preflights(tmp_path):
    repo = _repo(tmp_path / "vim")
    generated = repo / "generated"
    generated.mkdir()
    paths = []
    for index in range(1200):
        name = f"vim-generated-{index:04d}-" + ("x" * 190)
        path = generated / name
        path.write_text("generated\n", encoding="utf-8")
        paths.append(path)
    _git(repo, "add", "generated")
    _git(repo, "commit", "-qm", "generated baseline")
    for index, path in enumerate(paths):
        if index % 3 == 0:
            path.unlink()
        else:
            path.write_text("changed\n", encoding="utf-8")

    executor = GitCommandExecutor(repo, SessionDeadline.from_timeout(30), GitToolLimits())
    old = executor.run(
        "status", ["status", "--porcelain=v2", "-z", "--branch", "--untracked-files=all"])
    result = _preflight(repo)

    assert old.stdout_truncated is True
    assert result.ok is True
    assert result.status_counts["modified"] == 800
    assert result.status_counts["deleted"] == 400
    assert result.out_of_scope_count == 1200
    assert len(result.sample_paths) <= 32
    assert result.resource_bytes < 8 * 1024 * 1024


def test_go_style_long_tree_has_complete_decision_and_bounded_diagnostic(tmp_path):
    repo = _repo(tmp_path / "go")
    for index in range(300):
        path = repo / "pkg" / f"module-{index:04d}" / ("nested-" + "y" * 80 + ".go")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("package generated\n", encoding="utf-8")
    result = _preflight(repo)

    assert result.ok
    assert result.status_counts["untracked"] == 300
    assert len(result.sample_paths) == 32
    assert result.sample_truncated is True
    assert len(str(result.to_dict())) < 16_000


def test_libpcap_style_cherry_pick_conflict_is_supported(tmp_path):
    repo = _repo(tmp_path / "libpcap")
    base_branch = _git(repo, "branch", "--show-current")
    _git(repo, "checkout", "-qb", "upstream")
    (repo / "allowed.c").write_text("upstream\n", encoding="utf-8")
    _git(repo, "commit", "-qam", "upstream")
    commit = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", base_branch)
    (repo / "allowed.c").write_text("downstream\n", encoding="utf-8")
    _git(repo, "commit", "-qam", "downstream")
    subprocess.run(
        ["git", "cherry-pick", commit], cwd=repo, capture_output=True, check=False)

    result = _preflight(repo)

    assert result.ok
    assert result.operations["cherry_pick"] is True
    assert result.status_counts["unmerged"] == 1


@pytest.mark.skipif(os.name == "nt", reason="POSIX filename fixture")
def test_nul_delimited_status_preserves_unusual_valid_filenames(tmp_path):
    repo = _repo(tmp_path / "odd")
    odd = "odd name\twith-tab\nand-newline.c"
    (repo / odd).write_text("base\n", encoding="utf-8")
    _git(repo, "add", odd)
    _git(repo, "commit", "-qm", "odd")
    (repo / odd).write_text("changed\n", encoding="utf-8")

    result = _preflight(repo, (odd,))

    assert result.ok
    assert result.sample_paths == (odd,)


def test_workspace_change_during_capture_has_stable_code(tmp_path):
    repo = _repo(tmp_path / "race")

    def mutate():
        (repo / "allowed.c").write_text("raced\n", encoding="utf-8")

    result = _preflight(repo, between_captures=mutate)

    assert not result.ok
    assert result.error_code is PreflightErrorCode.WORKSPACE_CHANGED_DURING_CAPTURE


def test_dirty_out_of_scope_policy_uses_complete_set_with_bounded_sample(tmp_path):
    repo = _repo(tmp_path / "dirty")
    for index in range(60):
        path = repo / f"generated-{index}.c"
        path.write_text("base\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "generated")
    for index in range(60):
        (repo / f"generated-{index}.c").write_text("dirty\n", encoding="utf-8")

    result = _preflight(repo, reject_out_of_scope=True)

    assert result.error_code is PreflightErrorCode.DIRTY_OUT_OF_SCOPE
    assert result.out_of_scope_count == 60
    assert len(result.sample_paths) == 32
    assert result.sample_truncated


def test_generated_classification_excludes_known_corrector_outputs(tmp_path):
    repo = _repo(tmp_path / "generated-known")
    (repo / "generated.c").write_text("base\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "generated")
    (repo / "generated.c").write_text("dirty\n", encoding="utf-8")

    result = _preflight(
        repo, generated_files=("generated.c",), reject_out_of_scope=True)

    assert result.ok
    assert result.generated_path_count == 1
    assert result.out_of_scope_count == 0


def test_symlink_status_does_not_follow_target_outside_repository(tmp_path):
    repo = _repo(tmp_path / "symlink")
    outside = tmp_path / "secret"
    outside.write_text("outside\n", encoding="utf-8")
    (repo / "untracked-link").symlink_to(outside)

    result = _preflight(repo)

    assert result.ok
    assert result.status_counts["untracked"] == 1
    assert "outside" not in str(result.to_dict())


@pytest.mark.parametrize(
    ("workspace", "allowed", "code"),
    [
        ("missing", ("allowed.c",), PreflightErrorCode.REPOSITORY_UNAVAILABLE),
        ("repo", (), PreflightErrorCode.EMPTY_ALLOWED_SCOPE),
        ("repo", ("../escape",), PreflightErrorCode.INVALID_ALLOWED_SCOPE),
    ],
)
def test_early_preflight_error_codes(tmp_path, workspace, allowed, code):
    repo = _repo(tmp_path / "repo")
    selected = tmp_path / "missing" if workspace == "missing" else repo

    result = _preflight(selected, allowed)

    assert result.error_code is code


def test_unsupported_merge_state_has_specific_code(tmp_path):
    repo = _repo(tmp_path / "merge")
    (repo / ".git" / "MERGE_HEAD").write_text("0" * 40 + "\n", encoding="ascii")

    result = _preflight(repo)

    assert result.error_code is PreflightErrorCode.UNSUPPORTED_GIT_OPERATION_STATE


@pytest.mark.parametrize(
    ("fault", "code"),
    [
        ("malformed", PreflightErrorCode.GIT_STATUS_FAILED),
        ("status_rc", PreflightErrorCode.GIT_STATUS_FAILED),
        ("truncated", PreflightErrorCode.BASELINE_CAPTURE_LIMIT),
    ],
)
def test_injected_git_status_failures_have_specific_codes(tmp_path, fault, code):
    repo = _repo(tmp_path / fault)

    class FaultExecutor(GitCommandExecutor):
        def run(self, operation, argv, output_limit=None):
            if operation == "preflight_status":
                if fault == "malformed":
                    return GitCommandResult(0, "malformed\0", "", False, False)
                if fault == "status_rc":
                    return GitCommandResult(1, "", "bounded failure", False, False)
                return GitCommandResult(0, "", "", True, False)
            return super().run(operation, argv, output_limit)

    result = _preflight(repo, executor_factory=FaultExecutor)

    assert result.error_code is code
    assert len(str(result.to_dict())) < 16_000


def test_executor_initialization_failure_is_not_generic(tmp_path):
    repo = _repo(tmp_path / "executor-failure")

    def fail_factory(*args, **kwargs):
        raise RuntimeError("injected executor failure with hostile details")

    result = _preflight(repo, executor_factory=fail_factory)

    assert result.error_code is PreflightErrorCode.BASELINE_CAPTURE_FAILED
    assert "hostile details" not in str(result.to_dict())


def test_path_policy_initialization_failure_has_specific_code(tmp_path):
    repo = _repo(tmp_path / "policy-failure")

    with patch("cve_agent.openai_preflight.FileToolPathPolicy",
               side_effect=ValueError("injected path policy failure")):
        result = _preflight(repo)

    assert result.error_code is PreflightErrorCode.PATH_POLICY_FAILED


def _failure_result(code: PreflightErrorCode) -> PreflightResult:
    return PreflightResult(
        False, PreflightPhase.BASELINE_CAPTURE, code, None, None, None, None,
        False, {}, {}, (), False, 1, None, 0, 0, None, 0,
    )


def test_failed_preflight_makes_zero_backend_calls(tmp_path):
    repo = _repo(tmp_path / "provider-zero")
    context = tmp_path / "context.md"
    context.write_text("context", encoding="utf-8")
    backend = Mock()
    backend.run_session = Mock()

    with patch("cve_agent.session._ensure_cve_branch"), \
         patch("cve_agent.session.get_all_upstream_shas", return_value=[]), \
         patch("cve_agent.session.compute_allowed_files",
               return_value={"allowed.c"}), \
         patch("cve_agent.session.run_git_stdout", side_effect=["allowed.c", ""]), \
         patch("cve_agent.session.RepositoryPreflight.run",
               return_value=_failure_result(PreflightErrorCode.GIT_STATUS_FAILED)), \
         patch("cve_agent.session.get_backend", return_value=backend):
        result = guarded_session(
            context, repo, "", {}, cve_id="CVE-1", backend_name="openai")

    assert not result.resolved
    assert result.failure_reason.endswith("INIT_GIT_STATUS_FAILED")
    backend.run_session.assert_not_called()


def test_transcript_failure_has_specific_code_and_zero_backend_calls(tmp_path):
    repo = _repo(tmp_path / "transcript-zero")
    context = tmp_path / "context.md"
    context.write_text("context", encoding="utf-8")
    backend = Mock()
    backend.run_session = Mock()
    bad_artifacts = Mock()
    bad_artifacts.atomic_json.side_effect = ArtifactError("audit unavailable")
    good = RepositoryPreflight(
        repo, ("allowed.c",), SessionDeadline.from_timeout(30)).run()
    assert good.ok

    with patch("cve_agent.session._ensure_cve_branch"), \
         patch("cve_agent.session.get_all_upstream_shas", return_value=[]), \
         patch("cve_agent.session.compute_allowed_files",
               return_value={"allowed.c"}), \
         patch("cve_agent.session.run_git_stdout", side_effect=["allowed.c", ""]), \
         patch("cve_agent.session.RepositoryPreflight.run", return_value=good), \
         patch("cve_agent.session.current_run_artifacts", return_value=bad_artifacts), \
         patch("cve_agent.session.get_backend", return_value=backend):
        result = guarded_session(
            context, repo, "", {}, cve_id="CVE-1", backend_name="openai")

    assert result.failure_reason.endswith("INIT_TRANSCRIPT_FAILED")
    backend.run_session.assert_not_called()


def test_all_required_error_codes_are_stable_and_unique():
    assert {code.value for code in PreflightErrorCode} == {
        "INIT_REPOSITORY_UNAVAILABLE",
        "INIT_GIT_STATUS_FAILED",
        "INIT_UNSUPPORTED_GIT_OPERATION_STATE",
        "INIT_INVALID_ALLOWED_SCOPE",
        "INIT_EMPTY_ALLOWED_SCOPE",
        "INIT_DIRTY_OUT_OF_SCOPE",
        "INIT_BASELINE_CAPTURE_FAILED",
        "INIT_BASELINE_CAPTURE_LIMIT",
        "INIT_PATH_POLICY_FAILED",
        "INIT_TRANSCRIPT_FAILED",
        "INIT_WORKSPACE_CHANGED_DURING_CAPTURE",
    }
