# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent.context — full context building."""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from cve_agent import EXIT_BUILD_ERROR, EXIT_CONFLICT, EXIT_PTEST_ERROR
from cve_agent.context import (
    _build_header,
    _find_ptest_log,
    _find_state_file,
    _gather_analysis_context,
    _gather_build_error_context,
    _gather_conflict_context,
    _gather_context_for_exit_code,
    _gather_knowledge,
    _gather_ptest_error_context,
    _get_conflicted_files,
    _read_ptest_results,
    build_context,
)


class TestBuildHeader:
    @patch("cve_agent.context.compute_allowed_files", return_value={"file.c"})
    @patch("cve_agent.context.get_all_upstream_shas", return_value=["abc123"])
    @patch("cve_agent.context.get_upstream_sha", return_value="abc123")
    @patch("cve_agent.context.run_git_stdout", return_value="file.c")
    def test_conflict_phase(self, mock_git, mock_sha, mock_all, mock_allowed,
                            tmp_path):
        result = _build_header("CVE-1", "busybox", EXIT_CONFLICT, tmp_path, {})
        assert "CONFLICT RESOLUTION" in result
        assert "busybox" in result
        assert "file.c" in result

    @patch("cve_agent.context.get_all_upstream_shas", return_value=["a1", "b2"])
    @patch("cve_agent.context.get_upstream_sha", return_value="a1")
    @patch("cve_agent.context.run_git_stdout", return_value="f.c")
    def test_multi_sha_display(self, mock_git, mock_sha, mock_all, tmp_path):
        result = _build_header("CVE-1", "r", 0, tmp_path, {})
        assert "a1" in result and "b2" in result

    @patch("cve_agent.context.get_all_upstream_shas", return_value=["abc"])
    @patch("cve_agent.context.get_upstream_sha", return_value="abc")
    @patch("cve_agent.context.run_git_stdout", return_value="")
    def test_build_error_phase(self, mock_git, mock_sha, mock_all, tmp_path):
        result = _build_header("CVE-1", "r", EXIT_BUILD_ERROR, tmp_path, {})
        assert "BUILD ERROR" in result

    @patch("cve_agent.context.get_all_upstream_shas", return_value=["abc"])
    @patch("cve_agent.context.get_upstream_sha", return_value="abc")
    @patch("cve_agent.context.run_git_stdout", return_value="")
    def test_ptest_error_phase(self, mock_git, mock_sha, mock_all, tmp_path):
        result = _build_header("CVE-1", "r", EXIT_PTEST_ERROR, tmp_path, {})
        assert "TEST FAILURE" in result

    @patch("cve_agent.context.get_all_upstream_shas", return_value=["abc"])
    @patch("cve_agent.context.get_upstream_sha", return_value="abc")
    @patch("cve_agent.context.run_git_stdout", return_value="")
    def test_unknown_exit_code(self, mock_git, mock_sha, mock_all, tmp_path):
        result = _build_header("CVE-1", "r", 99, tmp_path, {})
        assert "ERROR (exit 99)" in result

    @patch("cve_agent.context.get_all_upstream_shas", return_value=["abc"])
    @patch("cve_agent.context.get_upstream_sha", return_value="abc")
    @patch("cve_agent.context.run_git_stdout", return_value="")
    def test_yocto_tmp_dir(self, mock_git, mock_sha, mock_all, tmp_path):
        ws = tmp_path / "build" / "workspace" / "sources" / "busybox"
        ws.mkdir(parents=True)
        build_dir = tmp_path / "build"
        (build_dir / "tmp-glibc").mkdir()
        result = _build_header("CVE-1", "busybox", 0, ws, {})
        assert "tmp-glibc" in result

    @patch("cve_agent.context.get_all_upstream_shas", return_value=["abc"])
    @patch("cve_agent.context.get_upstream_sha", return_value="abc")
    @patch("cve_agent.context.run_git_stdout", return_value="")
    def test_working_dir_does_not_instruct_cd(self, mock_git, mock_sha, mock_all, tmp_path):
        """The header must not render a runnable `cd <path>` — the shell
        already runs in the workspace, and a `cd ... && cmd` wrapper is
        rejected by the command allow-list. Regression guard for the
        `cd /ws && git status` rejection."""
        result = _build_header("CVE-1", "busybox", EXIT_CONFLICT, tmp_path, {})
        assert f"cd {tmp_path}" not in result
        assert "bare" in result.lower()


class TestGatherContextForExitCode:
    @patch("cve_agent.context._gather_conflict_context", return_value="conflict")
    def test_conflict(self, mock):
        assert _gather_context_for_exit_code(Path("/ws"), EXIT_CONFLICT, {}) == "conflict"

    @patch("cve_agent.context._gather_build_error_context", return_value="build")
    def test_build_error(self, mock):
        assert _gather_context_for_exit_code(Path("/ws"), EXIT_BUILD_ERROR, {}) == "build"

    @patch("cve_agent.context._gather_ptest_error_context", return_value="ptest")
    def test_ptest_error(self, mock):
        assert _gather_context_for_exit_code(Path("/ws"), EXIT_PTEST_ERROR, {}) == "ptest"

    @patch("cve_agent.context._gather_analysis_context", return_value="analysis")
    def test_success(self, mock):
        assert _gather_context_for_exit_code(Path("/ws"), 0, {}) == "analysis"


class TestGatherConflictContext:
    @patch("cve_agent.context.run_git_stdout")
    @patch("cve_agent.context.get_upstream_sha", return_value="abc123")
    @patch("cve_agent.context._get_conflicted_files", return_value=["a.c"])
    def test_basic(self, mock_files, mock_sha, mock_git):
        mock_git.side_effect = ["M a.c", "stat output", "log output"]
        result = _gather_conflict_context(Path("/ws"), {})
        assert "Conflict Details" in result
        assert "a.c" in result


class TestGatherBuildErrorContext:
    @patch("cve_agent.context.run_git_stdout", return_value="commit stat")
    def test_basic(self, _):
        result = _gather_build_error_context(Path("/ws"))
        assert "Build Error" in result
        assert "commit stat" in result
        # The stale-sstate recovery guidance now lives in the build.md phase
        # fragment (embedded alongside this section), not duplicated here.
        assert ".config.orig" not in result
        assert "cleansstate" not in result


class TestGatherPtestErrorContext:
    @patch("cve_agent.context.get_upstream_sha", return_value="3fb6b31c7166")
    @patch("cve_agent.context._read_ptest_results", return_value="ptest data")
    @patch("cve_agent.context.run_git_stdout", return_value="commit stat")
    def test_basic(self, *_):
        result = _gather_ptest_error_context(Path("/ws"), {})
        assert "Test Failure" in result
        assert "ptest data" in result
        # The concrete upstream SHA stays in the data section for `git show`.
        assert "3fb6b31c7166" in result
        # The defect-vs-companion-commit triage prose now lives in the ptest.md
        # phase fragment (embedded alongside this section), not duplicated here.
        assert "Never hand-edit" not in result
        assert "suggested_commits" not in result


class TestGatherAnalysisContext:
    @patch("cve_agent.context.run_git_stdout")
    @patch("cve_agent.context.get_upstream_sha", return_value="abc123")
    def test_with_upstream(self, mock_sha, mock_git):
        mock_git.side_effect = ["abc Fix CVE", "stat output"]
        result = _gather_analysis_context(Path("/ws"), {})
        assert "Patch Analysis" in result
        assert "Upstream Commit" in result

    @patch("cve_agent.context.run_git_stdout", return_value="abc Fix CVE")
    @patch("cve_agent.context.get_upstream_sha", return_value="")
    def test_no_upstream(self, *_):
        result = _gather_analysis_context(Path("/ws"), {})
        assert "Patch Analysis" in result


class TestReadPtestResults:
    @patch("cve_agent.context._find_ptest_log", return_value=None)
    @patch("cve_agent.context._find_state_file")
    def test_with_state_file(self, mock_state, mock_log, tmp_path):
        state = tmp_path / "state.json"
        state.write_text(json.dumps({"ptest_before": "PASS: 10\nFAIL: 0"}))
        mock_state.return_value = state
        ws = tmp_path / "build" / "workspace" / "sources" / "busybox"
        ws.mkdir(parents=True)
        result = _read_ptest_results(ws)
        assert "Before patch" in result

    @patch("cve_agent.context._find_ptest_log", return_value=None)
    @patch("cve_agent.context._find_state_file")
    def test_surfaces_ptest_after_failing_cases(self, mock_state, mock_log, tmp_path):
        """The post-patch summary — including the Failing cases: list — must
        reach the context so the agent knows which cases to investigate."""
        summary = ("PASSED: 620, FAILED: 2, SKIPPED: 90, ABORTED: 0\n"
                   "Failing cases:\n"
                   "  tar Pax-encoded UTF8 names and symlinks\n"
                   "  tar Symlinks and hardlinks coexist")
        state = tmp_path / "state.json"
        state.write_text(json.dumps({
            "ptest_before": "PASSED: 622, FAILED: 0, SKIPPED: 90, ABORTED: 0",
            "ptest_after": summary,
        }))
        mock_state.return_value = state
        ws = tmp_path / "build" / "workspace" / "sources" / "busybox"
        ws.mkdir(parents=True)
        result = _read_ptest_results(ws)
        assert "After patch" in result
        assert "tar Pax-encoded UTF8 names and symlinks" in result
        assert "tar Symlinks and hardlinks coexist" in result
        assert "investigate" in result.lower()

    @patch("cve_agent.context._find_ptest_log", return_value=None)
    @patch("cve_agent.context._find_state_file", return_value=None)
    def test_no_data(self, *_):
        result = _read_ptest_results(Path("/build/workspace/sources/r"))
        assert "No ptest result data" in result

    @patch("cve_agent.context._find_state_file", return_value=None)
    def test_with_ptest_log(self, _, tmp_path):
        ws = tmp_path / "build" / "workspace" / "sources" / "busybox"
        ws.mkdir(parents=True)
        log = tmp_path / "ptest.log"
        log.write_text("PASS: test1\nFAIL: test2\nFAIL: test3")
        with patch("cve_agent.context._find_ptest_log", return_value=log):
            result = _read_ptest_results(ws)
        assert "Failing test cases" in result


class TestFindPtestLog:
    def test_found(self, tmp_path):
        log_dir = tmp_path / "tmp-glibc" / "work" / "x86" / "core-image-minimal" / "1.0" / "testimage" / "ptest_log" / "busybox"
        log_dir.mkdir(parents=True)
        result = _find_ptest_log(tmp_path, "busybox")
        assert result is not None

    def test_not_found(self, tmp_path):
        assert _find_ptest_log(tmp_path, "busybox") is None


class TestFindStateFile:
    def test_found(self, tmp_path):
        """Must look where the corrector saves state:
        <build>/workspace/cve_corrector/<recipe>.json (two levels up from the
        recipe source dir), not <build>/cve_corrector."""
        ws = tmp_path / "build" / "workspace" / "sources" / "busybox"
        ws.mkdir(parents=True)
        state_dir = tmp_path / "build" / "workspace" / "cve_corrector"
        state_dir.mkdir(parents=True)
        state_file = state_dir / "busybox.json"
        state_file.write_text("{}")
        assert _find_state_file(ws) == state_file

    def test_not_at_build_root(self, tmp_path):
        """A state file one level too high (the old buggy location) is ignored."""
        ws = tmp_path / "build" / "workspace" / "sources" / "busybox"
        ws.mkdir(parents=True)
        wrong = tmp_path / "build" / "cve_corrector"
        wrong.mkdir(parents=True)
        (wrong / "busybox.json").write_text("{}")
        assert _find_state_file(ws) is None

    def test_not_found(self, tmp_path):
        ws = tmp_path / "build" / "workspace" / "sources" / "busybox"
        ws.mkdir(parents=True)
        assert _find_state_file(ws) is None


class TestGetConflictedFiles:
    @patch("subprocess.run")
    def test_with_conflicts(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="a.c\nb.c\n")
        assert _get_conflicted_files(Path("/ws")) == ["a.c", "b.c"]

    @patch("subprocess.run")
    def test_git_error(self, mock_run):
        mock_run.return_value = MagicMock(returncode=128, stdout="")
        assert _get_conflicted_files(Path("/ws")) == []


class TestGatherKnowledge:
    def test_none_kb(self):
        assert _gather_knowledge(None, "r", Path("/ws")) == ""

    @patch("cve_agent.context._get_conflicted_files", return_value=["a.c"])
    def test_no_similar(self, _):
        kb = MagicMock()
        kb.find_similar.return_value = []
        assert _gather_knowledge(kb, "r", Path("/ws")) == ""

    @patch("cve_agent.context._get_conflicted_files", return_value=["a.c"])
    def test_with_similar(self, _):
        pattern = MagicMock()
        pattern.cve_id = "CVE-1"
        pattern.recipe = "busybox"
        pattern.resolution_summary = "adapted"
        pattern.upstream_sha = "abc"
        pattern.affected_files = ["a.c"]
        pattern.per_file_changes = {"a.c": "adapted"}
        pattern.diff_stat = "+1 -1"
        pattern.commit_message = "Fix CVE"
        kb = MagicMock()
        kb.find_similar.return_value = [pattern]
        result = _gather_knowledge(kb, "busybox", Path("/ws"))
        assert "CVE-1" in result
        assert "adapted" in result


class TestBuildContext:
    @patch("cve_agent.context._gather_knowledge", return_value="")
    @patch("cve_agent.context._gather_context_for_exit_code", return_value="## Details")
    @patch("cve_agent.context._build_phase_instructions", return_value="## Instructions")
    @patch("cve_agent.context._build_header", return_value="# Header")
    @patch("cve_agent.context.get_agent_dir")
    def test_basic(self, mock_dir, mock_hdr, mock_instr, mock_ctx, mock_kb, tmp_path):
        agent_dir = tmp_path / "agent"
        agent_dir.mkdir()
        mock_dir.return_value = agent_dir
        result = build_context(Path("/ws"), 0, "CVE-1", {"name": "r"})
        assert result.exists()
        content = result.read_text()
        assert "Header" in content
        assert "Instructions" in content
        assert "Details" in content

    @patch("cve_agent.context._gather_knowledge", return_value="")
    @patch("cve_agent.context._gather_context_for_exit_code", return_value="## D")
    @patch("cve_agent.context._build_phase_instructions", return_value="## I")
    @patch("cve_agent.context._build_header", return_value="# H")
    @patch("cve_agent.context.get_agent_dir")
    def test_with_feedback(self, mock_dir, mock_hdr, mock_instr, mock_ctx, mock_kb, tmp_path):
        agent_dir = tmp_path / "agent"
        agent_dir.mkdir()
        (agent_dir / "human_feedback.txt").write_text("fix the null check")
        mock_dir.return_value = agent_dir
        result = build_context(Path("/ws"), 0, "CVE-1", {"name": "r"})
        content = result.read_text()
        assert "fix the null check" in content
        assert not (agent_dir / "human_feedback.txt").exists()

    @patch("cve_agent.context._gather_knowledge", return_value="## KB\npattern")
    @patch("cve_agent.context._gather_context_for_exit_code", return_value="## D")
    @patch("cve_agent.context._build_phase_instructions", return_value="## I")
    @patch("cve_agent.context._build_header", return_value="# H")
    @patch("cve_agent.context.get_agent_dir")
    def test_with_knowledge(self, mock_dir, mock_hdr, mock_instr, mock_ctx, mock_kb, tmp_path):
        agent_dir = tmp_path / "agent"
        agent_dir.mkdir()
        mock_dir.return_value = agent_dir
        content = build_context(Path("/ws"), 0, "CVE-1", {"name": "r"}).read_text()
        assert "KB" in content
