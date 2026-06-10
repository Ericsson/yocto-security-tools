# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent.__main__ — orchestration, batch, CLI helpers."""
import json
import signal
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cve_agent import (
    EXIT_NOT_APPLICABLE,
    AgentConfig,
    CveResult,
    ResultStatus,
)
from cve_agent.__main__ import (
    _config_from_args,
    _log_result,
    _print_batch_summary,
    _read_cve_list,
    _save_results,
    _show_trust_warning,
    _sigint_handler,
)
from cve_agent.corrector import get_workspace_path as _get_workspace_path
from cve_agent.corrector import load_cve_metadata as _load_cve_metadata
from cve_agent.corrector import run_corrector as _run_corrector
from cve_agent.knowledge import (
    KnowledgeBase,
)
from cve_agent.knowledge import (
    gather_pattern_details as _gather_pattern_details,
)
from cve_agent.knowledge import (
    save_knowledge_pattern as _save_knowledge_pattern,
)
from cve_agent.orchestrator import (
    _AttemptOutcome,
    _finalize_resolution,
    _make_result,
    _resolution_loop,
    _run_single_resolution_attempt,
    process_single_cve,
)
from cve_agent.session import SessionResult


def _cfg(**kwargs):
    defaults = dict(cve_id="CVE-2025-0001", cve_info_path=Path("/tmp/c.json"))
    defaults.update(kwargs)
    return AgentConfig(**defaults)


class TestShowTrustWarning:
    @patch("builtins.input", return_value="y")
    def test_accept(self, _):
        assert _show_trust_warning() is True

    @patch("builtins.input", return_value="n")
    def test_decline(self, _):
        assert _show_trust_warning() is False

    @patch("builtins.input", return_value="")
    def test_empty(self, _):
        assert _show_trust_warning() is False


class TestLoadCveMetadata:
    def test_valid(self, tmp_path):
        f = tmp_path / "cve.json"
        f.write_text(json.dumps({"CVE-1": {"name": "r"}}))
        assert _load_cve_metadata(f) == {"CVE-1": {"name": "r"}}

    def test_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            _load_cve_metadata(tmp_path / "nope.json")

    def test_invalid_json(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("not json")
        with pytest.raises(ValueError):
            _load_cve_metadata(f)


class TestGetWorkspacePath:
    def test_no_recipe(self):
        cfg = _cfg()
        assert _get_workspace_path(cfg, {"CVE-2025-0001": {}}) is None

    def test_no_bbpath(self):
        cfg = _cfg()
        with patch.dict("os.environ", {}, clear=True):
            result = _get_workspace_path(cfg, {"CVE-2025-0001": {"name": "r"}})
        assert result is None

    def test_workspace_not_exists(self, tmp_path):
        cfg = _cfg()
        with patch.dict("os.environ", {"BBPATH": str(tmp_path)}):
            result = _get_workspace_path(cfg, {"CVE-2025-0001": {"name": "r"}})
        assert result is None

    def test_workspace_exists(self, tmp_path):
        ws = tmp_path / "workspace" / "sources" / "busybox"
        ws.mkdir(parents=True)
        cfg = _cfg()
        with patch.dict("os.environ", {"BBPATH": str(tmp_path)}):
            result = _get_workspace_path(cfg, {"CVE-2025-0001": {"name": "busybox"}})
        assert result == ws


class TestMakeResult:
    def test_creates_result(self):
        start = time.monotonic() - 5.0
        r = _make_result("CVE-1", ResultStatus.SUCCESS, 2, start, "done")
        assert r.cve_id == "CVE-1"
        assert r.status == ResultStatus.SUCCESS
        assert r.retries == 2
        assert r.duration >= 5.0
        assert r.resolution_summary == "done"


class TestAttemptOutcome:
    def test_defaults(self):
        o = _AttemptOutcome()
        assert o.result is None
        assert o.next_step is None

    def test_with_result(self):
        r = CveResult("CVE-1", ResultStatus.SUCCESS)
        o = _AttemptOutcome(result=r)
        assert o.result is r


class TestSaveKnowledgePattern:
    def test_trust_mode(self, tmp_path):
        kb = KnowledgeBase(tmp_path / "kb.json")
        cfg = _cfg(trust_mode=True)
        _save_knowledge_pattern(cfg, kb, "summary", "abc", "busybox")
        assert len(kb.list_patterns()) == 1

    @patch("builtins.input", return_value="n")
    def test_skip(self, _, tmp_path):
        kb = KnowledgeBase(tmp_path / "kb.json")
        cfg = _cfg()
        _save_knowledge_pattern(cfg, kb, "summary", "abc", "busybox")
        assert len(kb.list_patterns()) == 0

    @patch("builtins.input", return_value="")
    def test_accept_default(self, _, tmp_path):
        kb = KnowledgeBase(tmp_path / "kb.json")
        cfg = _cfg()
        _save_knowledge_pattern(cfg, kb, "summary", "abc", "busybox")
        assert len(kb.list_patterns()) == 1

    @patch("builtins.input", return_value="custom description")
    def test_custom_description(self, _, tmp_path):
        kb = KnowledgeBase(tmp_path / "kb.json")
        cfg = _cfg()
        _save_knowledge_pattern(cfg, kb, "summary", "abc", "busybox")
        patterns = kb.list_patterns()
        assert len(patterns) == 1
        assert "custom description" in patterns[0].resolution_summary


class TestGatherPatternDetails:
    @patch("cve_agent.knowledge.run_git_stdout")
    @patch("cve_agent.knowledge.get_changed_files")
    def test_basic(self, mock_files, mock_git):
        mock_files.side_effect = [{"a.c", "b.c"}, {"a.c", "c.c"}]
        mock_git.side_effect = [
            "a.c | 2 +-",
            "commit msg",
            "commit message",
        ]
        result = _gather_pattern_details(Path("/ws"), "abc")
        assert "a.c" in result["per_file_changes"]
        assert "c.c" in result["per_file_changes"]
        assert result["per_file_changes"]["c.c"] == "omitted from backport"

    @patch("cve_agent.knowledge.run_git_stdout")
    @patch("cve_agent.knowledge.get_changed_files")
    def test_identical_to_upstream(self, mock_files, mock_git):
        mock_files.side_effect = [{"a.c"}, {"a.c"}]
        mock_git.side_effect = ["", "stat", "msg"]
        result = _gather_pattern_details(Path("/ws"), "abc")
        assert result["per_file_changes"]["a.c"] == "identical to upstream"


class TestFinalizeResolution:
    @patch("cve_agent.orchestrator.save_knowledge_pattern")
    @patch("cve_agent.orchestrator.run_corrector", return_value=(0, ""))
    @patch("cve_agent.orchestrator.gather_pattern_details", return_value={})
    @patch("cve_agent.orchestrator.build_change_summary", return_value="summary")
    def test_success(self, *_):
        kb = MagicMock()
        outcome = _finalize_resolution(_cfg(), kb, Path("/ws"), "abc", 1, time.monotonic())
        assert outcome.result.status == ResultStatus.CONFLICT_RESOLVED

    @patch("cve_agent.orchestrator.run_corrector", return_value=(2, ""))
    @patch("cve_agent.orchestrator.gather_pattern_details", return_value={})
    @patch("cve_agent.orchestrator.build_change_summary", return_value="summary")
    def test_unrecoverable(self, *_):
        outcome = _finalize_resolution(_cfg(), MagicMock(), Path("/ws"), "abc", 1, time.monotonic())
        assert outcome.result.status == ResultStatus.FAILED

    @patch("cve_agent.orchestrator.run_corrector", return_value=(1, ""))
    @patch("cve_agent.orchestrator.gather_pattern_details", return_value={})
    @patch("cve_agent.orchestrator.build_change_summary", return_value="summary")
    def test_recoverable_retry(self, *_):
        outcome = _finalize_resolution(_cfg(), MagicMock(), Path("/ws"), "abc", 1, time.monotonic())
        assert outcome.result is None
        assert outcome.next_step == 1


class TestRunSingleResolutionAttempt:
    @patch("cve_agent.orchestrator._read_conclusion", return_value=None)
    @patch("cve_agent.orchestrator._finalize_resolution")
    @patch("cve_agent.orchestrator.request_approval", return_value=("approved", ""))
    @patch("cve_agent.orchestrator.guarded_session",
           return_value=SessionResult(resolved=True, duration=1.0))
    @patch("cve_agent.orchestrator.get_upstream_sha", return_value="abc")
    @patch("cve_agent.orchestrator.build_context", return_value=Path("/ctx"))
    def test_approved(self, *mocks):
        finalize = mocks[4]
        finalize.return_value = _AttemptOutcome(
            result=CveResult("CVE-1", ResultStatus.CONFLICT_RESOLVED))
        outcome = _run_single_resolution_attempt(
            _cfg(), Path("/ws"), 1, {}, MagicMock(), 1, time.monotonic())
        assert outcome.result.status == ResultStatus.CONFLICT_RESOLVED

    @patch("cve_agent.orchestrator.guarded_session",
           return_value=SessionResult(resolved=False, duration=1.0))
    @patch("cve_agent.orchestrator.get_upstream_sha", return_value="abc")
    @patch("cve_agent.orchestrator.build_context", return_value=Path("/ctx"))
    def test_unresolved_trust_mode(self, *_):
        cfg = _cfg(trust_mode=True)
        outcome = _run_single_resolution_attempt(
            cfg, Path("/ws"), 1, {}, MagicMock(), 1, time.monotonic())
        assert outcome.result is None
        assert outcome.next_step is None

    @patch("builtins.input", return_value="n")
    @patch("cve_agent.orchestrator.guarded_session",
           return_value=SessionResult(resolved=False, duration=1.0))
    @patch("cve_agent.orchestrator.get_upstream_sha", return_value="abc")
    @patch("cve_agent.orchestrator.build_context", return_value=Path("/ctx"))
    def test_unresolved_user_escalates(self, *_):
        outcome = _run_single_resolution_attempt(
            _cfg(), Path("/ws"), 1, {}, MagicMock(), 1, time.monotonic())
        assert outcome.result.status == ResultStatus.ESCALATED

    @patch("builtins.input", return_value="y")
    @patch("cve_agent.orchestrator.guarded_session",
           return_value=SessionResult(resolved=False, duration=1.0))
    @patch("cve_agent.orchestrator.get_upstream_sha", return_value="abc")
    @patch("cve_agent.orchestrator.build_context", return_value=Path("/ctx"))
    def test_unresolved_user_retries(self, *_):
        outcome = _run_single_resolution_attempt(
            _cfg(), Path("/ws"), 1, {}, MagicMock(), 1, time.monotonic())
        assert outcome.result is None

    @patch("cve_agent.orchestrator._read_conclusion", return_value=None)
    @patch("cve_agent.orchestrator.guarded_session",
           return_value=SessionResult(resolved=True, duration=1.0))
    @patch("cve_agent.orchestrator.get_upstream_sha", return_value="abc")
    @patch("cve_agent.orchestrator.build_context", return_value=Path("/ctx"))
    def test_workspace_gone(self, *_):
        outcome = _run_single_resolution_attempt(
            _cfg(), Path("/nonexistent/ws"), 1, {}, MagicMock(), 1, time.monotonic())
        assert outcome.result.status == ResultStatus.CONFLICT_RESOLVED

    @patch("cve_agent.orchestrator.request_approval", return_value=("rejected", ""))
    @patch("cve_agent.orchestrator.guarded_session",
           return_value=SessionResult(resolved=True, duration=1.0))
    @patch("cve_agent.orchestrator.get_upstream_sha", return_value="abc")
    @patch("cve_agent.orchestrator.build_context", return_value=Path("/ctx"))
    def test_rejected(self, m_ctx, m_sha, m_session, m_approval, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        outcome = _run_single_resolution_attempt(
            _cfg(), ws, 1, {}, MagicMock(), 1, time.monotonic())
        assert outcome.result.status == ResultStatus.ESCALATED

    @patch("cve_agent.orchestrator.request_approval", return_value=("edit", "fix it"))
    @patch("cve_agent.orchestrator.guarded_session",
           return_value=SessionResult(resolved=True, duration=1.0))
    @patch("cve_agent.orchestrator.get_upstream_sha", return_value="abc")
    @patch("cve_agent.orchestrator.build_context", return_value=Path("/ctx"))
    @patch("cve_agent.orchestrator.get_agent_dir")
    def test_edit_with_feedback(self, mock_dir, m_ctx, m_sha, m_session, m_approval, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        agent_dir = tmp_path / "agent"
        agent_dir.mkdir()
        mock_dir.return_value = agent_dir
        outcome = _run_single_resolution_attempt(
            _cfg(), ws, 1, {}, MagicMock(), 1, time.monotonic())
        assert outcome.result is None
        assert (agent_dir / "human_feedback.txt").read_text() == "fix it"


class TestResolutionLoop:
    @patch("cve_agent.orchestrator._run_single_resolution_attempt")
    def test_resolves_first_try(self, mock_attempt):
        mock_attempt.return_value = _AttemptOutcome(
            result=CveResult("CVE-1", ResultStatus.CONFLICT_RESOLVED))
        result = _resolution_loop(_cfg(max_retries=3), Path("/ws"), 1, {}, MagicMock())
        assert result.status == ResultStatus.CONFLICT_RESOLVED

    @patch("cve_agent.orchestrator._run_single_resolution_attempt")
    def test_exhausts_retries(self, mock_attempt):
        mock_attempt.return_value = _AttemptOutcome()
        result = _resolution_loop(_cfg(max_retries=2), Path("/ws"), 1, {}, MagicMock())
        assert result.status == ResultStatus.ESCALATED
        assert "exhausted" in result.resolution_summary

    @patch("cve_agent.orchestrator._run_single_resolution_attempt")
    def test_step_change_resets_counter(self, mock_attempt):
        calls = [0]
        def side_effect(*args, **kwargs):
            calls[0] += 1
            if calls[0] == 1:
                return _AttemptOutcome(next_step=3)
            return _AttemptOutcome(
                result=CveResult("CVE-1", ResultStatus.CONFLICT_RESOLVED))
        mock_attempt.side_effect = side_effect
        result = _resolution_loop(_cfg(max_retries=2), Path("/ws"), 1, {}, MagicMock())
        assert result.status == ResultStatus.CONFLICT_RESOLVED


class TestRunCorrector:
    @patch("subprocess.Popen")
    def test_initial_mode(self, mock_popen):
        proc = MagicMock()
        proc.stdout = iter(["line1\n"])
        proc.wait.return_value = None
        proc.returncode = 0
        proc.__enter__ = lambda s: s
        proc.__exit__ = MagicMock(return_value=False)
        mock_popen.return_value = proc
        cfg = _cfg(clean=True, mirror_dir=Path("/m"), meta_layer=Path("/l"), skip_ptest=True)
        code, output = _run_corrector(cfg)
        assert code == 0
        cmd = mock_popen.call_args[0][0]
        assert "--cve-id" in cmd
        assert "--clean" in cmd
        assert "--mirror-dir" in cmd
        assert "--meta-layer" in cmd
        assert "--skip-ptest" in cmd

    @patch("subprocess.Popen")
    def test_continue_mode(self, mock_popen):
        proc = MagicMock()
        proc.stdout = iter([])
        proc.wait.return_value = None
        proc.returncode = 0
        proc.__enter__ = lambda s: s
        proc.__exit__ = MagicMock(return_value=False)
        mock_popen.return_value = proc
        code, _ = _run_corrector(_cfg(), continue_mode=True)
        assert code == 0
        cmd = mock_popen.call_args[0][0]
        assert "--continue" in cmd


class TestPrintBatchSummary:
    def test_prints(self, capsys):
        results = [
            CveResult("CVE-1", ResultStatus.SUCCESS, retries=0),
            CveResult("CVE-2", ResultStatus.FAILED, retries=2),
        ]
        _print_batch_summary(results)
        out = capsys.readouterr().out
        assert "BATCH SUMMARY" in out
        assert "CVE-1" in out
        assert "2 retries" in out


class TestSaveResults:
    def test_saves_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv('CVE_TOOLS_DATA_DIR', str(tmp_path))
        results = [CveResult("CVE-1", ResultStatus.SUCCESS, duration=1.5)]
        _save_results(results)
        files = list((tmp_path / 'yocto-security-tools' / 'results').glob(
            "backport_agent_results_*.txt"))
        assert len(files) == 1
        assert "CVE-1" in files[0].read_text()


class TestReadCveList:
    def test_valid(self, tmp_path):
        f = tmp_path / "cves.txt"
        f.write_text("CVE-1\nCVE-2\n\n  CVE-3  \n")
        assert _read_cve_list(f) == ["CVE-1", "CVE-2", "CVE-3"]

    def test_missing(self, tmp_path):
        with pytest.raises(SystemExit):
            _read_cve_list(tmp_path / "nope.txt")


class TestConfigFromArgs:
    def test_single_cve(self):
        args = MagicMock(
            cve_id="CVE-1", cve_info=Path("/c.json"), trust=False,
            max_retries=3, mirror_dir=None, meta_layer=None,
            skip_ptest=False, clean=False, model="m", session_timeout=600)
        cfg = _config_from_args(args, "CVE-1")
        assert cfg.cve_id == "CVE-1"

    def test_no_cve_id(self):
        args = MagicMock(
            cve_id=None, cve_info=Path("/c.json"), trust=True,
            max_retries=5, mirror_dir=Path("/m"), meta_layer=Path("/l"),
            skip_ptest=True, clean=True, model="m", session_timeout=300)
        cfg = _config_from_args(args)
        assert cfg.cve_id == ""
        assert cfg.trust_mode is True


class TestSigintHandler:
    def test_empty_results(self):
        handler = _sigint_handler([])
        with pytest.raises(SystemExit):
            handler(signal.SIGINT, None)

    @patch("cve_agent.__main__._save_results")
    @patch("cve_agent.__main__._print_batch_summary")
    def test_with_results(self, mock_summary, mock_save):
        results = [CveResult("CVE-1", ResultStatus.SUCCESS)]
        handler = _sigint_handler(results)
        with pytest.raises(SystemExit):
            handler(signal.SIGINT, None)
        mock_summary.assert_called_once()
        mock_save.assert_called_once()


class TestLogResult:
    def test_no_bbpath(self):
        with patch.dict("os.environ", {}, clear=True):
            _log_result(_cfg(), CveResult("CVE-1", ResultStatus.SUCCESS))

    def test_with_bbpath(self, tmp_path):
        log_dir = tmp_path / "workspace" / "cve_agent"
        with patch.dict("os.environ", {"BBPATH": str(tmp_path)}):
            with patch("cve_agent.__main__.load_cve_metadata",
                       side_effect=FileNotFoundError("not found")):
                _log_result(_cfg(), CveResult("CVE-1", ResultStatus.SUCCESS, duration=1.0,
                                              resolution_summary="done"))
        log = log_dir / "cve_agent.log"
        assert log.exists()
        assert "CVE-1" in log.read_text()


class TestProcessSingleCveNotApplicable:
    @patch("cve_agent.__main__._log_result")
    @patch("cve_agent.orchestrator.run_corrector",
           return_value=(EXIT_NOT_APPLICABLE, "Vulnerable code introduced in v3.0"))
    @patch("cve_agent.orchestrator.load_cve_metadata",
           return_value={"CVE-2025-0001": {"name": "foo"}})
    def test_not_applicable_returns_skipped(self, *_):
        kb = MagicMock()
        result = process_single_cve(_cfg(), kb)
        assert result.status == ResultStatus.SKIPPED
        assert "not present" in result.resolution_summary
