# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent.orchestrator — process_single_cve, _handle_clean_apply, _process_batch."""
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

from cve_agent import (
    AgentConfig,
    CveResult,
    ResultStatus,
    WorkflowStatus,
)
from cve_agent.__main__ import _process_batch
from cve_agent.knowledge import KnowledgeBase
from cve_agent.orchestrator import (
    _handle_clean_apply,
    _handle_not_applicable,
    process_single_cve,
)
from cve_agent.session import SessionResult


def _cfg(**kwargs):
    defaults = dict(cve_id="CVE-2025-0001", cve_info_path=Path("/tmp/c.json"))
    defaults.update(kwargs)
    return AgentConfig(**defaults)

class TestReadEscalation:
    """_read_escalation recognizes the needs_human conclusion (Strategy E),
    distinct from the not_applicable conclusion."""

    def _write(self, tmp_path, payload):
        import json as _json
        agent_dir = tmp_path / "agent"
        agent_dir.mkdir()
        (agent_dir / "conclusion.json").write_text(_json.dumps(payload))
        return agent_dir

    def test_needs_human_returns_reason(self, tmp_path):
        from cve_agent.orchestrator import _read_escalation
        agent_dir = self._write(
            tmp_path, {"needs_human": True, "reason": "prereq touches out-of-scope files"})
        with patch("cve_agent.orchestrator.get_agent_dir", return_value=agent_dir):
            esc = _read_escalation(tmp_path)
        assert esc is not None
        assert esc.reason == "prereq touches out-of-scope files"
        assert esc.suggested_commits == []

    def test_needs_human_without_reason_has_default(self, tmp_path):
        from cve_agent.orchestrator import _read_escalation
        agent_dir = self._write(tmp_path, {"needs_human": True})
        with patch("cve_agent.orchestrator.get_agent_dir", return_value=agent_dir):
            esc = _read_escalation(tmp_path)
        assert esc is not None
        assert "human review" in esc.reason

    def test_not_applicable_is_not_escalation(self, tmp_path):
        """A not_applicable conclusion must NOT read as an escalation."""
        from cve_agent.orchestrator import _read_escalation
        agent_dir = self._write(
            tmp_path, {"not_applicable": True, "reason": "code absent"})
        with patch("cve_agent.orchestrator.get_agent_dir", return_value=agent_dir):
            assert _read_escalation(tmp_path) is None

    def test_missing_file_returns_none(self, tmp_path):
        from cve_agent.orchestrator import _read_escalation
        agent_dir = tmp_path / "agent"
        agent_dir.mkdir()
        with patch("cve_agent.orchestrator.get_agent_dir", return_value=agent_dir):
            assert _read_escalation(tmp_path) is None

    def test_get_agent_dir_failure_returns_none(self, tmp_path):
        """A read helper must never crash the loop if agent_dir can't resolve."""
        from cve_agent.orchestrator import _read_escalation
        with patch("cve_agent.orchestrator.get_agent_dir",
                   side_effect=OSError("permission denied")):
            assert _read_escalation(tmp_path) is None



class TestProcessSingleCve:
    @patch("cve_agent.__main__._log_result")
    @patch("cve_agent.orchestrator.load_cve_metadata")
    def test_cve_not_in_metadata(self, mock_load, mock_log, tmp_path):
        mock_load.return_value = {}
        kb = KnowledgeBase(tmp_path / "kb.json")
        result = process_single_cve(_cfg(), kb)
        assert result.status == ResultStatus.FAILED
        assert "not found" in result.resolution_summary

    @patch("cve_agent.__main__._log_result")
    @patch("cve_agent.orchestrator.get_workspace_path", return_value=None)
    @patch("cve_agent.orchestrator.run_corrector", return_value=(0, ""))
    def test_multiple_fix_urls_build_one_dependent_series(
            self, mock_run, mock_ws, mock_log, tmp_path):
        """Three --fix-url values merge into one series consumed by the workflow."""
        urls = [
            "https://cgit.git.savannah.nongnu.org/cgit/acl.git/commit/"
            "?id=5906d2868ec8d3b08be556153696e6b1122eeeda",
            "https://cgit.git.savannah.nongnu.org/cgit/acl.git/commit/"
            "?id=0071c6d1fea0a8a6270333baa85fb609be325c26",
            "https://cgit.git.savannah.nongnu.org/cgit/acl.git/commit/"
            "?id=170dbd3beff9bd5bdab3f72db1a04bf282f6087c",
        ]
        cfg = _cfg(cve_info_path=None, fix_urls=urls, recipe="acl")
        result = process_single_cve(cfg, KnowledgeBase(tmp_path / "kb.json"))
        assert result.status == ResultStatus.SUCCESS
        expected_hashes = [
            '5906d2868ec8d3b08be556153696e6b1122eeeda',
            '0071c6d1fea0a8a6270333baa85fb609be325c26',
            '170dbd3beff9bd5bdab3f72db1a04bf282f6087c']
        cve_data_arg = mock_ws.call_args[0][1]
        cve_info = cve_data_arg[cfg.cve_id]
        assert cve_info['hashes'] == expected_hashes
        assert cve_info['series'] == [{'pull_url': '', 'commits': expected_hashes}]

    @patch("cve_agent.__main__._log_result")
    def test_single_fix_url_without_recipe_fails(self, mock_log, tmp_path):
        cfg = _cfg(cve_info_path=None,
                   fix_urls=['https://github.com/o/r/commit/abc123'],
                   recipe=None)
        result = process_single_cve(cfg, KnowledgeBase(tmp_path / "kb.json"))
        assert result.status == ResultStatus.FAILED
        assert "No --cve-info or --fix-url" in result.resolution_summary

    @patch("cve_agent.__main__._log_result")
    @patch("cve_agent.orchestrator.get_workspace_path", return_value=None)
    @patch("cve_agent.orchestrator.run_corrector", return_value=(2, ""))
    @patch("cve_agent.orchestrator.load_cve_metadata",
           return_value={"CVE-2025-0001": {"name": "r"}})
    def test_unrecoverable_generic(self, m_load, m_run, m_ws, m_log, tmp_path):
        result = process_single_cve(_cfg(), KnowledgeBase(tmp_path / "kb.json"))
        assert result.status == ResultStatus.FAILED
        assert "Unrecoverable" in result.resolution_summary

    @patch("cve_agent.__main__._log_result")
    @patch("cve_agent.orchestrator.get_workspace_path", return_value=None)
    @patch("cve_agent.orchestrator.run_corrector", return_value=(5, "--allow-empty"))
    @patch("cve_agent.orchestrator.load_cve_metadata",
           return_value={"CVE-2025-0001": {"name": "r"}})
    def test_already_applied(self, m_load, m_run, m_ws, m_log, tmp_path):
        result = process_single_cve(_cfg(), KnowledgeBase(tmp_path / "kb.json"))
        assert result.status == ResultStatus.SKIPPED

    @patch("cve_agent.__main__._log_result")
    @patch("cve_agent.orchestrator.get_workspace_path", return_value=None)
    @patch("cve_agent.orchestrator.run_corrector", return_value=(8, ""))
    @patch("cve_agent.orchestrator.load_cve_metadata",
           return_value={"CVE-2025-0001": {"name": "r"}})
    def test_ptest_preexisting(self, m_load, m_run, m_ws, m_log, tmp_path):
        result = process_single_cve(_cfg(), KnowledgeBase(tmp_path / "kb.json"))
        assert result.status == ResultStatus.SKIPPED
        assert "ptest" in result.resolution_summary.lower()

    @patch("cve_agent.__main__._log_result")
    @patch("cve_agent.orchestrator.get_workspace_path", return_value=None)
    @patch("cve_agent.orchestrator.run_corrector", return_value=(10, ""))
    @patch("cve_agent.orchestrator.load_cve_metadata",
           return_value={"CVE-2025-0001": {"name": "r"}})
    def test_build_preexisting(self, m_load, m_run, m_ws, m_log, tmp_path):
        result = process_single_cve(_cfg(), KnowledgeBase(tmp_path / "kb.json"))
        assert result.status == ResultStatus.SKIPPED
        assert "build" in result.resolution_summary.lower()

    @patch("cve_agent.__main__._log_result")
    @patch("cve_agent.orchestrator.get_workspace_path", return_value=None)
    @patch("cve_agent.orchestrator.run_corrector", return_value=(0, ""))
    @patch("cve_agent.orchestrator.load_cve_metadata",
           return_value={"CVE-2025-0001": {"name": "r"}})
    def test_success_no_workspace(self, m_load, m_run, m_ws, m_log, tmp_path):
        result = process_single_cve(_cfg(), KnowledgeBase(tmp_path / "kb.json"))
        assert result.status == ResultStatus.SUCCESS

    @patch("cve_agent.__main__._log_result")
    @patch("cve_agent.orchestrator.get_workspace_path", return_value=None)
    @patch("cve_agent.orchestrator.run_corrector", return_value=(1, ""))
    @patch("cve_agent.orchestrator.load_cve_metadata",
           return_value={"CVE-2025-0001": {"name": "r"}})
    def test_no_workspace_recoverable(self, m_load, m_run, m_ws, m_log, tmp_path):
        result = process_single_cve(_cfg(), KnowledgeBase(tmp_path / "kb.json"))
        assert result.status == ResultStatus.FAILED
        assert "workspace" in result.resolution_summary.lower()

    @patch("cve_agent.__main__._log_result")
    @patch("cve_agent.orchestrator._handle_clean_apply",
           return_value=CveResult("CVE-2025-0001", ResultStatus.SUCCESS))
    @patch("cve_agent.orchestrator._is_empty_cherry_pick", return_value=False)
    @patch("cve_agent.orchestrator.run_corrector", return_value=(0, ""))
    @patch("cve_agent.orchestrator.load_cve_metadata",
           return_value={"CVE-2025-0001": {"name": "r"}})
    def test_clean_apply_path(self, mock_load, mock_run, mock_empty, mock_handle, mock_log, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        with patch("cve_agent.orchestrator.get_workspace_path", return_value=ws):
            result = process_single_cve(_cfg(), KnowledgeBase(tmp_path / "kb.json"))
        assert result.status == ResultStatus.SUCCESS
        mock_handle.assert_called_once()

    @patch("cve_agent.__main__._log_result")
    @patch("cve_agent.orchestrator._resolution_loop",
           return_value=CveResult("CVE-2025-0001", ResultStatus.CONFLICT_RESOLVED))
    @patch("cve_agent.orchestrator.run_corrector", return_value=(1, ""))
    @patch("cve_agent.orchestrator.load_cve_metadata",
           return_value={"CVE-2025-0001": {"name": "r"}})
    def test_recoverable_path(self, mock_load, mock_run, mock_loop, mock_log, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        with patch("cve_agent.orchestrator.get_workspace_path", return_value=ws):
            result = process_single_cve(_cfg(), KnowledgeBase(tmp_path / "kb.json"))
        assert result.status == ResultStatus.CONFLICT_RESOLVED

    @patch("cve_agent.__main__._log_result")
    @patch("cve_agent.orchestrator.run_corrector", return_value=(99, ""))
    @patch("cve_agent.orchestrator.load_cve_metadata",
           return_value={"CVE-2025-0001": {"name": "r"}})
    def test_unexpected_exit_code(self, m_load, m_run, m_log, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        with patch("cve_agent.orchestrator.get_workspace_path", return_value=ws):
            result = process_single_cve(_cfg(), KnowledgeBase(tmp_path / "kb.json"))
        assert result.status == ResultStatus.FAILED
        assert "Unexpected" in result.resolution_summary

    @patch("cve_agent.__main__._log_result")
    @patch("cve_agent.orchestrator._handle_clean_apply",
           return_value=CveResult("CVE-2025-0001", ResultStatus.SUCCESS))
    @patch("cve_agent.orchestrator._is_empty_cherry_pick", return_value=False)
    @patch("cve_agent.orchestrator.run_corrector", return_value=(0, ""))
    @patch("cve_agent.orchestrator.load_cve_metadata",
           return_value={"CVE-2025-0001": {"name": "r"}})
    def test_clean_flag(self, m_load, m_run, m_empty, m_handle, m_log, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        agent_dir = tmp_path / "cve_agent" / ws.name
        agent_dir.mkdir(parents=True)
        (agent_dir / "old_state").write_text("x")
        with patch("cve_agent.orchestrator.get_workspace_path", return_value=ws):
            with patch("cve_agent.orchestrator.get_agent_dir", return_value=agent_dir):
                process_single_cve(_cfg(clean=True), KnowledgeBase(tmp_path / "kb.json"))
        assert not (agent_dir / "old_state").exists()


class TestHandleCleanApply:
    @patch("cve_agent.orchestrator.run_corrector")
    @patch("cve_agent.orchestrator._read_conclusion", return_value="feature is absent")
    @patch("cve_agent.orchestrator.guarded_session",
           return_value=SessionResult(resolved=True, duration=1.0))
    @patch("cve_agent.orchestrator.get_upstream_sha", return_value="abc")
    @patch("cve_agent.orchestrator.build_context", return_value=Path("/ctx"))
    def test_model_not_applicable_requires_review(self, *mocks):
        result = _handle_clean_apply(
            _cfg(), Path("/ws"), {}, MagicMock(), time.monotonic())

        assert result.status is ResultStatus.ESCALATED
        assert result.outcome.workflow_status is WorkflowStatus.ESCALATED
        mocks[-1].assert_called_once()

    @patch("cve_agent.orchestrator.request_approval")
    @patch("cve_agent.orchestrator._read_conclusion")
    @patch("cve_agent.orchestrator.guarded_session",
           return_value=SessionResult(
               resolved=False, duration=1.0,
               failure_reason="mandatory transcript failed"))
    @patch("cve_agent.orchestrator.get_upstream_sha", return_value="abc")
    @patch("cve_agent.orchestrator.build_context", return_value=Path("/ctx"))
    def test_unresolved_session_cannot_reach_conclusion_or_approval(
            self, _context, _sha, _session, read_conclusion, approval):
        result = _handle_clean_apply(
            _cfg(), Path("/ws"), {}, MagicMock(), time.monotonic())
        assert result.status == ResultStatus.ESCALATED
        assert "mandatory transcript failed" in result.resolution_summary
        read_conclusion.assert_not_called()
        approval.assert_not_called()

    @patch("cve_agent.orchestrator._read_conclusion", return_value=None)
    @patch("cve_agent.orchestrator.run_corrector", return_value=(0, ""))
    @patch("cve_agent.orchestrator.save_knowledge_pattern")
    @patch("cve_agent.orchestrator.gather_pattern_details", return_value={})
    @patch("cve_agent.orchestrator.build_change_summary", return_value="summary")
    @patch("cve_agent.orchestrator.request_approval", return_value=("approved", ""))
    @patch("cve_agent.orchestrator.guarded_session",
           return_value=SessionResult(resolved=True, duration=1.0))
    @patch("cve_agent.orchestrator.get_upstream_sha", return_value="abc")
    @patch("cve_agent.orchestrator.build_context", return_value=Path("/ctx"))
    def test_approved_success(self, *_):
        result = _handle_clean_apply(_cfg(), Path("/ws"), {}, MagicMock(), time.monotonic())
        assert result.status == ResultStatus.SUCCESS

    @patch("cve_agent.orchestrator._read_conclusion", return_value=None)
    @patch("cve_agent.orchestrator.request_approval", return_value=("rejected", ""))
    @patch("cve_agent.orchestrator.guarded_session",
           return_value=SessionResult(resolved=True, duration=1.0))
    @patch("cve_agent.orchestrator.get_upstream_sha", return_value="abc")
    @patch("cve_agent.orchestrator.build_context", return_value=Path("/ctx"))
    def test_rejected(self, *_):
        result = _handle_clean_apply(_cfg(), Path("/ws"), {}, MagicMock(), time.monotonic())
        assert result.status == ResultStatus.ESCALATED

    @patch("cve_agent.orchestrator._read_conclusion", return_value=None)
    @patch("cve_agent.orchestrator._resolution_loop",
           return_value=CveResult("CVE-2025-0001", ResultStatus.CONFLICT_RESOLVED))
    @patch("cve_agent.orchestrator.request_approval", return_value=("edit", ""))
    @patch("cve_agent.orchestrator.guarded_session",
           return_value=SessionResult(resolved=True, duration=1.0))
    @patch("cve_agent.orchestrator.get_upstream_sha", return_value="abc")
    @patch("cve_agent.orchestrator.build_context", return_value=Path("/ctx"))
    def test_edit_enters_resolution_loop(self, *_):
        result = _handle_clean_apply(_cfg(), Path("/ws"), {}, MagicMock(), time.monotonic())
        assert result.status == ResultStatus.CONFLICT_RESOLVED

    @patch("cve_agent.orchestrator._read_conclusion", return_value=None)
    @patch("cve_agent.orchestrator.run_corrector", return_value=(2, ""))
    @patch("cve_agent.orchestrator.gather_pattern_details", return_value={})
    @patch("cve_agent.orchestrator.build_change_summary", return_value="summary")
    @patch("cve_agent.orchestrator.request_approval", return_value=("approved", ""))
    @patch("cve_agent.orchestrator.guarded_session",
           return_value=SessionResult(resolved=True, duration=1.0))
    @patch("cve_agent.orchestrator.get_upstream_sha", return_value="abc")
    @patch("cve_agent.orchestrator.build_context", return_value=Path("/ctx"))
    def test_continue_unrecoverable(self, *_):
        result = _handle_clean_apply(_cfg(), Path("/ws"), {}, MagicMock(), time.monotonic())
        assert result.status == ResultStatus.FAILED

    @patch("cve_agent.orchestrator._read_conclusion", return_value=None)
    @patch("cve_agent.orchestrator._resolution_loop",
           return_value=CveResult("CVE-2025-0001", ResultStatus.CONFLICT_RESOLVED))
    @patch("cve_agent.orchestrator.run_corrector", return_value=(1, ""))
    @patch("cve_agent.orchestrator.gather_pattern_details", return_value={})
    @patch("cve_agent.orchestrator.build_change_summary", return_value="summary")
    @patch("cve_agent.orchestrator.request_approval", return_value=("approved", ""))
    @patch("cve_agent.orchestrator.guarded_session",
           return_value=SessionResult(resolved=True, duration=1.0))
    @patch("cve_agent.orchestrator.get_upstream_sha", return_value="abc")
    @patch("cve_agent.orchestrator.build_context", return_value=Path("/ctx"))
    def test_continue_recoverable_enters_loop(self, *_):
        result = _handle_clean_apply(_cfg(), Path("/ws"), {}, MagicMock(), time.monotonic())
        assert result.status == ResultStatus.CONFLICT_RESOLVED


class TestHandleNotApplicable:
    @patch("cve_agent.orchestrator.run_corrector")
    @patch("cve_agent.orchestrator._read_conclusion", return_value="fix is present")
    @patch("cve_agent.orchestrator.guarded_session",
           return_value=SessionResult(resolved=True, duration=1.0))
    @patch("cve_agent.orchestrator.get_upstream_sha", return_value="abc")
    @patch("cve_agent.orchestrator.build_context", return_value=Path("/ctx"))
    def test_model_conclusion_requires_review(self, *mocks):
        result = _handle_not_applicable(
            _cfg(), {}, MagicMock(), time.monotonic(),
            cve_data={}, workspace_path=Path("/ws"))

        assert result.status is ResultStatus.ESCALATED
        assert result.outcome.workflow_status is WorkflowStatus.ESCALATED
        mocks[-1].assert_called_once()

    @patch("cve_agent.orchestrator.run_corrector")
    @patch("cve_agent.orchestrator._read_conclusion")
    @patch("cve_agent.orchestrator.guarded_session",
           return_value=SessionResult(
               resolved=False, duration=1.0,
               failure_reason="audit flush failed"))
    @patch("cve_agent.orchestrator.get_upstream_sha", return_value="abc")
    @patch("cve_agent.orchestrator.build_context", return_value=Path("/ctx"))
    def test_unresolved_session_cannot_mark_not_applicable(
            self, _context, _sha, _session, read_conclusion, corrector):
        result = _handle_not_applicable(
            _cfg(), {}, MagicMock(), time.monotonic(),
            cve_data={}, workspace_path=Path("/ws"))
        assert result.status == ResultStatus.ESCALATED
        assert "audit flush failed" in result.resolution_summary
        read_conclusion.assert_not_called()
        corrector.assert_not_called()


class TestProcessBatch:
    @patch("cve_agent.__main__.process_single_cve")
    def test_all_success(self, mock_process, tmp_path):
        mock_process.return_value = CveResult("CVE-1", ResultStatus.SUCCESS)
        cfg = _cfg(trust_mode=True)
        results = _process_batch(["CVE-1", "CVE-2"], cfg, KnowledgeBase(tmp_path / "kb.json"))
        assert len(results) == 2
        assert all(r.status == ResultStatus.SUCCESS for r in results)

    @patch("builtins.input", return_value="y")
    @patch("cve_agent.__main__.process_single_cve")
    def test_failure_continues(self, mock_process, mock_input, tmp_path):
        mock_process.side_effect = [
            CveResult("CVE-1", ResultStatus.FAILED),
            CveResult("CVE-2", ResultStatus.SUCCESS),
        ]
        results = _process_batch(["CVE-1", "CVE-2"], _cfg(), KnowledgeBase(tmp_path / "kb.json"))
        assert len(results) == 2

    @patch("builtins.input", return_value="n")
    @patch("cve_agent.__main__.process_single_cve")
    def test_failure_stops(self, mock_process, mock_input, tmp_path):
        mock_process.return_value = CveResult("CVE-1", ResultStatus.FAILED)
        results = _process_batch(["CVE-1", "CVE-2"], _cfg(), KnowledgeBase(tmp_path / "kb.json"))
        assert len(results) == 1
