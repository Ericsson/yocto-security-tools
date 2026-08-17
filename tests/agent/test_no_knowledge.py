# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for the --no-knowledge flag: no KB reads or writes when set."""
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

from cve_agent import AgentConfig, ResultStatus
from cve_agent.orchestrator import _handle_clean_apply
from cve_agent.session import SessionResult


def _cfg(**kwargs):
    defaults = dict(cve_id="CVE-2025-0001", cve_info_path=Path("/tmp/c.json"))
    defaults.update(kwargs)
    return AgentConfig(**defaults)


class TestNoKnowledgeEndToEnd:
    """A successful resolution with no_knowledge=True must never touch the
    knowledge base — no similarity lookups (context building) and no pattern
    saved on success."""

    @patch("cve_agent.orchestrator._read_conclusion", return_value=None)
    @patch("cve_agent.orchestrator.run_corrector", return_value=(0, ""))
    @patch("cve_agent.orchestrator.gather_pattern_details", return_value={})
    @patch("cve_agent.orchestrator.build_change_summary", return_value="summary")
    @patch("cve_agent.orchestrator.request_approval", return_value=("approved", ""))
    @patch("cve_agent.orchestrator.guarded_session",
           return_value=SessionResult(resolved=True, duration=1.0))
    @patch("cve_agent.orchestrator.get_upstream_sha", return_value="abc")
    @patch("cve_agent.orchestrator.build_context", return_value=Path("/ctx"))
    def test_no_knowledge_skips_kb_writes(self, *_):
        spy_kb = MagicMock()
        config = _cfg(no_knowledge=True)

        result = _handle_clean_apply(
            config, Path("/ws"), {}, spy_kb, time.monotonic())

        assert result.status == ResultStatus.SUCCESS
        spy_kb.add_pattern.assert_not_called()
        spy_kb.find_similar.assert_not_called()

    @patch("cve_agent.orchestrator._read_conclusion", return_value=None)
    @patch("cve_agent.orchestrator.run_corrector", return_value=(0, ""))
    @patch("cve_agent.orchestrator.gather_pattern_details", return_value={})
    @patch("cve_agent.orchestrator.build_change_summary", return_value="summary")
    @patch("cve_agent.orchestrator.request_approval", return_value=("approved", ""))
    @patch("cve_agent.orchestrator.guarded_session",
           return_value=SessionResult(resolved=True, duration=1.0))
    @patch("cve_agent.orchestrator.get_upstream_sha", return_value="abc")
    @patch("cve_agent.orchestrator.build_context", return_value=Path("/ctx"))
    def test_knowledge_enabled_still_saves(self, *_):
        """Control case: without --no-knowledge, the pattern IS saved."""
        spy_kb = MagicMock()
        config = _cfg(no_knowledge=False)

        with patch("cve_agent.orchestrator.save_knowledge_pattern") as mock_save:
            result = _handle_clean_apply(
                config, Path("/ws"), {}, spy_kb, time.monotonic())

        assert result.status == ResultStatus.SUCCESS
        mock_save.assert_called_once()

    def test_save_knowledge_pattern_noop_when_no_knowledge(self, tmp_path):
        """Direct unit check on the guarded write path itself."""
        from cve_agent.knowledge import save_knowledge_pattern

        spy_kb = MagicMock()
        config = _cfg(no_knowledge=True)

        save_knowledge_pattern(config, spy_kb, "summary", "abc123", "recipe")

        spy_kb.add_pattern.assert_not_called()

    def test_save_knowledge_pattern_noop_when_kb_is_none(self):
        """Passing knowledge_base=None (main()'s --no-knowledge wiring) must
        not raise and must not attempt any KB access."""
        from cve_agent.knowledge import save_knowledge_pattern

        config = _cfg(no_knowledge=False)

        # Must not raise despite knowledge_base being None.
        save_knowledge_pattern(config, None, "summary", "abc123", "recipe")


class TestNoKnowledgeCliWiring:
    """--no-knowledge threads through argument parsing and main()."""

    def test_flag_default_false(self, monkeypatch):
        from cve_agent.__main__ import _parse_args

        monkeypatch.setattr('sys.argv', [
            'cve-agent', '--cve-id', 'CVE-1', '--cve-info', '/tmp/c.json'])
        args = _parse_args()
        assert args.no_knowledge is False

    def test_flag_sets_true(self, monkeypatch):
        from cve_agent.__main__ import _parse_args

        monkeypatch.setattr('sys.argv', [
            'cve-agent', '--cve-id', 'CVE-1', '--cve-info', '/tmp/c.json',
            '--no-knowledge'])
        args = _parse_args()
        assert args.no_knowledge is True

    def test_config_from_args_threads_flag(self, monkeypatch):
        from cve_agent.__main__ import _config_from_args, _parse_args

        monkeypatch.setattr('sys.argv', [
            'cve-agent', '--cve-id', 'CVE-1', '--cve-info', '/tmp/c.json',
            '--no-knowledge'])
        args = _parse_args()
        config = _config_from_args(args, args.cve_id)
        assert config.no_knowledge is True

    @patch("cve_agent.__main__._log_result")
    @patch("cve_agent.__main__.process_single_cve")
    @patch("cve_agent.corrector.validate_cve_id", return_value=True)
    @patch("cve_agent.__main__.KnowledgeBase")
    def test_main_does_not_construct_kb_when_no_knowledge(
            self, mock_kb_cls, mock_validate, mock_process, mock_log,
            monkeypatch):
        from cve_agent import CveResult, ResultStatus
        from cve_agent.__main__ import main

        mock_process.return_value = CveResult("CVE-1", ResultStatus.SUCCESS)
        monkeypatch.setattr('sys.argv', [
            'cve-agent', '--cve-id', 'CVE-1', '--cve-info', '/tmp/c.json',
            '--no-knowledge', '--trust'])
        monkeypatch.setattr('builtins.input', lambda *_: 'y')

        with patch("cve_agent.__main__.ensure_agents"):
            main()

        mock_kb_cls.assert_not_called()
        # process_single_cve must have received None, not a real KnowledgeBase.
        assert mock_process.call_args[0][1] is None
