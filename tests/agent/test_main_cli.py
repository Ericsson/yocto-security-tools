# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent/__main__.py CLI parsing and batch processing."""
from unittest.mock import MagicMock, patch

import pytest

from cve_agent import CveResult, ResultStatus
from cve_agent.__main__ import (
    _command_succeeded,
    _config_from_args,
    _get_version,
    _parse_args,
    _print_batch_summary,
    _process_batch,
    _read_cve_list,
    _save_results,
)


class TestGetVersion:
    def test_returns_string(self):
        assert isinstance(_get_version(), str)


class TestParseArgs:
    def test_single_cve(self, monkeypatch):
        monkeypatch.setattr('sys.argv', [
            'cve-agent', '--cve-id', 'CVE-2025-0001',
            '--cve-info', '/tmp/cve.json'])
        args = _parse_args()
        assert args.cve_id == 'CVE-2025-0001'

    def test_cve_list(self, monkeypatch):
        monkeypatch.setattr('sys.argv', [
            'cve-agent', '--cve-list', '/tmp/cves.txt',
            '--cve-info', '/tmp/cve.json'])
        args = _parse_args()
        assert str(args.cve_list) == '/tmp/cves.txt'

    def test_trust_mode(self, monkeypatch):
        monkeypatch.setattr('sys.argv', [
            'cve-agent', '--cve-id', 'CVE-1', '--cve-info', '/tmp/c.json',
            '--trust'])
        args = _parse_args()
        assert args.trust is True

    def test_skip_ptest(self, monkeypatch):
        monkeypatch.setattr('sys.argv', [
            'cve-agent', '--cve-id', 'CVE-1', '--cve-info', '/tmp/c.json',
            '--skip-ptest'])
        args = _parse_args()
        assert args.skip_ptest is True

    def test_skip_source_single(self, monkeypatch):
        monkeypatch.setattr('sys.argv', [
            'cve-agent', '--cve-id', 'CVE-1', '--cve-info', '/tmp/c.json',
            '--skip-source', 'osv'])
        args = _parse_args()
        assert args.skip_sources == ['osv']

    def test_skip_source_repeatable(self, monkeypatch):
        monkeypatch.setattr('sys.argv', [
            'cve-agent', '--cve-id', 'CVE-1', '--cve-info', '/tmp/c.json',
            '--skip-source', 'osv', '--skip-source', 'ubuntu'])
        args = _parse_args()
        assert args.skip_sources == ['osv', 'ubuntu']

    def test_skip_source_default_empty(self, monkeypatch):
        monkeypatch.setattr('sys.argv', [
            'cve-agent', '--cve-id', 'CVE-1', '--cve-info', '/tmp/c.json'])
        args = _parse_args()
        assert args.skip_sources == []

    def test_sign_off_default_false(self, monkeypatch):
        monkeypatch.setattr('sys.argv', [
            'cve-agent', '--cve-id', 'CVE-1', '--cve-info', '/tmp/c.json'])
        args = _parse_args()
        assert args.sign_off is False

    def test_sign_off_flag(self, monkeypatch):
        monkeypatch.setattr('sys.argv', [
            'cve-agent', '--cve-id', 'CVE-1', '--cve-info', '/tmp/c.json',
            '--sign-off'])
        args = _parse_args()
        assert args.sign_off is True


class TestConfigFromArgs:
    def test_creates_config(self, monkeypatch):
        monkeypatch.setattr('sys.argv', [
            'cve-agent', '--cve-id', 'CVE-2025-0001',
            '--cve-info', '/tmp/cve.json', '--max-retries', '5'])
        args = _parse_args()
        config = _config_from_args(args, 'CVE-2025-0001')
        assert config.cve_id == 'CVE-2025-0001'
        assert config.max_retries == 5

    def test_skip_sources_passthrough(self, monkeypatch):
        monkeypatch.setattr('sys.argv', [
            'cve-agent', '--cve-id', 'CVE-2025-0001',
            '--cve-info', '/tmp/cve.json',
            '--skip-source', 'osv', '--skip-source', 'ubuntu'])
        args = _parse_args()
        config = _config_from_args(args, 'CVE-2025-0001')
        assert config.skip_sources == ['osv', 'ubuntu']

    def test_sign_off_passthrough(self, monkeypatch):
        monkeypatch.setattr('sys.argv', [
            'cve-agent', '--cve-id', 'CVE-2025-0001',
            '--cve-info', '/tmp/cve.json', '--sign-off'])
        args = _parse_args()
        config = _config_from_args(args, 'CVE-2025-0001')
        assert config.sign_off is True

    def test_sign_off_default_false(self, monkeypatch):
        monkeypatch.setattr('sys.argv', [
            'cve-agent', '--cve-id', 'CVE-2025-0001',
            '--cve-info', '/tmp/cve.json'])
        args = _parse_args()
        config = _config_from_args(args, 'CVE-2025-0001')
        assert config.sign_off is False


class TestTrustSignOffRejected:
    """--trust auto-approves AI changes with no human review; combined with
    --sign-off that would certify a DCO nobody actually reviewed. The
    combination is rejected outright rather than allowed silently."""

    @patch('cve_agent.__main__.ensure_agents')
    @patch('cve_agent.__main__.process_single_cve')
    def test_trust_and_sign_off_rejected(self, mock_process, mock_ensure,
                                         monkeypatch, capsys):
        from cve_agent import EXIT_AGENT_ERROR
        from cve_agent.__main__ import main
        monkeypatch.setattr('sys.argv', [
            'cve-agent', '--cve-id', 'CVE-2025-0001', '--cve-info', '/tmp/c.json',
            '--trust', '--sign-off'])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == EXIT_AGENT_ERROR
        err = capsys.readouterr().err
        assert '--trust' in err
        assert '--sign-off' in err
        # The rejection must happen before any agent/AI-session setup or CVE
        # processing — no AI backend touched, no work attempted.
        mock_ensure.assert_not_called()
        mock_process.assert_not_called()

    def test_sign_off_alone_not_rejected(self, monkeypatch, capsys):
        """--sign-off without --trust must pass the combination check and
        fall through to the next validation (missing --cve-info), not the
        --trust/--sign-off rejection — distinguished by the error message
        since both paths share EXIT_AGENT_ERROR."""
        from cve_agent.__main__ import main
        monkeypatch.setattr('sys.argv', [
            'cve-agent', '--cve-id', 'CVE-2025-0001', '--sign-off'])
        with pytest.raises(SystemExit):
            main()
        err = capsys.readouterr().err
        assert '--trust and --sign-off cannot be combined' not in err
        assert '--cve-info or --fix-url is required' in err

    def test_trust_alone_not_rejected(self, monkeypatch, capsys):
        from cve_agent.__main__ import main
        monkeypatch.setattr('sys.argv', [
            'cve-agent', '--cve-id', 'CVE-2025-0001', '--trust'])
        with pytest.raises(SystemExit):
            main()
        err = capsys.readouterr().err
        assert '--trust and --sign-off cannot be combined' not in err


class TestMainSingleCveCostReport:
    """On completion of a single-CVE run, main() prints the backend cost when
    the session reported one, and stays silent when it did not."""

    def _run_main(self, monkeypatch, result):
        from cve_agent.__main__ import main
        monkeypatch.setattr('sys.argv', [
            'cve-agent', '--cve-id', 'CVE-2025-0001',
            '--cve-info', '/tmp/c.json', '--trust'])
        with patch('cve_agent.__main__.ensure_agents'), \
             patch('cve_agent.__main__._show_trust_warning', return_value=True), \
             patch('cve_agent.__main__._log_result'), \
             patch('cve_agent.__main__.process_single_cve', return_value=result):
            main()

    def test_prints_cost_when_present(self, monkeypatch, capsys):
        result = CveResult('CVE-2025-0001', ResultStatus.SUCCESS,
                           total_credits=5.86, credits_unit='credits')
        self._run_main(monkeypatch, result)
        out = capsys.readouterr().out
        assert 'credits: 5.86 credits' in out

    def test_omits_cost_when_none(self, monkeypatch, capsys):
        result = CveResult('CVE-2025-0001', ResultStatus.SUCCESS)
        self._run_main(monkeypatch, result)
        out = capsys.readouterr().out
        assert 'credits:' not in out

    def test_trusted_host_skip_exits_zero(self, monkeypatch):
        result = CveResult('CVE-2025-0001', ResultStatus.SKIPPED)
        self._run_main(monkeypatch, result)

    def test_model_non_applicable_escalation_exits_nonzero(self, monkeypatch):
        result = CveResult('CVE-2025-0001', ResultStatus.ESCALATED)
        with pytest.raises(SystemExit):
            self._run_main(monkeypatch, result)


def test_command_success_distinguishes_host_skip_from_review_required():
    skipped = CveResult('CVE-1', ResultStatus.SKIPPED)
    review = CveResult('CVE-2', ResultStatus.ESCALATED)

    assert _command_succeeded(skipped)
    assert not _command_succeeded(review)


class TestReadCveList:
    def test_valid_file(self, tmp_path):
        f = tmp_path / 'cves.txt'
        f.write_text('CVE-2025-0001\nCVE-2025-0002\n\n')
        result = _read_cve_list(f)
        assert result == ['CVE-2025-0001', 'CVE-2025-0002']

    def test_missing_file(self, tmp_path):
        with pytest.raises(SystemExit):
            _read_cve_list(tmp_path / 'nope.txt')


class TestPrintBatchSummary:
    def test_prints_counts(self, capsys):
        results = [
            CveResult('CVE-1', ResultStatus.SUCCESS),
            CveResult('CVE-2', ResultStatus.FAILED),
        ]
        _print_batch_summary(results)
        out = capsys.readouterr().out
        assert 'Total CVEs processed: 2' in out
        assert 'WORKFLOW_COMPLETED_UNVERIFIED: 1' in out
        assert 'WORKFLOW_FAILED: 1' in out


class TestSaveResults:
    def test_saves_to_data_dir(self, tmp_path, monkeypatch):
        monkeypatch.setenv('CVE_TOOLS_DATA_DIR', str(tmp_path))
        results = [CveResult('CVE-1', ResultStatus.SUCCESS, duration=1.0)]
        _save_results(results)
        results_dir = tmp_path / 'yocto-security-tools' / 'results'
        files = list(results_dir.glob('backport_agent_results_*.txt'))
        assert len(files) == 1
        content = files[0].read_text()
        assert 'CVE-1' in content
        assert 'WORKFLOW_COMPLETED_UNVERIFIED' in content


class TestProcessBatch:
    @patch('cve_agent.__main__.process_single_cve')
    @patch('cve_agent.__main__._log_result')
    def test_processes_all(self, mock_log, mock_process):
        from cve_agent import AgentConfig
        mock_process.return_value = CveResult(
            'CVE-1', ResultStatus.SUCCESS, resolution_summary='done')
        config = AgentConfig(cve_id='', trust_mode=True)
        kb = MagicMock()
        results = _process_batch(['CVE-1', 'CVE-2'], config, kb)
        assert len(results) == 2
        assert mock_process.call_count == 2

    @patch('builtins.input')
    @patch('cve_agent.__main__.process_single_cve')
    @patch('cve_agent.__main__._log_result')
    def test_trusted_host_skip_does_not_prompt(
            self, mock_log, mock_process, mock_input):
        from cve_agent import AgentConfig
        mock_process.return_value = CveResult('CVE-1', ResultStatus.SKIPPED)
        config = AgentConfig(cve_id='')

        results = _process_batch(['CVE-1'], config, MagicMock())

        assert len(results) == 1
        mock_input.assert_not_called()
