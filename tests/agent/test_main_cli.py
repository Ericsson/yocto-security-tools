# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent/__main__.py CLI parsing and batch processing."""
from unittest.mock import MagicMock, patch

import pytest

from cve_agent import CveResult, ResultStatus
from cve_agent.__main__ import (
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
        assert 'success: 1' in out
        assert 'failed: 1' in out


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
        assert 'success' in content


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
