# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent audit logging — deviation detection and result logging."""
import os
from pathlib import Path
from unittest.mock import patch

from cve_agent import AgentConfig, CveResult, ResultStatus
from cve_agent.__main__ import _log_result
from cve_agent.session import _log_session_end, _log_session_start, _write_audit_log


def _cfg(**kwargs):
    defaults = dict(cve_id='CVE-2025-0001', cve_info_path=Path('/tmp/c.json'))
    defaults.update(kwargs)
    return AgentConfig(**defaults)


class TestWriteAuditLog:
    @patch('cve_agent.session._get_backport_note', return_value='')
    @patch('cve_agent.session.run_git_stdout', return_value='')
    def test_no_deviations_verbatim_message(self, mock_git, mock_note, tmp_path):
        agent_dir = tmp_path / 'agent'
        agent_dir.mkdir()
        with patch('cve_agent.session.get_agent_dir', return_value=agent_dir):
            _write_audit_log(Path('/ws'), 'busybox', 'CVE-1', ['abc'], {}, 'HEAD~1')
        log = agent_dir / 'busybox-CVE-1-ai-changes.log'
        assert log.exists()
        content = log.read_text()
        assert 'verbatim' in content.lower() or 'Empty cherry-pick' in content

    @patch('cve_agent.session._get_backport_note', return_value='adapted')
    @patch('cve_agent.session.run_git_stdout')
    def test_deviation_shows_both_diffs(self, mock_git, mock_note, tmp_path):
        agent_dir = tmp_path / 'agent'
        agent_dir.mkdir()
        # Agent diff differs from upstream
        mock_git.side_effect = [
            'diff --git a/a.c b/a.c\n+agent_line',  # diff original-version..HEAD
            'a.c',  # diff --name-only pre_session..HEAD (agent touched)
            '',  # ls-tree (file exists in baseline)
        ]
        upstream_diffs = {'a.c': 'diff --git a/a.c b/a.c\n+upstream_line'}
        with patch('cve_agent.session.get_agent_dir', return_value=agent_dir):
            _write_audit_log(Path('/ws'), 'busybox', 'CVE-1', ['abc'],
                             upstream_diffs, 'HEAD~1')
        content = (agent_dir / 'busybox-CVE-1-ai-changes.log').read_text()
        assert 'deviation' in content.lower() or 'Upstream diff' in content

    @patch('cve_agent.session._get_backport_note', return_value='')
    def test_new_file_excluded(self, mock_note, tmp_path):
        agent_dir = tmp_path / 'agent'
        agent_dir.mkdir()
        def fake_git(args, cwd=None):
            if 'original-version..HEAD' in ' '.join(args):
                if '--name-only' in args:
                    return 'new.c'
                return 'diff --git a/new.c b/new.c\n+content'
            if args[:1] == ['ls-tree']:
                return ''  # file not in baseline
            return 'new.c'  # agent touched
        upstream_diffs = {'new.c': 'diff --git a/new.c b/new.c\n+upstream'}
        with patch('cve_agent.session.get_agent_dir', return_value=agent_dir), \
             patch('cve_agent.session.run_git_stdout', side_effect=fake_git):
            _write_audit_log(Path(tmp_path / 'ws'), 'busybox', 'CVE-1',
                             ['abc'], upstream_diffs, 'HEAD~1')
        content = (agent_dir / 'busybox-CVE-1-ai-changes.log').read_text()
        # new.c should NOT appear as a deviation
        assert 'new.c' not in content or 'deviation' not in content.lower()

    @patch('cve_agent.session._get_backport_note', return_value='')
    @patch('cve_agent.session.run_git_stdout', return_value='')
    def test_multiple_sessions_append(self, mock_git, mock_note, tmp_path):
        agent_dir = tmp_path / 'agent'
        agent_dir.mkdir()
        with patch('cve_agent.session.get_agent_dir', return_value=agent_dir):
            _write_audit_log(Path('/ws'), 'busybox', 'CVE-1', ['abc'], {}, 'H1')
            _write_audit_log(Path('/ws'), 'busybox', 'CVE-1', ['abc'], {}, 'H2')
        content = (agent_dir / 'busybox-CVE-1-ai-changes.log').read_text()
        assert content.count('AI Changes Audit Log') == 2


class TestLogResult:
    def test_no_bbpath_noop(self):
        with patch.dict(os.environ, {}, clear=True):
            _log_result(_cfg(), CveResult('CVE-1', ResultStatus.SUCCESS))
        # Should not raise

    def test_writes_correct_format(self, tmp_path):
        log_dir = tmp_path / 'workspace' / 'cve_agent'
        with patch.dict(os.environ, {'BBPATH': str(tmp_path)}):
            with patch('cve_agent.__main__.load_cve_metadata',
                       side_effect=FileNotFoundError('not found')):
                _log_result(_cfg(), CveResult('CVE-1', ResultStatus.SUCCESS,
                                              duration=2.5, resolution_summary='done'))
        log = log_dir / 'cve_agent.log'
        assert log.exists()
        content = log.read_text()
        assert 'CVE-1' in content
        assert 'success' in content
        assert '2.5s' in content


class TestSessionLogs:
    def test_log_start(self, tmp_path):
        _log_session_start(tmp_path, Path('/ctx.md'))
        assert 'SESSION START' in (tmp_path / 'sessions.log').read_text()

    def test_log_end_resolved(self, tmp_path):
        _log_session_end(tmp_path, True, 5.0)
        content = (tmp_path / 'sessions.log').read_text()
        assert 'RESOLVED' in content
        assert '5.0s' in content

    def test_log_end_unresolved(self, tmp_path):
        _log_session_end(tmp_path, False, 3.0)
        assert 'UNRESOLVED' in (tmp_path / 'sessions.log').read_text()
