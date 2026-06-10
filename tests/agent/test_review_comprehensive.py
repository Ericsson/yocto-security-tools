# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Comprehensive tests for cve_agent.review — approval gate edge cases."""
from pathlib import Path
from unittest.mock import patch

from cve_agent.review import (
    _display_changes,
    amend_commit_with_summary,
)


class TestAmendSkipsKiroNotes:
    @patch('subprocess.run')
    @patch('cve_agent.review.run_git_stdout',
           return_value='Fix CVE\n\nBackport-Resolution: adapted')
    def test_skips_backport_resolution(self, mock_git, mock_run):
        amend_commit_with_summary(Path('/ws'), 'def456', 'summary')
        msg = mock_run.call_args[0][0][-1]
        assert 'Backport-Resolution' in msg
        assert 'summary' not in msg

    @patch('subprocess.run')
    @patch('cve_agent.review.run_git_stdout',
           return_value='Fix CVE\n\nBackport changes: adapted code')
    def test_skips_backport_changes(self, mock_git, mock_run):
        amend_commit_with_summary(Path('/ws'), 'def456', 'summary')
        msg = mock_run.call_args[0][0][-1]
        assert 'Backport changes' in msg
        assert 'summary' not in msg

    @patch('subprocess.run')
    @patch('cve_agent.review.run_git_stdout',
           return_value='Fix CVE\n\nConflict resolution notes: adapted')
    def test_skips_conflict_resolution_notes(self, mock_git, mock_run):
        amend_commit_with_summary(Path('/ws'), 'def456', 'summary')
        msg = mock_run.call_args[0][0][-1]
        assert 'Conflict resolution notes' in msg
        assert 'summary' not in msg


class TestAmendStripsCveBlock:
    @patch('subprocess.run')
    @patch('cve_agent.review.run_git_stdout',
           return_value='Fix buffer overflow\n\nSigned-off-by: x\n\nCVE: CVE-2025-0001')
    def test_strips_cve_block(self, mock_git, mock_run):
        amend_commit_with_summary(Path('/ws'), 'def456', 'my summary')
        msg = mock_run.call_args[0][0][-1]
        assert 'my summary' in msg
        assert 'CVE: CVE-2025-0001' not in msg


class TestDisplayChanges:
    @patch('cve_agent.review.get_agent_dir')
    @patch('cve_agent.review.run_git_display')
    @patch('cve_agent.review.run_git_stdout', return_value='')
    @patch('cve_agent.review.get_changed_files', return_value=set())
    def test_empty_cherry_pick_display(self, mock_files, mock_git, mock_display,
                                       mock_dir, tmp_path, capsys):
        mock_dir.return_value = tmp_path
        _display_changes(Path('/ws'), 'abc123', 'summary', 'CVE-2025-0001')
        out = capsys.readouterr().out
        assert 'no new changes' in out.lower() or 'Empty cherry-pick' in out

    @patch('cve_agent.review.get_agent_dir')
    @patch('cve_agent.review.run_git_display')
    @patch('cve_agent.review.run_git_stdout', return_value='')
    @patch('cve_agent.review.get_changed_files', return_value=set())
    def test_audit_log_displayed(self, mock_files, mock_git, mock_display,
                                  mock_dir, tmp_path, capsys):
        mock_dir.return_value = tmp_path
        log = tmp_path / 'busybox-CVE-2025-0001-ai-changes.log'
        log.write_text('AI adapted code')
        _display_changes(tmp_path / 'busybox', 'abc123', 'summary', 'CVE-2025-0001')
        out = capsys.readouterr().out
        assert 'AI adapted code' in out
