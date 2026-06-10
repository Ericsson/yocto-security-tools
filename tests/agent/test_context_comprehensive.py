# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Comprehensive tests for cve_agent.context — context building edge cases."""
import json
from pathlib import Path
from unittest.mock import patch

from cve_agent import EXIT_BUILD_ERROR, EXIT_CONFLICT, EXIT_PTEST_ERROR
from cve_agent.context import (
    _build_header,
    _read_ptest_results,
    build_context,
)


class TestContextAllowedFilesHeader:
    """Context always includes allowed file list regardless of exit code."""

    @patch('cve_agent.context.get_all_upstream_shas', return_value=['abc'])
    @patch('cve_agent.context.get_upstream_sha', return_value='abc')
    @patch('cve_agent.context.run_git_stdout', return_value='file.c')
    def test_exit_0_has_allowed_files(self, *_):
        ws = Path('/build/workspace/sources/busybox')
        result = _build_header('CVE-1', 'busybox', 0, ws, {})
        assert 'Allowed Files' in result
        assert 'file.c' in result

    @patch('cve_agent.context.get_all_upstream_shas', return_value=['abc'])
    @patch('cve_agent.context.get_upstream_sha', return_value='abc')
    @patch('cve_agent.context.run_git_stdout', return_value='file.c')
    def test_exit_1_has_allowed_files(self, *_):
        result = _build_header('CVE-1', 'r', EXIT_CONFLICT, Path('/ws'), {})
        assert 'Allowed Files' in result

    @patch('cve_agent.context.get_all_upstream_shas', return_value=['abc'])
    @patch('cve_agent.context.get_upstream_sha', return_value='abc')
    @patch('cve_agent.context.run_git_stdout', return_value='file.c')
    def test_exit_3_has_allowed_files(self, *_):
        result = _build_header('CVE-1', 'r', EXIT_PTEST_ERROR, Path('/ws'), {})
        assert 'Allowed Files' in result

    @patch('cve_agent.context.get_all_upstream_shas', return_value=['abc'])
    @patch('cve_agent.context.get_upstream_sha', return_value='abc')
    @patch('cve_agent.context.run_git_stdout', return_value='file.c')
    def test_exit_4_has_allowed_files(self, *_):
        result = _build_header('CVE-1', 'r', EXIT_BUILD_ERROR, Path('/ws'), {})
        assert 'Allowed Files' in result


class TestContextModelName:
    @patch('cve_agent.context.get_all_upstream_shas', return_value=['abc'])
    @patch('cve_agent.context.get_upstream_sha', return_value='abc')
    @patch('cve_agent.context.run_git_stdout', return_value='')
    def test_model_in_header(self, *_):
        result = _build_header('CVE-1', 'r', 0, Path('/ws'), {},
                               model='claude-sonnet-4-20250514')
        assert 'claude-sonnet-4-20250514' in result


class TestContextMultiSha:
    @patch('cve_agent.context.get_all_upstream_shas', return_value=['aaa', 'bbb', 'ccc'])
    @patch('cve_agent.context.get_upstream_sha', return_value='aaa')
    @patch('cve_agent.context.run_git_stdout', return_value='f.c')
    def test_all_shas_listed(self, *_):
        result = _build_header('CVE-1', 'r', 0, Path('/ws'), {})
        assert 'aaa' in result
        assert 'bbb' in result
        assert 'ccc' in result


class TestContextFeedback:
    @patch('cve_agent.context._gather_knowledge', return_value='')
    @patch('cve_agent.context._gather_context_for_exit_code', return_value='## D')
    @patch('cve_agent.context._build_phase_instructions', return_value='## I')
    @patch('cve_agent.context._build_header', return_value='# H')
    @patch('cve_agent.context.get_agent_dir')
    def test_feedback_consumed_and_deleted(self, mock_dir, _h, _i, _d, _k, tmp_path):
        agent_dir = tmp_path / 'agent'
        agent_dir.mkdir()
        feedback = agent_dir / 'human_feedback.txt'
        feedback.write_text('fix the null check')
        mock_dir.return_value = agent_dir
        ctx = build_context(Path('/ws'), 0, 'CVE-1', {'name': 'r'})
        content = ctx.read_text()
        assert 'fix the null check' in content
        assert not feedback.exists()


class TestContextPtestResults:
    @patch('cve_agent.context._find_ptest_log', return_value=None)
    @patch('cve_agent.context._find_state_file')
    def test_ptest_state_file_included(self, mock_state, _, tmp_path):
        state = tmp_path / 'state.json'
        state.write_text(json.dumps({'ptest_before': 'PASS: 10\nFAIL: 2'}))
        mock_state.return_value = state
        ws = tmp_path / 'build' / 'workspace' / 'sources' / 'busybox'
        ws.mkdir(parents=True)
        result = _read_ptest_results(ws)
        assert 'Before patch' in result
        assert 'PASS: 10' in result

    @patch('cve_agent.context._find_state_file', return_value=None)
    def test_ptest_log_failed_lines(self, _, tmp_path):
        ws = tmp_path / 'build' / 'workspace' / 'sources' / 'busybox'
        ws.mkdir(parents=True)
        log = tmp_path / 'ptest.log'
        log.write_text('PASS: test1\nFAILED: test2\nFAILED: test3')
        with patch('cve_agent.context._find_ptest_log', return_value=log):
            result = _read_ptest_results(ws)
        assert 'FAILED: test2' in result
        assert 'FAILED: test3' in result


class TestContextYoctoTmpDir:
    @patch('cve_agent.context.get_all_upstream_shas', return_value=['abc'])
    @patch('cve_agent.context.get_upstream_sha', return_value='abc')
    @patch('cve_agent.context.run_git_stdout', return_value='')
    def test_prefers_tmp_glibc(self, _git, _sha, _all, tmp_path):
        ws = tmp_path / 'build' / 'workspace' / 'sources' / 'busybox'
        ws.mkdir(parents=True)
        (tmp_path / 'build' / 'tmp-glibc').mkdir()
        (tmp_path / 'build' / 'tmp').mkdir()
        result = _build_header('CVE-1', 'busybox', 0, ws, {})
        assert 'tmp-glibc' in result
