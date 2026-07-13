# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent interactive mode and session behavior."""
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from cve_agent import AgentConfig
from cve_agent.kiro_backend import KiroBackend

_kiro = KiroBackend()


def _spawn_kiro_cli(context_file, workspace_path, model, timeout, interactive=False):
    result = _kiro.run_session(
        f"Read {context_file}", workspace_path, set(), model, timeout, interactive)
    return not result.resolved


def _build_session_env():
    return _kiro._build_env()


def _cfg(**kwargs):
    defaults = dict(cve_id='CVE-2025-0001', cve_info_path=Path('/tmp/c.json'))
    defaults.update(kwargs)
    return AgentConfig(**defaults)


class TestInteractiveFlag:
    def test_interactive_default_false(self):
        cfg = _cfg()
        assert cfg.interactive is False

    def test_interactive_set_true(self):
        cfg = _cfg(interactive=True)
        assert cfg.interactive is True

    def test_parse_args_interactive(self):
        from cve_agent.__main__ import _config_from_args
        args = MagicMock(
            cve_id='CVE-1', cve_info=Path('/c.json'), trust=False,
            max_retries=3, mirror_dir=None, meta_layer=None,
            skip_ptest=False, clean=False, model='m', session_timeout=600,
            bbappend=False, skip_cve_applicability=False, interactive=True)
        cfg = _config_from_args(args, 'CVE-1')
        assert cfg.interactive is True


class TestInteractiveAgentSelection:
    @patch('subprocess.run')
    def test_interactive_uses_correct_agent(self, mock_run):
        _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300, interactive=True)
        cmd = mock_run.call_args_list[0][0][0]
        assert 'yocto-cve-backport-interactive' in cmd

    @patch('subprocess.run')
    def test_non_interactive_uses_correct_agent(self, mock_run):
        _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300, interactive=False)
        cmd = mock_run.call_args_list[0][0][0]
        assert 'yocto-cve-backport' in cmd
        # Should NOT be the interactive variant
        assert 'yocto-cve-backport-interactive' not in ' '.join(cmd).replace('yocto-cve-backport-interactive', '')

    @patch('subprocess.run')
    def test_interactive_omits_no_interactive_flag(self, mock_run):
        _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300, interactive=True)
        cmd = mock_run.call_args_list[0][0][0]
        assert '--no-interactive' not in cmd

    @patch('subprocess.run')
    def test_non_interactive_includes_flag(self, mock_run):
        _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300, interactive=False)
        cmd = mock_run.call_args_list[0][0][0]
        assert '--no-interactive' in cmd
        assert '--trust-tools=fs_read,fs_write,execute_bash' in cmd

    @patch('subprocess.run')
    def test_interactive_omits_trust_tools(self, mock_run):
        _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300, interactive=True)
        cmd = mock_run.call_args_list[0][0][0]
        assert '--trust-tools=fs_read,fs_write,execute_bash' not in cmd


class TestSessionErrorHandling:
    @patch('subprocess.run', side_effect=subprocess.TimeoutExpired('cmd', 300))
    def test_timeout_returns_true(self, _):
        assert _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300) is True

    @patch('subprocess.run', side_effect=[KeyboardInterrupt, MagicMock(returncode=0, stdout='')])
    def test_keyboard_interrupt_returns_false(self, _):
        assert _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300) is False

    @patch('subprocess.run', side_effect=[FileNotFoundError, MagicMock(returncode=0, stdout='')])
    def test_kiro_not_found_returns_false(self, _):
        assert _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300) is False
