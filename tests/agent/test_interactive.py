# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent interactive mode and session behavior."""
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

from cve_agent import AgentConfig
from cve_agent.kiro_backend import KiroBackend

_kiro = KiroBackend()


class _FakePopen:
    """subprocess.Popen stand-in for the non-interactive tee path."""

    def __init__(self, lines=(), wait_exc=None):
        self.stdout = iter(lines)
        self._wait_exc = wait_exc
        self.wait_timeout = "unset"
        self.killed = False

    def wait(self, timeout=None):
        self.wait_timeout = timeout
        if self._wait_exc is not None:
            raise self._wait_exc
        return 0

    def kill(self):
        self.killed = True


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

    def test_cli_default_is_non_interactive(self, monkeypatch):
        """No -i/--interactive flag -> non-interactive, safe for CI."""
        from cve_agent.__main__ import _parse_args
        monkeypatch.setattr(sys, 'argv', [
            'cve-agent', '--cve-id', 'CVE-2024-1234',
            '--cve-info', '/tmp/x.json'])
        args = _parse_args()
        assert args.interactive is False

    def test_cli_short_flag_matches_long_flag(self, monkeypatch):
        """-i is a backward-compatible alias for --interactive."""
        from cve_agent.__main__ import _parse_args
        monkeypatch.setattr(sys, 'argv', [
            'cve-agent', '--cve-id', 'CVE-2024-1234',
            '--cve-info', '/tmp/x.json', '-i'])
        short_args = _parse_args()
        monkeypatch.setattr(sys, 'argv', [
            'cve-agent', '--cve-id', 'CVE-2024-1234',
            '--cve-info', '/tmp/x.json', '--interactive'])
        long_args = _parse_args()
        assert short_args.interactive is True
        assert long_args.interactive is True


class TestInteractiveAgentSelection:
    @patch('subprocess.run')
    def test_interactive_uses_correct_agent(self, mock_run):
        _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300, interactive=True)
        cmd = mock_run.call_args_list[0][0][0]
        assert 'yocto-cve-backport-interactive' in cmd

    @patch('cve_agent.kiro_backend.KiroBackend._check_resolution', return_value=True)
    @patch('cve_agent.kiro_backend.subprocess.Popen')
    def test_non_interactive_uses_correct_agent(self, mock_popen, _resolve):
        mock_popen.return_value = _FakePopen()
        _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300, interactive=False)
        cmd = mock_popen.call_args_list[0][0][0]
        assert 'yocto-cve-backport' in cmd
        # Should NOT be the interactive variant
        assert 'yocto-cve-backport-interactive' not in ' '.join(cmd).replace('yocto-cve-backport-interactive', '')

    @patch('subprocess.run')
    def test_interactive_omits_no_interactive_flag(self, mock_run):
        _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300, interactive=True)
        cmd = mock_run.call_args_list[0][0][0]
        assert '--no-interactive' not in cmd

    @patch('cve_agent.kiro_backend.KiroBackend._check_resolution', return_value=True)
    @patch('cve_agent.kiro_backend.subprocess.Popen')
    def test_non_interactive_includes_flag(self, mock_popen, _resolve):
        mock_popen.return_value = _FakePopen()
        _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300, interactive=False)
        cmd = mock_popen.call_args_list[0][0][0]
        assert '--no-interactive' in cmd
        assert '--trust-tools' not in cmd
        assert '--trust-all-tools' not in cmd


class TestPromptCarriesNoInlinedInstructions:
    """The instructions reach the model via the agent's file:// system prompt
    plus the per-phase context.md — the query itself is just a pointer to the
    context file, in both interactive and non-interactive mode. Regression
    guard against re-introducing the AGENT_INSTRUCTIONS.md double-send that
    inlined the full manual into the query on every CI run."""

    @patch('cve_agent.kiro_backend.KiroBackend._check_resolution', return_value=True)
    @patch('cve_agent.kiro_backend.subprocess.Popen')
    def test_non_interactive_prompt_is_just_context_pointer(self, mock_popen, _resolve):
        mock_popen.return_value = _FakePopen()
        _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300,
                        interactive=False)
        cmd = mock_popen.call_args_list[0][0][0]
        assert cmd[-1] == 'Read /ctx.md'
        assert '--no-interactive' in cmd

    @patch('subprocess.run')
    def test_interactive_prompt_is_just_context_pointer(self, mock_run):
        _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300,
                        interactive=True)
        cmd = mock_run.call_args_list[0][0][0]
        assert cmd[-1] == 'Read /ctx.md'

    @patch('subprocess.run')
    def test_interactive_omits_trust_tools(self, mock_run):
        _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300, interactive=True)
        cmd = mock_run.call_args_list[0][0][0]
        assert '--trust-tools' not in ' '.join(cmd)
        assert '--trust-all-tools' not in cmd


class TestInteractiveTimeout:
    """Interactive sessions must never be killed by a subprocess timeout."""

    @patch('subprocess.run')
    def test_interactive_passes_timeout_none(self, mock_run):
        """When interactive=True, timeout must be None (no time limit)."""
        _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300, interactive=True)
        # First subprocess.run call is the kiro-cli session itself
        _, kwargs = mock_run.call_args_list[0]
        assert kwargs.get('timeout') is None

    @patch('cve_agent.kiro_backend.KiroBackend._check_resolution', return_value=True)
    @patch('cve_agent.kiro_backend.subprocess.Popen')
    def test_non_interactive_passes_configured_timeout(self, mock_popen, _resolve):
        """When interactive=False, the configured timeout is forwarded to wait()."""
        fake = _FakePopen()
        mock_popen.return_value = fake
        _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 600, interactive=False)
        assert fake.wait_timeout == 600


class TestSessionErrorHandling:
    @patch('cve_agent.kiro_backend.subprocess.Popen')
    def test_timeout_returns_true(self, mock_popen):
        mock_popen.return_value = _FakePopen(
            wait_exc=subprocess.TimeoutExpired('cmd', 300))
        assert _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300) is True

    @patch('cve_agent.kiro_backend.KiroBackend._check_resolution', return_value=True)
    @patch('cve_agent.kiro_backend.subprocess.Popen', side_effect=KeyboardInterrupt)
    def test_keyboard_interrupt_returns_false(self, _popen, _resolve):
        assert _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300) is False

    @patch('cve_agent.kiro_backend.KiroBackend._check_resolution', return_value=True)
    @patch('cve_agent.kiro_backend.subprocess.Popen', side_effect=FileNotFoundError)
    def test_kiro_not_found_returns_false(self, _popen, _resolve):
        assert _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300) is False


class TestTranscriptCapture:
    """Interactive sessions are wrapped with `script` to capture a
    stdin+stdout transcript, without disrupting the live TTY kiro-cli needs
    for its prompts."""

    def test_wrap_with_script_captures_stdin_and_stdout(self):
        cmd = ['kiro-cli', 'chat', '--agent', 'yocto-cve-backport-interactive',
               '--model', 'm', 'do the thing']
        wrapped = _kiro._wrap_with_script(cmd, Path('/tmp/session.log'))
        assert wrapped[0] == 'script'
        assert '-B' in wrapped
        assert str(Path('/tmp/session.log')) in wrapped
        assert '-c' in wrapped
        # The original command is preserved (shell-quoted) after -c.
        inner = wrapped[wrapped.index('-c') + 1]
        assert 'kiro-cli' in inner
        assert 'yocto-cve-backport-interactive' in inner

    def test_wrap_with_script_returns_none_without_script_binary(self):
        cmd = ['kiro-cli', 'chat', 'x']
        with patch('shutil.which', return_value=None):
            assert _kiro._wrap_with_script(cmd, Path('/tmp/session.log')) is None

    def test_transcript_path_none_on_uncreatable_dir(self):
        # /ws doesn't exist and isn't creatable in the test sandbox, so this
        # must fail gracefully rather than raising.
        assert _kiro._transcript_path(Path('/ws')) is None

    @patch('subprocess.run')
    def test_interactive_session_wraps_with_script_when_dir_creatable(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=0, stdout='')
        with patch('cve_agent.git.build_git_env', return_value={'PATH': '/usr/bin'}):
            _spawn_kiro_cli(Path('/ctx.md'), tmp_path, 'model', 300, interactive=True)
        cmd = mock_run.call_args_list[0][0][0]
        assert cmd[0] == 'script'
        inner = cmd[cmd.index('-c') + 1]
        assert 'yocto-cve-backport-interactive' in inner

    @patch('cve_agent.kiro_backend.KiroBackend._check_resolution', return_value=True)
    @patch('cve_agent.kiro_backend.subprocess.Popen')
    def test_non_interactive_session_never_wrapped(self, mock_popen, _resolve, tmp_path):
        """Non-interactive runs are unaffected by transcript capture."""
        mock_popen.return_value = _FakePopen()
        with patch('cve_agent.git.build_git_env', return_value={'PATH': '/usr/bin'}):
            _spawn_kiro_cli(Path('/ctx.md'), tmp_path, 'model', 300, interactive=False)
        cmd = mock_popen.call_args_list[0][0][0]
        assert cmd[0] == 'kiro-cli'
