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
        assert '--trust-tools' not in cmd
        assert '--trust-all-tools' not in cmd


class TestNonInteractivePromptIncludesInstructions:
    """CI (--no-interactive) runs inline AGENT_INSTRUCTIONS.md into the query
    text itself, since kiro-cli has no --append-system-prompt equivalent and
    there's no human to notice a silently-unresolved file:// agent prompt."""

    @patch('subprocess.run')
    def test_non_interactive_prompt_prepends_instructions(self, mock_run, tmp_path):
        instructions_file = tmp_path / 'AGENT_INSTRUCTIONS.md'
        instructions_file.write_text('# CVE Backport Agent Instructions\n'
                                     'Use fs_read for everything.',
                                     encoding='utf-8')
        with patch('cve_agent.resolve_agent_instructions',
                   return_value=instructions_file):
            _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300,
                            interactive=False)
        cmd = mock_run.call_args_list[0][0][0]
        query = cmd[-1]
        assert 'Use fs_read for everything.' in query
        assert 'Read /ctx.md' in query

    @patch('subprocess.run')
    def test_interactive_prompt_does_not_duplicate_instructions(
            self, mock_run, tmp_path):
        """Interactive already gets instructions via the agent config's
        file:// prompt; inlining them again would be redundant noise."""
        instructions_file = tmp_path / 'AGENT_INSTRUCTIONS.md'
        instructions_file.write_text('# CVE Backport Agent Instructions',
                                     encoding='utf-8')
        with patch('cve_agent.resolve_agent_instructions',
                   return_value=instructions_file):
            _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300,
                            interactive=True)
        cmd = mock_run.call_args_list[0][0][0]
        query = cmd[-1]
        assert query == 'Read /ctx.md'

    @patch('subprocess.run')
    def test_missing_instructions_file_falls_back_to_plain_prompt(
            self, mock_run, tmp_path):
        missing = tmp_path / 'does-not-exist.md'
        with patch('cve_agent.resolve_agent_instructions', return_value=missing):
            _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300,
                            interactive=False)
        cmd = mock_run.call_args_list[0][0][0]
        assert cmd[-1] == 'Read /ctx.md'

    @patch('subprocess.run')
    def test_interactive_omits_trust_tools(self, mock_run):
        _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300, interactive=True)
        cmd = mock_run.call_args_list[0][0][0]
        assert '--trust-tools' not in ' '.join(cmd)
        assert '--trust-all-tools' not in cmd


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

    @patch('subprocess.run')
    def test_non_interactive_session_never_wrapped(self, mock_run, tmp_path):
        """Non-interactive runs are unaffected by transcript capture."""
        mock_run.return_value = MagicMock(returncode=0, stdout='')
        with patch('cve_agent.git.build_git_env', return_value={'PATH': '/usr/bin'}):
            _spawn_kiro_cli(Path('/ctx.md'), tmp_path, 'model', 300, interactive=False)
        cmd = mock_run.call_args_list[0][0][0]
        assert cmd[0] == 'kiro-cli'
