# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent security — env filtering, input validation, agent config."""
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

from cve_agent.kiro_backend import KiroBackend
from shared import GIT_ENV_ALLOWLIST, build_git_env

_kiro = KiroBackend()
_ALLOWED_ENV_VARS = GIT_ENV_ALLOWLIST


def _build_session_env():
    return build_git_env()


def _spawn_kiro_cli(context_file, workspace_path, model, timeout, interactive=False):
    result = _kiro.run_session(
        f"Read {context_file}", workspace_path, set(), model, timeout, interactive)
    return not result.resolved
from cve_agent.corrector import validate_cve_id, validate_recipe_name


class TestEnvFiltering:
    def test_excludes_secrets(self):
        """Secret env vars are NOT passed to kiro-cli."""
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'secret123', 'API_KEY': 'x',
                    'PATH': '/usr/bin', 'HOME': '/home/u'}, clear=True):
            env = _build_session_env()
        assert 'GITHUB_TOKEN' not in env
        assert 'API_KEY' not in env

    def test_preserves_build_env(self):
        """Build-essential vars are preserved."""
        with patch.dict(os.environ, {'BBPATH': '/build', 'PATH': '/usr/bin',
                    'HOME': '/home/u'}, clear=True):
            env = _build_session_env()
        assert env.get('BBPATH') == '/build'
        assert 'PATH' in env
        assert 'HOME' in env

    def test_all_filtered_vars_covered(self):
        """Known secret env vars are not in the allowlist."""
        secrets = {'GITHUB_TOKEN', 'OPENEMBEDDED_TOKEN',
                    'API_KEY', 'API_SECRET',
                    'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN'}
        assert not (secrets & _ALLOWED_ENV_VARS)


class TestValidateCveId:
    def test_valid_ids(self):
        assert validate_cve_id('CVE-2024-12345') is True
        assert validate_cve_id('CVE-2025-0001') is True
        assert validate_cve_id('CVE-2026-123456') is True

    def test_invalid_ids(self):
        assert validate_cve_id('../etc/passwd') is False
        assert validate_cve_id('CVE-bad') is False
        assert validate_cve_id('') is False
        assert validate_cve_id('CVE-2024-1') is False  # too short
        assert validate_cve_id('CVE-2024-123; rm -rf /') is False
        assert validate_cve_id('not-a-cve') is False


class TestValidateRecipeName:
    def test_valid_names(self):
        assert validate_recipe_name('busybox') is True
        assert validate_recipe_name('gstreamer1.0-plugins-good') is True
        assert validate_recipe_name('python3-certifi') is True
        assert validate_recipe_name('libsoup-2.4') is True

    def test_invalid_names(self):
        assert validate_recipe_name('../hack') is False
        assert validate_recipe_name('; rm -rf /') is False
        assert validate_recipe_name('') is False
        assert validate_recipe_name('.hidden') is False
        assert validate_recipe_name('/absolute/path') is False


import pytest

_KIRO_CONFIG = Path(__file__).resolve().parent.parent.parent / '.kiro' / 'agents' / 'yocto-cve-backport.json'


class TestAgentConfig:
    @pytest.mark.skipif(not _KIRO_CONFIG.exists(),
                        reason="kiro agent config not installed")
    def test_tools_match_session(self):
        """Agent config tools match what the session uses."""
        config_path = _KIRO_CONFIG
        config = json.loads(config_path.read_text())
        assert config['tools'] == ['fs_read', 'fs_write', 'execute_bash']
        assert config['allowedTools'] == ['fs_read', 'fs_write', 'execute_bash']

    @pytest.mark.skipif(not _KIRO_CONFIG.exists(),
                        reason="kiro agent config not installed")
    def test_denied_paths_comprehensive(self):
        """Agent config blocks sensitive paths."""
        config_path = _KIRO_CONFIG
        config = json.loads(config_path.read_text())
        denied = config['toolsSettings']['fs_write']['deniedPaths']
        assert '/etc/**' in denied
        assert '~/.ssh/**' in denied
        assert '~/.aws/**' in denied
        assert '~/.kiro/**' in denied
        assert '**/cve_agent/**/*.py' in denied
        assert '**/cve_corrector/**/*.py' in denied


class TestTrustToolsInNonInteractiveMode:
    @patch('subprocess.run')
    def test_non_interactive_trusts_only_allowed_tools(self, mock_run):
        """Non-interactive mode trusts only fs_read, fs_write, execute_bash."""
        mock_run.return_value = MagicMock(returncode=0, stdout='')
        with patch('cve_agent.git.build_git_env', return_value={'PATH': '/usr/bin'}):
            _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300, interactive=False)
        # First call is kiro-cli, second is git status --porcelain
        cmd = mock_run.call_args_list[0][0][0]
        cmd_str = ' '.join(cmd)
        assert '--agent' in cmd_str
        assert 'yocto-cve-backport' in cmd_str
        assert '--trust-tools=fs_read,fs_write,execute_bash' in cmd_str
        assert '--trust-all-tools' not in cmd_str

    @patch('subprocess.run')
    def test_interactive_does_not_trust_tools(self, mock_run):
        """Interactive mode does NOT pass --trust-tools (user approves each)."""
        mock_run.return_value = MagicMock(returncode=0, stdout='')
        with patch('cve_agent.git.build_git_env', return_value={'PATH': '/usr/bin'}):
            _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300, interactive=True)
        cmd = mock_run.call_args_list[0][0][0]
        cmd_str = ' '.join(cmd)
        assert '--trust-tools' not in cmd_str
        assert '--agent' in cmd_str
        assert 'yocto-cve-backport-interactive' in cmd_str


class TestConclusionSpecialChars:
    def test_special_chars_safe(self):
        """Conclusion with shell metacharacters doesn't break subprocess."""
        from cve_agent import AgentConfig
        from cve_agent.corrector import run_corrector
        config = AgentConfig(cve_id='CVE-2025-0001', cve_info_path=Path('/tmp/c.json'))
        with patch('subprocess.Popen') as mock_popen:
            proc = MagicMock()
            proc.stdout = iter([])
            proc.wait.return_value = None
            proc.returncode = 0
            proc.__enter__ = lambda s: s
            proc.__exit__ = MagicMock(return_value=False)
            mock_popen.return_value = proc
            run_corrector(config, mark_not_applicable='"; rm -rf / #')
            cmd = mock_popen.call_args[0][0]
            # The dangerous string is a separate list element, not shell-interpolated
            assert '"; rm -rf / #' in cmd
