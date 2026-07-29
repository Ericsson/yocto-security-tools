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


import re

import pytest

_KIRO_CONFIG = Path(__file__).resolve().parent.parent.parent / '.kiro' / 'agents' / 'yocto-cve-backport.json'
_AGENT_INSTRUCTIONS = (Path(__file__).resolve().parent.parent.parent
                       / 'cve_agent' / 'AGENT_INSTRUCTIONS.md')

# A bare ``>`` / ``>>`` file redirect. ``2>&1`` (digit before, ``&`` after) is
# not a file redirect and is accepted by kiro-cli.
_FILE_REDIRECT_RE = re.compile(r'(?<![0-9])>>?(?!&)')


def _has_file_redirect(command: str) -> bool:
    return _FILE_REDIRECT_RE.search(command) is not None


def _split_subcommands(command: str) -> list:
    """Split a compound command the way kiro-cli's guard does."""
    return [part.strip() for part in re.split(r'&&|\|\||[;|]', command)
            if part.strip()]


def _kiro_permits(command: str, allowed: list) -> bool:
    """Whether kiro-cli's execute_bash guard would run ``command``.

    Models the behaviour verified empirically against kiro-cli 2.9.0 (see
    ``TestAgentConfig.test_build_verify_command_is_permitted``):

    1. ``>`` / ``>>`` file redirection is refused unconditionally — no
       ``allowedCommands`` pattern can re-enable it.
    2. Compound commands are split on ``;``, ``|`` and ``&&``, and **each**
       part must match an ``allowedCommands`` entry on its own.

    This deliberately differs from a naive ``re.fullmatch`` against the whole
    command string, which wrongly reported the old redirect-based build
    command as permitted while kiro-cli rejected it in practice.
    """
    if _has_file_redirect(command):
        return False
    return all(any(re.fullmatch(pattern, part) for pattern in allowed)
               for part in _split_subcommands(command))


def _documented_build_command() -> str:
    """Extract the build-verify command from AGENT_INSTRUCTIONS.md §5."""
    text = _AGENT_INSTRUCTIONS.read_text(encoding='utf-8')
    section = text.split('### 5. Build Verification', 1)[1]
    block = section.split('```bash', 1)[1].split('```', 1)[0]
    return block.strip()


class TestAgentConfig:
    @pytest.mark.skipif(not _KIRO_CONFIG.exists(),
                        reason="kiro agent config not installed")
    def test_tools_match_session(self):
        """Agent config tools match what the session uses."""
        config_path = _KIRO_CONFIG
        config = json.loads(config_path.read_text())
        assert config['tools'] == ['fs_read', 'fs_write', 'execute_bash']
        # execute_bash is deliberately excluded from allowedTools so that
        # toolsSettings.execute_bash.allowedCommands (a lower-priority rule)
        # actually gates bash commands instead of being shadowed by blanket
        # tool-level trust.
        assert config['allowedTools'] == ['fs_read', 'fs_write']
        assert config['toolsSettings']['execute_bash']['denyByDefault'] is True

    @pytest.mark.skipif(not _KIRO_CONFIG.exists(),
                        reason="kiro agent config not installed")
    def test_prerequisite_cherry_pick_allowed(self):
        """The agent must be able to start a fresh cherry-pick of an in-scope
        prerequisite (Strategy A), but the rule must not permit command
        chaining. The pre-commit scope hook remains the hard boundary for
        what actually gets committed."""
        import re
        config = json.loads(_KIRO_CONFIG.read_text())
        allowed = config['toolsSettings']['execute_bash']['allowedCommands']

        def permitted(cmd):
            return any(re.fullmatch(pat, cmd) for pat in allowed)

        # Fresh cherry-picks (with/without -x, refs, multiple SHAs) are allowed.
        assert permitted("git cherry-pick -x deadbeefcafe1234")
        assert permitted("git cherry-pick abc1234")
        assert permitted("git cherry-pick -x --no-edit abc1234 def5678")
        # Chaining / injection via the cherry-pick rule is rejected.
        assert not permitted("git cherry-pick abc1234 && rm -rf /")
        assert not permitted("git cherry-pick abc1234; rm -rf /")
        assert not permitted("git cherry-pick abc1234 | tee x")

    @pytest.mark.skipif(not _KIRO_CONFIG.exists(),
                        reason="kiro agent config not installed")
    def test_build_verify_command_is_permitted(self):
        """The documented build-verify command must actually run under
        kiro-cli's execute_bash guard.

        Regression guard for a real, observed rejection. The instructions used
        to document::

            devtool build <recipe> > <agent_dir>/build.log 2>&1; echo "Exit code: $?"

        which kiro-cli 2.9.0 refuses with "Command not in allowed list" for two
        independent reasons, both confirmed by probing kiro-cli directly:

        * ``>`` file redirection is rejected unconditionally — even an
          allow-list entry written to match the redirect verbatim does not
          help, so the log must be captured with ``| tee``.
        * A compound command is split on ``;``/``|``/``&&`` and each part is
          matched separately, so the trailing ``echo`` needs its own entry.

        A whole-string ``re.fullmatch`` check passed for the redirect form,
        which is precisely why this regression reached a live run.
        """
        allowed = json.loads(_KIRO_CONFIG.read_text())[
            'toolsSettings']['execute_bash']['allowedCommands']

        good = ('devtool build libarchive 2>&1 | tee '
                '/ws/workspace/cve_agent/libarchive/build.log; '
                'echo "Exit code: ${PIPESTATUS[0]}"')
        assert _kiro_permits(good, allowed)

        # The forms kiro-cli actually rejects must stay rejected.
        assert not _kiro_permits(
            'devtool build libarchive > /ws/workspace/cve_agent/libarchive/'
            'build.log 2>&1; echo "Exit code: $?"', allowed)
        # A two-line submission matches nothing (the newline breaks it).
        assert not _kiro_permits(
            'devtool build libarchive 2>&1 | tee /ws/build.log\n'
            'echo "Exit code: $?"', allowed)
        # Bare build, and the plain-$? chain without a pipe, still work.
        assert _kiro_permits("devtool build libarchive", allowed)
        assert _kiro_permits(
            'devtool build libarchive; echo "Exit code: $?"', allowed)

    @pytest.mark.skipif(not _KIRO_CONFIG.exists(),
                        reason="kiro agent config not installed")
    def test_documented_build_command_matches_allowlist(self):
        """AGENT_INSTRUCTIONS.md §5 and the allow-list must not drift apart.

        The command the agent is told to run is extracted from the docs and
        checked against the manifest, so editing either one alone fails here
        instead of at the next live backport.
        """
        allowed = json.loads(_KIRO_CONFIG.read_text())[
            'toolsSettings']['execute_bash']['allowedCommands']
        documented = _documented_build_command()
        concrete = (documented
                    .replace('<recipe>', 'libarchive')
                    .replace('<agent_dir>',
                             '/ws/workspace/cve_agent/libarchive'))
        assert '\n' not in concrete, (
            "the documented build command must stay on one line")
        assert not _has_file_redirect(concrete), (
            f"documented build command uses > redirection, which kiro-cli "
            f"rejects: {concrete!r}")
        assert _kiro_permits(concrete, allowed), (
            f"documented build command is not permitted by the allow-list: "
            f"{concrete!r}")

    @pytest.mark.skipif(not _KIRO_CONFIG.exists(),
                        reason="kiro agent config not installed")
    def test_tee_is_scoped_to_agent_log_files(self):
        """``tee`` can write files, so it is restricted to ``.log`` files under
        a ``cve_agent/`` directory — it must not become a way to overwrite
        source files or bypass fs_write's deniedPaths."""
        allowed = json.loads(_KIRO_CONFIG.read_text())[
            'toolsSettings']['execute_bash']['allowedCommands']

        assert _kiro_permits(
            'tee /ws/workspace/cve_agent/jq/build.log', allowed)
        for bad in (
            'tee /ws/workspace/sources/jq/src/main.c',
            'tee /home/user/.ssh/authorized_keys',
            'tee /etc/passwd',
        ):
            assert not _kiro_permits(bad, allowed), (
                f"tee must not be allowed to write {bad!r}")

    @pytest.mark.skipif(not _KIRO_CONFIG.exists(),
                        reason="kiro agent config not installed")
    def test_readonly_inspection_commands_are_permitted(self):
        """The read-only log/file inspection commands must be available, in
        both bare and piped-into forms (``wc`` is typically reached by pipe).

        These stay broad (``^wc .*$``) like ``cat``/``head``/``tail`` because
        none of them can write a file — unlike ``tee``, which is deliberately
        scoped in ``test_tee_is_scoped_to_agent_log_files``.
        """
        allowed = json.loads(_KIRO_CONFIG.read_text())[
            'toolsSettings']['execute_bash']['allowedCommands']

        assert _kiro_permits('wc -l /ws/workspace/cve_agent/jq/build.log',
                             allowed)
        assert _kiro_permits('cat /ws/workspace/cve_agent/jq/build.log',
                             allowed)
        assert _kiro_permits('tail -50 /ws/workspace/cve_agent/jq/build.log',
                             allowed)
        # Reached via a pipe, each part must still be individually allowed.
        assert _kiro_permits(
            'tail -50 /ws/workspace/cve_agent/jq/build.log | wc -l', allowed)
        # wc must not smuggle in a redirect or an unlisted command.
        assert not _kiro_permits('wc -l build.log > /tmp/count.txt', allowed)
        assert not _kiro_permits('wc -l build.log | rm -rf /', allowed)

    @pytest.mark.skipif(not _KIRO_CONFIG.exists(),
                        reason="kiro agent config not installed")
    def test_echo_allowance_is_narrow(self):
        """``echo`` exists only to surface the build exit code; it must not
        become a general-purpose shell primitive."""
        allowed = json.loads(_KIRO_CONFIG.read_text())[
            'toolsSettings']['execute_bash']['allowedCommands']

        assert _kiro_permits('echo "Exit code: $?"', allowed)
        assert _kiro_permits('echo "Exit code: ${PIPESTATUS[0]}"', allowed)
        for bad in (
            'echo hello',
            'echo "$(rm -rf /)"',
            'echo',
        ):
            assert not _kiro_permits(bad, allowed), (
                f"echo allow-list is too broad: it permits {bad!r}")

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
    def test_non_interactive_does_not_pass_trust_flags(self, mock_run):
        """Non-interactive mode passes no --trust-tools/--trust-all-tools —
        permissions live entirely in the agent config JSON (allowedTools +
        toolsSettings.execute_bash.allowedCommands), so execute_bash relies
        on that allowlist instead of blanket tool trust (which would
        shadow it)."""
        mock_run.return_value = MagicMock(returncode=0, stdout='')
        with patch('cve_agent.git.build_git_env', return_value={'PATH': '/usr/bin'}):
            _spawn_kiro_cli(Path('/ctx.md'), Path('/ws'), 'model', 300, interactive=False)
        # First call is kiro-cli, second is git status --porcelain
        cmd = mock_run.call_args_list[0][0][0]
        cmd_str = ' '.join(cmd)
        assert '--agent' in cmd_str
        assert 'yocto-cve-backport' in cmd_str
        assert '--trust-tools' not in cmd_str
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


class TestSkipSourceForwarding:
    def test_skip_sources_forwarded_to_corrector(self):
        """--skip-source values are forwarded as repeated corrector flags."""
        from cve_agent import AgentConfig
        from cve_agent.corrector import run_corrector
        config = AgentConfig(cve_id='CVE-2025-0001',
                             cve_info_path=Path('/tmp/c.json'),
                             skip_sources=['osv', 'ubuntu'])
        with patch('subprocess.Popen') as mock_popen:
            proc = MagicMock()
            proc.stdout = iter([])
            proc.wait.return_value = None
            proc.returncode = 0
            proc.__enter__ = lambda s: s
            proc.__exit__ = MagicMock(return_value=False)
            mock_popen.return_value = proc
            run_corrector(config)
            cmd = mock_popen.call_args[0][0]
            assert cmd.count('--skip-source') == 2
            osv_idx = cmd.index('osv')
            ubuntu_idx = cmd.index('ubuntu')
            assert cmd[osv_idx - 1] == '--skip-source'
            assert cmd[ubuntu_idx - 1] == '--skip-source'

    def test_no_skip_sources_omits_flag(self):
        """Empty skip_sources adds no --skip-source flag."""
        from cve_agent import AgentConfig
        from cve_agent.corrector import run_corrector
        config = AgentConfig(cve_id='CVE-2025-0001',
                             cve_info_path=Path('/tmp/c.json'))
        with patch('subprocess.Popen') as mock_popen:
            proc = MagicMock()
            proc.stdout = iter([])
            proc.wait.return_value = None
            proc.returncode = 0
            proc.__enter__ = lambda s: s
            proc.__exit__ = MagicMock(return_value=False)
            mock_popen.return_value = proc
            run_corrector(config)
            cmd = mock_popen.call_args[0][0]
            assert '--skip-source' not in cmd
