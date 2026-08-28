# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Guard-parity tests between the Claude backend and the kiro agent manifest.

ClaudeBackend's ``--allowedTools`` / ``--disallowedTools`` lists are documented
as mirrors of ``cve_agent/agents/yocto-cve-backport.json``. Until now only a
comment enforced that. These tests load the manifest and fail whenever either
side drifts: a command allowed to kiro but not claude (capability gap), a
command allowed to claude but not kiro (privilege escalation), or a path kiro
denies that claude does not.
"""
import json
from pathlib import Path

import cve_agent
from cve_agent.claude_backend import (
    _ALLOWED_TOOLS,
    _DENIED_READ_WRITE,
    _DENIED_WRITE,
)

_MANIFEST_PATH = (Path(cve_agent.__file__).resolve().parent
                  / "agents" / "yocto-cve-backport.json")


def _manifest() -> dict:
    return json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))


def _kiro_allowed_commands() -> list[str]:
    settings = _manifest()["toolsSettings"]
    return settings["execute_bash"]["allowedCommands"]


def _kiro_denied_paths() -> list[str]:
    settings = _manifest()["toolsSettings"]
    return settings["fs_write"]["deniedPaths"]


def _claude_bash_prefixes() -> list[str]:
    """Extract command prefixes from Bash(<prefix>:*) allow entries."""
    return [tool[len("Bash("):-len(":*)")] for tool in _ALLOWED_TOOLS
            if tool.startswith("Bash(") and tool.endswith(":*)")]


def _base_command(command: str) -> str:
    """Normalize a kiro allowedCommands regex entry: strip anchors/wildcard.

    kiro's ``allowedCommands`` entries are regex patterns anchored with
    ``^``/``$``; a trailing "anything after the prefix" match is spelled
    ``.*$`` (e.g. ``^git add .*$``). Strip both anchors and the wildcard
    tail so the remaining literal prefix (e.g. ``git add``) can be compared
    against Claude's plain-text ``Bash(<prefix>:*)`` rules.
    """
    base = command
    if base.startswith("^"):
        base = base[1:]
    if base.endswith("$"):
        base = base[:-1]
    if base.endswith(".*"):
        base = base[:-2]
    base = base.replace("\\.", ".").strip()
    return base


def _to_claude_path(kiro_path: str) -> str:
    """Map a kiro deniedPaths entry to Claude Code's path-rule form.

    Claude Code spells absolute paths with a leading ``//``; home-relative
    and workspace-relative globs are identical in both.
    """
    return "/" + kiro_path if kiro_path.startswith("/") else kiro_path


def test_manifest_exists_and_parses():
    assert _MANIFEST_PATH.is_file()
    assert _kiro_allowed_commands()
    assert _kiro_denied_paths()


def test_every_kiro_command_is_allowed_for_claude():
    """No capability gap: each command the kiro agent may run must be covered
    by some Bash(<prefix>:*) entry in the Claude allow-list."""
    prefixes = _claude_bash_prefixes()
    for command in _kiro_allowed_commands():
        base = _base_command(command)
        covered = any(base == prefix or base.startswith(prefix + " ")
                      for prefix in prefixes)
        assert covered, (
            f"kiro allows {command!r} but no Claude Bash allow rule covers it")


def test_no_claude_bash_rule_beyond_kiro_allowlist():
    """No privilege escalation: each Claude Bash allow prefix must trace back
    to at least one command in the kiro manifest.

    Prefix rules are inherently broader than kiro's exact patterns —
    ``Bash(git cherry-pick:*)`` also permits ``git cherry-pick <sha>``, not
    just ``--continue``/``--abort``. This test locks the command *families*;
    the git pre-commit hook remains the authoritative file-scope guard.
    """
    kiro_bases = [_base_command(c) for c in _kiro_allowed_commands()]
    for prefix in _claude_bash_prefixes():
        justified = any(base == prefix or base.startswith(prefix + " ")
                        for base in kiro_bases)
        assert justified, (
            f"Claude allows Bash({prefix}:*) but the kiro manifest has no "
            f"matching allowedCommands entry")


def test_documented_git_show_path_form_is_allowed_for_claude():
    """``git show HEAD:<path>`` is documented in AGENT_INSTRUCTIONS.md as the
    way to read a file as committed, so the ``git show`` family must stay in
    Claude's allow-list too — not just kiro's."""
    assert 'git show' in _claude_bash_prefixes()


def test_every_kiro_denied_path_is_write_denied_for_claude():
    """Each path kiro denies writes to must appear in a Claude deny list
    (in Claude's ``//`` absolute-path spelling where applicable)."""
    claude_denied = set(_DENIED_WRITE) | set(_DENIED_READ_WRITE)
    for kiro_path in _kiro_denied_paths():
        assert _to_claude_path(kiro_path) in claude_denied, (
            f"kiro denies writes to {kiro_path!r} but Claude does not")


def test_claude_denies_reads_on_sensitive_paths():
    """Claude goes beyond kiro by also denying reads of secret/system paths;
    ensure the read-deny list keeps covering the sensitive subset."""
    sensitive = {"//etc/**", "~/.ssh/**", "~/.aws/**", "~/.netrc",
                 "~/.gitconfig", "~/.kiro/**"}
    assert sensitive <= set(_DENIED_READ_WRITE)
