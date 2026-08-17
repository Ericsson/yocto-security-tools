# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for the agent manifests' bash allow-list and fs_write deny-list.

Two classes of regression are guarded here:

1. **Capability gaps.** Commands the documented workflow tells the agent to
   run (``git commit --amend --no-edit``, ``git rm``, ``git restore --staged``,
   ``git checkout --ours/--theirs``, ``git cherry-pick --skip``) must actually
   be permitted, and read-only diagnostics (``git ls-files -u``,
   ``git submodule status``) must be available.
2. **Blast-radius creep.** The additions above must not smuggle in the
   destructive forms of the same commands (``git reset --hard``,
   ``git restore`` without ``--staged``, ``git checkout <path>``,
   ``--no-verify``), nor allow command chaining or command substitution.

The fs_write tests cover the third regression: a blanket ``**/tests/**`` deny
rule contradicted the session's own Allowed Files list, which routinely
includes a recipe's regression tests (e.g. jq's ``tests/jq.test``).
"""
import json
import re
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_MANIFESTS = {
    "kiro": _PROJECT_ROOT / ".kiro" / "agents",
    "packaged": _PROJECT_ROOT / "cve_agent" / "agents",
}
_AGENT_NAMES = ("yocto-cve-backport", "yocto-cve-backport-interactive")


def _load(agent_dir: Path, name: str) -> dict:
    return json.loads((agent_dir / f"{name}.json").read_text(encoding="utf-8"))


def _allowed_commands(name: str, source: str = "kiro") -> list[str]:
    return _load(_MANIFESTS[source], name)["toolsSettings"]["execute_bash"][
        "allowedCommands"]


def _permitted(command: str, name: str = "yocto-cve-backport") -> bool:
    """Whether kiro's allowedCommands admit ``command`` (whole-command match)."""
    return any(re.fullmatch(pattern, command)
               for pattern in _allowed_commands(name))


# Commands the workflow documented in AGENT_INSTRUCTIONS.md requires.
MUST_ALLOW = [
    # Unstage a single path — index-only, working tree untouched. Needed for
    # every tarball-sourced recipe whose upstream history records a gitlink.
    "git restore --staged modules/oniguruma",
    "git restore --staged -- modules/oniguruma",
    # Take one side of a conflict wholesale.
    "git checkout --ours tests/jq.test",
    "git checkout --theirs tests/jq.test",
    "git checkout --theirs -- src/execute.c",
    # Mark a resolution where upstream deleted the file.
    "git rm src/gone.c",
    "git rm -- src/gone.c",
    "git rm --cached modules/oniguruma",
    # Commit by hand (pre-commit hook still enforces file scope).
    'git commit -m "jq: fix CVE-2024-1234"',
    "git commit -F /ws/cve_agent/jq/msg.txt",
    # Documented in the build.md fragment / AGENT_INSTRUCTIONS.md §5 for
    # build-failure iterations.
    "git commit --amend --no-edit",
    'git commit --amend -m "reworded"',
    "git commit --amend -F /ws/msg.txt",
    # git itself suggests --skip on every conflict.
    "git cherry-pick --skip",
    # Read-only diagnostics.
    "git ls-files",
    "git ls-files -u",
    "git ls-files -s tests/jq.test",
    "git submodule status",
    "git submodule status modules/oniguruma",
    # Recover stale build state (busybox .config.orig etc.) — a single recipe,
    # forces do_configure to re-run. Recipe names may contain '.', '-', digits.
    "bitbake -c cleansstate busybox",
    "bitbake -c cleansstate gstreamer1.0-plugins-good",
]

# Forms that must stay rejected: destructive variants of the newly allowed
# commands, hook bypasses, and shell chaining/substitution.
MUST_DENY = [
    # Bare git reset in any form — no index-only/pathspec exception.
    "git reset",
    "git reset --hard",
    "git reset --hard HEAD~1",
    "git reset -- tests/jq.test",
    # git restore without --staged discards working-tree edits.
    "git restore tests/jq.test",
    "git restore --worktree tests/jq.test",
    "git restore --staged tests/jq.test --worktree",
    # git checkout of a path (or a branch) is not the --ours/--theirs form.
    "git checkout tests/jq.test",
    "git checkout main",
    "git checkout -b other",
    # Multiple pathspecs in one call are rejected (one path per invocation).
    "git checkout --ours -- a b",
    "git rm a b",
    # Hook bypass / history rewrite / remote mutation.
    "git commit --no-verify",
    'git commit --no-verify -m "x"',
    'git commit -m "x" --no-verify',
    "git commit -F msg.txt --no-verify",
    "git commit --amend --no-edit --no-verify",
    "git push --force",
    "git clean -f",
    # Editor-blocking commit forms (would hang a headless session).
    "git commit",
    "git commit --amend",
    # Deliberately excluded tools.
    "git stash",
    "git stash pop",
    "git submodule update --init",
    "git submodule foreach rm -rf .",
    # bitbake is allowed ONLY as `-c cleansstate <recipe>`; nothing else.
    "bitbake core-image-minimal",
    "bitbake busybox",
    "bitbake -c clean busybox",
    "bitbake -c cleanall busybox",
    "bitbake -c cleansstate -rf",
    "bitbake -c cleansstate busybox; rm -rf /",
    "bitbake -c cleansstate busybox && rm -rf /",
    "bitbake -c cleansstate $(echo busybox)",
    # Chaining and command substitution.
    "git rm x; rm -rf /",
    "git rm $(echo x)",
    "git restore --staged x && rm -rf /",
    "git checkout --theirs x | tee y",
    "git ls-files -u; rm -rf /",
    'git commit -m "$(rm -rf /)"',
    'git commit -m "a" ; rm -rf /',
    "git commit -F `echo x`",
]


@pytest.mark.parametrize("agent", _AGENT_NAMES)
@pytest.mark.parametrize("command", MUST_ALLOW)
def test_required_command_is_permitted(agent, command):
    assert _permitted(command, agent), (
        f"{agent} must permit {command!r} — it is part of the documented "
        f"backport workflow")


@pytest.mark.parametrize("command", MUST_DENY)
def test_destructive_command_is_rejected(command):
    assert not _permitted(command), (
        f"yocto-cve-backport must NOT permit {command!r}")


@pytest.mark.parametrize("command", MUST_DENY)
def test_destructive_command_is_rejected_interactive(command):
    """The interactive manifest gates on human approval but must not be a
    looser allow-list, except for its documented extras (``git format-patch``,
    ``find``, ``grep``). Bare ``git checkout <path>`` (without ``--ours``/
    ``--theirs``) is explicitly documented as unavailable in
    AGENT_INSTRUCTIONS.md, so it must be rejected here too."""
    assert not _permitted(command, "yocto-cve-backport-interactive"), (
        f"yocto-cve-backport-interactive must NOT permit {command!r}")


@pytest.mark.parametrize("agent", _AGENT_NAMES)
def test_packaged_and_kiro_manifests_are_identical(agent):
    """``cve_agent.setup.AGENT_SOURCE_DIR`` prefers .kiro/agents/ for editable
    installs and falls back to the packaged copy, so the two must not drift."""
    assert _load(_MANIFESTS["kiro"], agent) == _load(_MANIFESTS["packaged"], agent)


@pytest.mark.parametrize("agent", _AGENT_NAMES)
def test_allowed_commands_compile_and_are_anchored(agent):
    for pattern in _allowed_commands(agent):
        re.compile(pattern)
        assert pattern.startswith("^") and pattern.endswith("$"), (
            f"{pattern!r} must be anchored so it matches whole commands only")


# --- fs_write deny-list ---

def _glob_to_regex(pattern: str) -> re.Pattern:
    """Compile a globset-style deny pattern to a regex.

    Mirrors the semantics kiro-cli/Claude Code use for these path rules:
    ``**`` matches any number of path segments (including none, so ``**/x``
    also matches a top-level ``x``), and ``*`` matches within one segment.
    """
    out = ""
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:[^/]+/)*"
            i += 3
        elif pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(f"{out}\\Z")


def _write_denied(path: str, agent: str = "yocto-cve-backport") -> bool:
    denied = _load(_MANIFESTS["kiro"], agent)["toolsSettings"]["fs_write"][
        "deniedPaths"]
    return any(_glob_to_regex(p).match(path) for p in denied)


@pytest.mark.parametrize("agent", _AGENT_NAMES)
@pytest.mark.parametrize("path", [
    # A recipe's own regression tests are regular backport targets and appear
    # in the session's Allowed Files list — the write tool must not refuse them.
    "tests/jq.test",
    "tests/CVE-2024-1234.test",
    "tests/data/input.json",
    "src/execute.c",
    "modules/oniguruma/src/regcomp.c",
])
def test_recipe_workspace_paths_are_writable(agent, path):
    assert not _write_denied(path, agent), (
        f"{agent} denies writes to {path!r}, but a recipe workspace path like "
        f"this can legitimately be in the session's Allowed Files list")


@pytest.mark.parametrize("agent", _AGENT_NAMES)
@pytest.mark.parametrize("path", [
    # This project's own code and tests stay write-protected.
    "cve_agent/session.py",
    "cve_corrector/workflow.py",
    "cve_metadata_extractor/sources.py",
    "shared/exit_codes.py",
    "tests/agent/test_security.py",
    "tests/corrector/test_workflow.py",
    "tests/extractor/test_sources.py",
    "tests/shared/test_paths.py",
    "tests/integration/test_pipeline.py",
    "/etc/passwd",
])
def test_project_paths_stay_write_protected(agent, path):
    assert _write_denied(path, agent), (
        f"{agent} must keep denying writes to {path!r}")


@pytest.mark.parametrize("agent", _AGENT_NAMES)
def test_no_blanket_tests_deny_rule(agent):
    """Regression guard: ``**/tests/**`` contradicted the Allowed Files list."""
    denied = _load(_MANIFESTS["kiro"], agent)["toolsSettings"]["fs_write"][
        "deniedPaths"]
    assert "**/tests/**" not in denied
