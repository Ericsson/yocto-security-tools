# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for the agent manifests' bash allow-list and fs_write deny-list.

Two classes of regression are guarded here:

1. **Capability gaps.** Commands the documented workflow tells the agent to
   run (``git commit --amend --no-edit``, ``git rm``, ``git restore --staged``,
   ``git checkout --ours/--theirs``, ``git cherry-pick --skip``) must actually
   be permitted, and read-only diagnostics (``git ls-files -u``,
   ``git submodule status``, ``git branch``, ``git describe``, ``git ls-tree``,
   ``git show-ref``, ``git cat-file``, ``git grep``, ``sed -n 'A,Bp'``) must be
   available. The read-only set and the multi-path pathspec forms were added
   after benchmark run ``bench_20260828_145923``, where 41 of 133 recorded
   ``execute_bash`` rejections were safe commands the regexes refused on a
   technicality (see ``TestBenchmarkAllowListGaps``).
2. **Blast-radius creep.** The additions above must not smuggle in the
   destructive forms of the same commands (``git reset --hard``,
   ``git restore`` without ``--staged``, ``git checkout <path>``,
   ``git revert``, ``git update-ref``, ``git branch -f``, ``sed -i``,
   ``--no-verify``), nor allow command chaining or command substitution.

The fs_write tests cover the third regression: a blanket ``**/tests/**`` deny
rule contradicted the session's own Allowed Files list, which routinely
includes a recipe's regression tests (e.g. jq's ``tests/jq.test``).
"""
import json
import re
from pathlib import Path

import pytest

from tests.agent.allowlist_model import kiro_permits

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_MANIFESTS = {
    "kiro": _PROJECT_ROOT / ".kiro" / "agents",
    "packaged": _PROJECT_ROOT / "cve_agent" / "agents",
}
_AGENT_INSTRUCTIONS = _PROJECT_ROOT / "cve_agent" / "AGENT_INSTRUCTIONS.md"
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
    # Several paths in one call. Benchmark bench_20260828_145923 showed models
    # burning turns degrading to one-file-per-call after a multi-path rejection.
    "git restore --staged common-kex.c runopts.h svr-runopts.c",
    "git restore --staged -- a.c b.c",
    "git status --porcelain -- src/cli-main.c src/cli-runopts.c src/dbutil.h",
    "git checkout --ours -- a.c b.c",
    "git checkout --theirs ld/emultempl/vms.em ld/ldexp.c ld/ldlang.c",
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
    # Read-only ref/object queries. Every one of these was attempted and
    # rejected during bench_20260828_145923 while the AI was orienting itself.
    "git branch",
    "git branch -a",
    "git branch --contains b706c5c5",
    "git branch -a --contains 8ebe3ac",
    "git describe",
    "git describe --tags e5a0ef27",
    "git describe --tags original-version",
    "git show-ref",
    "git show-ref refs/heads/CVE-2024-1234",
    "git ls-tree -r --name-only c3d1e47573",
    "git cat-file -t b706c5c5b7ce11d002a5b77ff938aa3693931c12",
    "git cat-file -s b706c5c5",
    "git grep -n lbool -- less.h",
    # Read a file **as committed** rather than as it sits in the working tree —
    # documented in AGENT_INSTRUCTIONS.md "Available Tools".
    "git show HEAD:src/execute.c",
    "git show HEAD:tests/jq.test",
    "git show original-version:src/execute.c",
    "git show abc1234:src/execute.c",
    # Print one line range. Read-only, and strictly weaker than the already
    # allowed `head N | tail M` pipeline it replaces.
    "sed -n '9968,9980p' ld/ldlang.c",
    "sed -n '1,20p'",
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
    "git checkout HEAD~1",
    "git checkout HEAD~1 -- tests/jq.test",
    # Multi-path pathspecs are accepted for the --ours/--theirs/--staged forms,
    # but every path must still be a path: a trailing flag is read as a path
    # starting with '-' and rejected, so flag injection stays closed.
    "git restore --staged tests/jq.test --worktree",
    "git checkout --ours a.c --force",
    "git checkout --theirs a.c -f",
    # git rm stays one path per invocation (no benchmark evidence for widening).
    "git rm a b",
    # History rewriting / ref mutation is unavailable in every form — this is
    # what AGENT_INSTRUCTIONS.md "Undoing a Bad Cherry-Pick" exists to replace.
    "git revert 74e1c836c53",
    "git revert --no-edit 74e1c836c53",
    "git update-ref HEAD c3d1e47573",
    "git branch -f CVE-2025-47183 c3d1e47573",
    "git branch -d topic",
    "git branch -D topic",
    "git branch -m old new",
    "git branch newbranch",
    "git branch --contains $(id)",
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
    # sed is allowed ONLY as a read-only line-range print.
    "sed -i 's/a/b/' tests/jq.test",
    "sed -i.bak 's/a/b/' tests/jq.test",
    "sed 's/a/b/' tests/jq.test",
    "sed -n 'p' tests/jq.test",
    "sed -n '1,20p' --in-place",
    "sed -n '1,20p' a.c b.c",
    "sed -e 's/a/b/' a.c",
    # Chaining and command substitution.
    "git rm x; rm -rf /",
    "git rm $(echo x)",
    "git restore --staged x && rm -rf /",
    "git restore --staged a.c b.c && rm -rf /",
    "git checkout --theirs x | tee y",
    "git ls-files -u; rm -rf /",
    "git ls-tree -r x; rm -rf /",
    "git show-ref; rm -rf /",
    "git describe --tags; rm -rf /",
    "git grep $(id)",
    "git cat-file -t `id`",
    "git status --porcelain -- a.c; rm -rf /",
    "sed -n '1,2p' a.c; rm -rf /",
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


class TestBenchmarkAllowListGaps:
    """Regression guards for the four gaps found in ``bench_20260828_145923``.

    Each command below was rejected by kiro-cli during that run even though it
    is read-only or is the documented workflow's own idiom. Counts are the
    number of rejections attributed to that shape across the 35 runs.

    These use :func:`kiro_permits` rather than ``re.fullmatch`` because two of
    the four gaps only show up once a command is split into pipeline segments.
    """

    @staticmethod
    def _permits(command: str, agent: str = "yocto-cve-backport") -> bool:
        return kiro_permits(command, _allowed_commands(agent))

    # Gap 1 (12 rejections): the pathspec regexes matched exactly one path, so
    # resolving a conflict across N files needed N calls. qwen3-coder-next
    # retried `git restore --staged` six times on CVE-2025-47203 before
    # degrading to one file per invocation.
    @pytest.mark.parametrize("agent", _AGENT_NAMES)
    @pytest.mark.parametrize("command", [
        "git checkout --theirs cli-runopts.c runopts.h",
        "git checkout --theirs ld/emultempl/vms.em ld/ldexp.c ld/ldlang.c "
        "ld/ldwrite.c ld/plugin.c",
        "git checkout --ours a.c b.c c.c",
        "git restore --staged common-kex.c runopts.h svr-runopts.c",
        "git restore --staged -- common-kex.c runopts.h",
        "git status --porcelain -- src/cli-main.c src/cli-runopts.c "
        "src/dbutil.c src/dbutil.h src/runopts.h",
    ])
    def test_multi_path_pathspecs_are_permitted(self, agent, command):
        assert self._permits(command, agent)

    @pytest.mark.parametrize("agent", _AGENT_NAMES)
    @pytest.mark.parametrize("command", [
        # A trailing flag must read as a path starting with '-' and be rejected,
        # so widening to N paths cannot become flag injection.
        "git restore --staged a.c --worktree",
        "git restore --staged a.c b.c --worktree",
        "git checkout --ours a.c --force",
        "git checkout --theirs a.c b.c -f",
        # ...and chaining must still be impossible through the widened rules.
        "git restore --staged a.c b.c; rm -rf /",
        "git checkout --theirs a.c b.c && rm -rf /",
        "git status --porcelain -- a.c b.c | rm -rf /",
    ])
    def test_multi_path_widening_does_not_leak(self, agent, command):
        assert not self._permits(command, agent)

    # Gap 2 (11 rejections): read-only ref/object queries the AI used purely to
    # orient itself. `git grep` being denied while plain `grep` was allowed was
    # a straight inconsistency.
    @pytest.mark.parametrize("agent", _AGENT_NAMES)
    @pytest.mark.parametrize("command", [
        "git branch",
        "git branch -a",
        "git branch -a --contains 8ebe3ac",
        "git branch --contains b706c5c5",
        "git describe --tags e5a0ef27",
        "git ls-tree -r --name-only c3d1e47573",
        "git show-ref",
        "git cat-file -t b706c5c5b7ce11d002a5b77ff938aa3693931c12",
        "git grep -n lbool -- less.h",
        # Reached through a pipe, as the AI actually wrote them.
        "git branch -a | head -20",
        "git ls-tree -r --name-only c3d1e47573 | grep qtatom",
    ])
    def test_readonly_ref_queries_are_permitted(self, agent, command):
        assert self._permits(command, agent)

    @pytest.mark.parametrize("agent", _AGENT_NAMES)
    @pytest.mark.parametrize("command", [
        # The mutating git branch forms must stay denied — these are what the
        # AI reached for next when trying to rewind a committed cherry-pick.
        "git branch -f CVE-2025-47183 c3d1e47573",
        "git branch -f CVE-2025-47203 HEAD~1",
        "git branch -d topic",
        "git branch -D topic",
        "git branch -m old new",
        "git branch -M old new",
        "git branch -c old new",
        "git branch newbranch",
        "git branch newbranch c3d1e47573",
        "git update-ref HEAD c3d1e47573",
    ])
    def test_ref_mutation_stays_denied(self, agent, command):
        assert not self._permits(command, agent)

    # Gap 3 (10 rejections): `echo` was pinned to two verbatim strings, so the
    # natural `echo "Exit: $?"` killed the whole build-verify pipeline it was
    # attached to. qwen3-coder-next lost its build verification on
    # CVE-2025-47183 this way.
    @pytest.mark.parametrize("agent", _AGENT_NAMES)
    @pytest.mark.parametrize("command", [
        'echo "Exit code: $?"',
        'echo "Exit code: ${PIPESTATUS[0]}"',
        'echo "Exit: $?"',
        'echo "Exit: ${PIPESTATUS[0]}"',
        'echo "build exit code: $?"',
        'devtool build gstreamer1.0-plugins-good 2>&1 | tail -5; '
        'echo "Exit: $?"',
    ])
    def test_exit_code_echo_variants_are_permitted(self, agent, command):
        assert self._permits(command, agent)

    @pytest.mark.parametrize("agent", _AGENT_NAMES)
    @pytest.mark.parametrize("command", [
        # echo must still not be a general-purpose shell primitive: the message
        # has to end in an exit-code expansion, and no other expansion is
        # reachable.
        'echo hello',
        'echo "Done"',
        'echo "$(rm -rf /)"',
        'echo "`id`"',
        'echo "${HOME}"',
        'echo "$?extra"',
        'echo',
        'echo "Exit: $?" > /tmp/out',
    ])
    def test_echo_stays_narrow(self, agent, command):
        assert not self._permits(command, agent)

    # Gap 4 (8 rejections): every attempted `sed` was the read-only line-range
    # print, which is strictly weaker than the `head N | tail M` pipeline that
    # was already allowed.
    @pytest.mark.parametrize("agent", _AGENT_NAMES)
    @pytest.mark.parametrize("command", [
        "sed -n '9968,9980p' ld/ldlang.c",
        "sed -n '35,45p' /ws/sources/libxml2/catalog.c",
        "sed -n '1,20p'",
        "git show HEAD:gst/isomp4/qtdemux.c | sed -n '14190,14240p'",
        "git show original-version:catalog.c | sed -n '2774,2820p'",
    ])
    def test_sed_line_range_is_permitted(self, agent, command):
        assert self._permits(command, agent)

    @pytest.mark.parametrize("agent", _AGENT_NAMES)
    @pytest.mark.parametrize("command", [
        # In-place and substitution forms can write files — they stay denied.
        "sed -i 's/a/b/' catalog.c",
        "sed -i.bak 's/a/b/' catalog.c",
        "sed -i -e 's/a/b/' catalog.c",
        "sed 's/a/b/' catalog.c",
        "sed -e 's/a/b/' catalog.c",
        "sed -n 'p' catalog.c",
        "sed -n '1,20p' catalog.c > out.c",
        "sed -n '1,20p' a.c; rm -rf /",
        "sed -n '$(id)p' a.c",
    ])
    def test_sed_write_forms_stay_denied(self, agent, command):
        assert not self._permits(command, agent)


class TestUndoBadCherryPickIsRunnable:
    """Every command in AGENT_INSTRUCTIONS.md "Undoing a Bad Cherry-Pick" must
    actually be permitted.

    40 of the 87 rejections recorded in the failed runs of
    ``bench_20260828_145923`` were attempts to rewind a committed cherry-pick
    (``git reset``, ``git revert``, ``git update-ref``, ``git branch -f``,
    ``git checkout <commit>``) — minimax-m2.5 issued ``git revert`` nine times
    in a row against an unchanging denial. The section documents what *is*
    possible instead; if its recipe drifts out of the allow-list the agent is
    back to probing blindly, so both are pinned here.
    """

    _SECTION = "## Undoing a Bad Cherry-Pick"

    @classmethod
    def _section_text(cls) -> str:
        text = _AGENT_INSTRUCTIONS.read_text(encoding="utf-8")
        assert cls._SECTION in text, (
            f"{cls._SECTION!r} section is missing from AGENT_INSTRUCTIONS.md")
        after = text.split(cls._SECTION, 1)[1]
        return after.split("\n## ", 1)[0]

    @classmethod
    def _documented_commands(cls) -> list[str]:
        """Every command line inside the section's ```bash blocks."""
        commands = []
        for block in re.findall(r"```bash\n(.*?)```", cls._section_text(),
                                re.DOTALL):
            for line in block.splitlines():
                line = line.split("#", 1)[0].strip()
                if line:
                    commands.append(line)
        assert commands, "no bash commands found in the undo section"
        return commands

    def test_section_documents_commands(self):
        assert len(self._documented_commands()) >= 6

    @pytest.mark.parametrize("agent", _AGENT_NAMES)
    def test_every_documented_undo_command_is_permitted(self, agent):
        allowed = _allowed_commands(agent)
        for command in self._documented_commands():
            concrete = (command
                        .replace("<path>...", "catalog.c ldlang.c")
                        .replace("<path>", "catalog.c")
                        .replace("<agent_dir>", "/ws/workspace/cve_agent/jq")
                        .replace("<upstream_sha>", "48bf6a92d75051be7e5ffb66f"))
            assert "<" not in concrete, (
                f"unsubstituted placeholder in documented command: {command!r}")
            assert kiro_permits(concrete, allowed), (
                f"{agent} does not permit documented undo command "
                f"{concrete!r} (from {command!r})")

    @pytest.mark.parametrize("agent", _AGENT_NAMES)
    def test_the_four_documented_recoveries_work(self, agent):
        """Spot-check each case's key command independently of the doc parse."""
        allowed = _allowed_commands(agent)
        # Case 1: abort/skip an in-progress cherry-pick.
        assert kiro_permits("git cherry-pick --abort", allowed)
        assert kiro_permits("git cherry-pick --skip", allowed)
        # Case 2: correct the tree and amend in place.
        assert kiro_permits("git add catalog.c", allowed)
        assert kiro_permits("git commit --amend --no-edit", allowed)
        # Case 3: recover a committed pre-image via tee into the agent dir,
        # then read it back with the file tool. This is the route
        # qwen3-coder-next came within one `&& echo "Done"` of finding.
        assert kiro_permits(
            "git show original-version:catalog.c | tee "
            "/ws/workspace/cve_agent/libxml2/pre-image.log", allowed)
        # Case 4: size up the mismatch, then escalate.
        assert kiro_permits("git log original-version..HEAD --oneline", allowed)
        assert kiro_permits("git show --stat HEAD", allowed)

    @pytest.mark.parametrize("agent", _AGENT_NAMES)
    @pytest.mark.parametrize("command", [
        # The section promises these do NOT work; if any starts working, the
        # instructions are lying to the model.
        "git reset --hard HEAD",
        "git reset --hard HEAD~1",
        "git reset --soft HEAD~1",
        "git reset HEAD~1",
        "git revert HEAD",
        "git revert --no-edit 74e1c836c53",
        "git update-ref HEAD c3d1e47573",
        "git branch -f CVE-2025-47183 c3d1e47573",
        "git checkout HEAD~1",
        "git checkout HEAD~1 -- catalog.c",
        "git restore catalog.c",
        "git restore --source c3d1e47573 catalog.c",
        # tee must not become a way to write the source file back directly.
        "git show original-version:catalog.c | tee catalog.c",
        "git show original-version:catalog.c | tee /ws/sources/libxml2/"
        "catalog.c",
        "cp /tmp/original.c catalog.c",
    ])
    def test_documented_dead_ends_stay_denied(self, agent, command):
        assert not kiro_permits(command, _allowed_commands(agent)), (
            f"AGENT_INSTRUCTIONS.md tells the agent {command!r} is "
            f"unavailable, so it must stay denied")


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
