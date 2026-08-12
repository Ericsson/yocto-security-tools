# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Regression tests for cve_agent.session._ensure_cve_branch.

The agent must operate on the CVE branch (the source of truth that
cherry_pick_to_devtool transfers to the throwaway devtool branch). The
corrector's build step leaves the *devtool* branch checked out, and the
agent's command allow-list forbids switching branches. Without an explicit
switch, the agent would amend its fix onto devtool, where it is orphaned when
the session forces back to the CVE branch and then wiped on the next resume by
reset_devtool_to_base + cherry_pick_to_devtool re-applying the unfixed
CVE-branch commit — silently reverting the fix every round.
"""
import subprocess

import pytest

from cve_agent.session import _ensure_cve_branch


def _git(cwd, *args):
    subprocess.run(
        ['git', *args], cwd=cwd, check=True,
        capture_output=True, text=True,
    )


def _current_branch(cwd):
    return subprocess.run(
        ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
        cwd=cwd, capture_output=True, text=True, check=True,
    ).stdout.strip()


@pytest.fixture
def devtool_repo(tmp_path):
    """A workspace mirroring a devtool-modify tree mid-CVE-workflow.

    Branches: ``devtool-base`` (pristine), ``CVE-2025-6021`` (the CVE fix
    commit, source of truth), and ``devtool`` (throwaway build branch). The
    tree is left on ``devtool`` — exactly how the corrector's build step
    leaves it before the AI session starts.
    """
    repo = tmp_path / "libxml2"
    repo.mkdir()
    _git(repo, 'init', '-q')
    _git(repo, 'config', 'user.email', 'test@example.com')
    _git(repo, 'config', 'user.name', 'Test')
    (repo / 'tree.c').write_text("#include <limits.h>\nint main(void){return 0;}\n")
    _git(repo, 'add', 'tree.c')
    _git(repo, 'commit', '-q', '-m', 'Initial commit from upstream at 2.12.10')
    _git(repo, 'branch', 'devtool-base')
    # CVE branch carries the cherry-picked fix commit (source of truth).
    _git(repo, 'checkout', '-q', '-b', 'CVE-2025-6021')
    (repo / 'tree.c').write_text(
        "#include <limits.h>\nint main(void){return 0;}\n/* fix */\n")
    _git(repo, 'add', 'tree.c')
    _git(repo, 'commit', '-q', '-m', 'Fix: Integer Overflow in xmlBuildQName()')
    # devtool branch is the build branch; leave the tree checked out on it.
    _git(repo, 'checkout', '-q', '-b', 'devtool', 'devtool-base')
    # xmlconf/ mirrors libxml2's secondary-tarball W3C conformance suite:
    # tracked on devtool (committed from the unpacked tarball) but absent from
    # the upstream-history CVE branch. do_configure needs it present.
    (repo / 'xmlconf').mkdir()
    (repo / 'xmlconf' / 'test.xml').write_text("<x/>\n")
    _git(repo, 'add', 'xmlconf/test.xml')
    _git(repo, 'commit', '-q', '-m', 'unpack xmlconf test suite from tarball')
    return repo


def test_switches_from_devtool_to_cve_branch(devtool_repo):
    assert _current_branch(devtool_repo) == 'devtool'
    _ensure_cve_branch(devtool_repo, 'CVE-2025-6021')
    assert _current_branch(devtool_repo) == 'CVE-2025-6021'


def test_restores_devtool_tracked_files_missing_on_cve(devtool_repo):
    """Tarball payloads tracked on devtool but not on the CVE branch (e.g.
    xmlconf/) must be restored after the switch, or the agent's own
    ``devtool build`` fails in do_configure looking for them."""
    # Present on devtool (where the fixture leaves the tree).
    assert (devtool_repo / 'xmlconf' / 'test.xml').exists()

    _ensure_cve_branch(devtool_repo, 'CVE-2025-6021')

    assert _current_branch(devtool_repo) == 'CVE-2025-6021'
    # Restored into the working tree even though the CVE branch never tracked it.
    assert (devtool_repo / 'xmlconf' / 'test.xml').exists(), \
        "devtool-tracked tarball file was not restored on the CVE branch"
    # ...and left untracked (not committed onto the CVE branch).
    status = subprocess.run(
        ['git', 'status', '--porcelain', '--', 'xmlconf/test.xml'],
        cwd=devtool_repo, capture_output=True, text=True, check=True,
    ).stdout
    assert status.startswith('??'), \
        f"expected xmlconf/test.xml untracked, got: {status!r}"


def test_switches_even_with_dirty_worktree(devtool_repo):
    """A dirty tree (e.g. regenerated autotools output) must not block the
    switch — force_checkout_branch escalates cleanup as needed."""
    (devtool_repo / 'tree.c').write_text("locally modified, would block checkout\n")
    _ensure_cve_branch(devtool_repo, 'CVE-2025-6021')
    assert _current_branch(devtool_repo) == 'CVE-2025-6021'


def test_noop_when_already_on_cve_branch(devtool_repo):
    _git(devtool_repo, 'checkout', '-q', 'CVE-2025-6021')
    head_before = subprocess.run(
        ['git', 'rev-parse', 'HEAD'], cwd=devtool_repo,
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    _ensure_cve_branch(devtool_repo, 'CVE-2025-6021')
    assert _current_branch(devtool_repo) == 'CVE-2025-6021'
    head_after = subprocess.run(
        ['git', 'rev-parse', 'HEAD'], cwd=devtool_repo,
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert head_before == head_after


def test_noop_when_cve_branch_missing(devtool_repo):
    """If the named branch doesn't exist, stay put rather than error."""
    _ensure_cve_branch(devtool_repo, 'CVE-9999-0000')
    assert _current_branch(devtool_repo) == 'devtool'


def test_noop_when_cve_id_empty(devtool_repo):
    _ensure_cve_branch(devtool_repo, '')
    assert _current_branch(devtool_repo) == 'devtool'


def test_noop_when_workspace_missing(tmp_path):
    # Must not raise when the workspace directory does not exist.
    _ensure_cve_branch(tmp_path / 'gone', 'CVE-2025-6021')
