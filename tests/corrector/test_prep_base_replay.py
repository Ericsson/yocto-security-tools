# SPDX-License-Identifier: MIT
"""Regression tests for recipe-patch replay onto the CVE branch.

Models the CVE-2025-47273 / python3-setuptools failure with real git:

* the recipe carries an earlier patch (``CVE-2024-6345``) that rewrites the
  very function the new CVE fix touches
* that patch's diff also touches a packaging file (``setup.cfg``) whose
  release-tarball copy differs from the upstream git copy
* replaying it onto the upstream release tag therefore conflicts

The old behaviour aborted the whole cherry-pick, so the CVE branch kept the
*unpatched* function, the AI resolved the fix against it, and the resulting
commits could not be anchored on the devtool branch
(``TRANSFER_CONTEXT_MISMATCH``). The replay now keeps the cleanly merged source
paths and drops only the conflicted packaging file, and aborts up front when a
conflicted path is one the fix itself changes.
"""
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from cve_corrector.state import PrepBaseMismatchError
from cve_corrector.transfer import TransferError, transfer_commits
from cve_corrector.workspace import (
    collect_fix_commit_paths,
    prepare_cve_branch,
    read_prep_report,
)
from shared.exit_codes import EXIT_PREP_BASE_MISMATCH

CVE_ID = "CVE-2026-47273"

# Upstream release content: the fix's target function before the recipe patch.
PKG_RELEASE = """\
def download(self, scheme, url, tmp):
    name = info(url)
    filename = join(tmp, name)
    if scheme == 'svn':
        return vcs(url, filename)
    return other(url, filename)
"""

# After the recipe's earlier CVE patch (upstream "modernize" commit): the
# signature and dispatch the new fix must be written against.
PKG_MODERNIZED = """\
def download(self, url, tmp):
    name = info(url)
    filename = join(tmp, name)
    return download_vcs(url, filename) or download_other(url, filename)
"""

# The new CVE fix: a path-traversal guard added to the modernized function.
PKG_FIXED = """\
def download(self, url, tmp):
    name = info(url)
    filename = join(tmp, name)
    if not filename.startswith(str(tmp)):
        raise ValueError(f"Invalid filename {filename}")
    return download_vcs(url, filename) or download_other(url, filename)
"""

# What a model produces when the recipe patch was dropped from the base: the
# fix is adapted to the *release* signature and dispatch, so its removed lines
# do not exist on the devtool branch.
PKG_ADAPTED_TO_RELEASE = """\
def resolve(url, tmp):
    name = info(url)
    filename = join(tmp, name)
    if not filename.startswith(str(tmp)):
        raise ValueError(f"Invalid filename {filename}")
    return filename


def download(self, scheme, url, tmp):
    filename = resolve(url, tmp)
    if scheme == 'svn':
        return vcs(url, filename)
    return other(url, filename)
"""

# Packaging file: the sdist copy is regenerated and differs from the git copy by
# a trailing space on the line right after the recipe patch's insertion point —
# exactly what made the real replay conflict.
CFG_UPSTREAM = "[options]\ntesting =\n\tpytest\ntesting-integration =\n"
CFG_TARBALL = "[options]\ntesting =\n\tpytest\ntesting-integration = \n"
CFG_TARBALL_PATCHED = (
    "[options]\ntesting =\n\tpytest\n\tpytest-subprocess\ntesting-integration = \n")


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(['git', *args], cwd=repo, check=True,
                            capture_output=True, text=True)
    return result.stdout.strip()


def _commit(repo: Path, files: dict[str, str], message: str) -> str:
    for name, content in files.items():
        (repo / name).write_text(content)
    _git(repo, 'add', '-A')
    _git(repo, 'commit', '-m', message)
    return _git(repo, 'rev-parse', 'HEAD')


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """Build a devtool-like workspace with a conflicting recipe patch."""
    repo = tmp_path / "setuptools"
    repo.mkdir()
    # The upstream history is fetched into a devtool workspace under an
    # ``upstream`` remote, so it must not look like a devtool base branch
    # (main/master/devtool-base) to prepare_cve_branch.
    _git(repo, 'init', '-q', '-b', 'upstream-history')
    _git(repo, 'config', 'user.email', 'test@example.com')
    _git(repo, 'config', 'user.name', 'Test')
    _git(repo, 'config', 'commit.gpgsign', 'false')

    # Upstream release tag.
    _commit(repo, {'Makefile': 'all:\n', 'pkg.py': PKG_RELEASE,
                   'setup.cfg': CFG_UPSTREAM}, 'release 1.0')
    _git(repo, 'tag', 'v1.0')
    # Upstream fix commit, written against the modernized function.
    _commit(repo, {'pkg.py': PKG_MODERNIZED, 'setup.cfg': CFG_UPSTREAM},
            'modernize download dispatch')
    fix = _commit(repo, {'pkg.py': PKG_FIXED}, 'ensure target stays in tmp')
    _git(repo, 'branch', 'fix', fix)

    # devtool workspace: tarball import, then the recipe's own patches.
    _git(repo, 'checkout', '-q', '--orphan', 'devtool-base')
    _git(repo, 'rm', '-q', '-rf', '.')
    (repo / 'Makefile').write_text('all:\n')
    (repo / 'pkg.py').write_text(PKG_RELEASE)
    (repo / 'setup.cfg').write_text(CFG_TARBALL)
    _git(repo, 'add', '-A')
    _git(repo, 'commit', '-m', 'Initial commit from upstream tarball')
    _git(repo, 'checkout', '-q', '-b', 'devtool')
    _commit(repo, {'pkg.py': PKG_MODERNIZED,
                   'setup.cfg': CFG_TARBALL_PATCHED},
            'recipe patch: modernize download dispatch (earlier CVE)')
    _git(repo, 'tag', 'devtool-patched', 'devtool')

    # The corrector starts the CVE branch at the release tag.
    _git(repo, 'checkout', '-q', '-b', CVE_ID, 'v1.0')
    return repo


def _prepare(workspace_path: Path, protected: set[str]):
    """Run the replay with the unrelated devtool plumbing stubbed out."""
    with patch("cve_corrector.workspace._init_submodules"), \
            patch("cve_corrector.workspace.copy_missing_files_from_devtool"), \
            patch("cve_corrector.workspace.remove_git_only_build_triggers"):
        return prepare_cve_branch(workspace_path, None, CVE_ID,
                                  protected_paths=protected,
                                  recipe='python3-setuptools')


def test_collect_fix_commit_paths_reads_fix_commits(workspace: Path) -> None:
    fix = _git(workspace, 'rev-parse', 'fix')

    assert collect_fix_commit_paths(workspace, [fix]) == {'pkg.py'}
    assert collect_fix_commit_paths(
        workspace, None, [{'commits': [fix]}]) == {'pkg.py'}
    assert collect_fix_commit_paths(workspace, ['not-a-hash', 'f' * 40]) == set()


def test_partial_replay_keeps_source_paths(workspace: Path) -> None:
    """The conflicted packaging file is dropped; the source change survives."""
    checkout_ok, skipped = _prepare(workspace, {'pkg.py'})

    assert checkout_ok is True
    assert skipped == []
    # The function the CVE fix targets now matches the devtool branch.
    assert (workspace / 'pkg.py').read_text() == PKG_MODERNIZED
    assert _git(workspace, 'rev-parse', f'{CVE_ID}:pkg.py') == \
        _git(workspace, 'rev-parse', 'devtool:pkg.py')
    # Only the packaging file was given up, and it is reported.
    assert (workspace / 'setup.cfg').read_text() == CFG_UPSTREAM
    report = read_prep_report(workspace, 'python3-setuptools')
    assert report is not None
    assert report['dropped_paths'] == ['setup.cfg']
    assert len(report['partial']) == 1
    assert report['skipped'] == []
    # No cherry-pick left in progress, nothing unmerged.
    assert not (workspace / '.git' / 'CHERRY_PICK_HEAD').exists()
    assert _git(workspace, 'status', '--porcelain') == ''


def test_protected_path_conflict_aborts_before_any_build(workspace: Path) -> None:
    """A conflict in a file the fix touches fails fast with exit 17."""
    with pytest.raises(PrepBaseMismatchError) as excinfo:
        _prepare(workspace, {'setup.cfg'})

    assert excinfo.value.exit_code == EXIT_PREP_BASE_MISMATCH
    assert 'PREP_BASE_MISMATCH' in str(excinfo.value)
    assert 'setup.cfg' in str(excinfo.value)
    # The workspace is left clean, not mid-cherry-pick.
    assert not (workspace / '.git' / 'CHERRY_PICK_HEAD').exists()
    assert _git(workspace, 'status', '--porcelain') == ''
    report = read_prep_report(workspace, 'python3-setuptools')
    assert report is not None
    assert report['failure_code'] == 'PREP_BASE_MISMATCH'


def test_protected_basename_match_aborts(workspace: Path) -> None:
    """Layout differences still count: basenames are matched too."""
    with pytest.raises(PrepBaseMismatchError):
        _prepare(workspace, {'python/setup.cfg'})


def test_transfer_succeeds_after_partial_replay(workspace: Path) -> None:
    """End to end: the fix now anchors on the devtool branch.

    This is the CVE-2025-47273 regression — with the recipe patch dropped
    wholesale the same transfer fails with TRANSFER_CONTEXT_MISMATCH (see
    :func:`test_transfer_fails_when_recipe_patch_missing`).
    """
    _prepare(workspace, {'pkg.py'})
    fix = _git(workspace, 'rev-parse', 'fix')
    _git(workspace, 'cherry-pick', fix)
    cve_commit = _git(workspace, 'rev-parse', 'HEAD')

    _git(workspace, 'checkout', '-q', '-f', 'devtool')
    manifest = transfer_commits(workspace, [cve_commit], 'python3-setuptools',
                                CVE_ID)

    assert manifest.verification == 'verified'
    assert manifest.final_changed_paths == ('pkg.py',)
    assert (workspace / 'pkg.py').read_text() == PKG_FIXED


def test_transfer_fails_when_recipe_patch_missing(workspace: Path) -> None:
    """Baseline: the old wholesale skip leaves an untransferable base."""
    # Simulate the previous behaviour: the recipe patch was dropped entirely,
    # so the fix is adapted to the release signature and dispatch.
    _git(workspace, 'tag', '-f', 'original-version')
    (workspace / 'pkg.py').write_text(PKG_ADAPTED_TO_RELEASE)
    _git(workspace, 'add', '-A')
    _git(workspace, 'commit', '-m', 'ensure target stays in tmp (adapted)')
    cve_commit = _git(workspace, 'rev-parse', 'HEAD')

    _git(workspace, 'checkout', '-q', '-f', 'devtool')
    with pytest.raises(TransferError) as excinfo:
        transfer_commits(workspace, [cve_commit], 'python3-setuptools', CVE_ID)

    assert 'TRANSFER_CONTEXT_MISMATCH' in str(excinfo.value)
