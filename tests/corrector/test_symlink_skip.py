# SPDX-License-Identifier: MIT
"""Tests for symlink handling in copy_missing_files_from_devtool.

Reproduces the bug where recipes whose upstream tree tracks a directory
symlink (git mode 120000) get their symlink clobbered because:
1. Release tarballs dereference symlinks into real directories, so the
   devtool branch lists the symlink target's contents as regular files
   (e.g. tutorial/swift/swift-dep/Sources/*.swift).
2. copy_missing_files_from_devtool() copies those files out of devtool,
   overwriting the symlink with a real directory.
3. The resulting staged deletion + untracked directory leaves the working
   tree dirty and blocks every subsequent git cherry-pick.

The fix: skip any devtool file living under a path that HEAD tracks as a
symlink — the symlink already resolves to an in-tree path, so nothing is
actually missing.
"""
import subprocess
from pathlib import Path

import pytest

from cve_corrector.git_ops import copy_missing_files_from_devtool


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ['git', *args], cwd=repo, check=True,
        capture_output=True, text=True,
    )
    return result.stdout.strip()


def _init_repo(repo: Path) -> None:
    repo.mkdir()
    _git(repo, 'init', '-q', '-b', 'main')
    _git(repo, 'config', 'user.email', 'test@test.com')
    _git(repo, 'config', 'user.name', 'Test')
    _git(repo, 'config', 'commit.gpgsign', 'false')


@pytest.fixture
def workspace_with_symlink(tmp_path: Path) -> Path:
    """Create a repo whose HEAD tracks a directory symlink.

    Layout on HEAD (upstream git):
        src/real/a.swift
        tutorial/swift -> ../src/real   (symlink, mode 120000)

    Layout on devtool (tarball, symlink dereferenced into a real dir):
        src/real/a.swift
        tutorial/swift/a.swift          (regular file)
        Makefile                        (a genuinely-missing generated file)
    """
    repo = tmp_path / "repo"
    _init_repo(repo)

    # Upstream HEAD: real dir + a symlink pointing at it.
    (repo / 'src' / 'real').mkdir(parents=True)
    (repo / 'src' / 'real' / 'a.swift').write_text('let x = 1\n')
    (repo / 'tutorial').mkdir()
    (repo / 'tutorial' / 'swift').symlink_to('../src/real')
    _git(repo, 'add', '-A')
    _git(repo, 'commit', '-m', 'upstream with symlink')
    _git(repo, 'tag', 'v1.0')

    # Build the devtool branch as an orphan mimicking a dereferenced tarball.
    _git(repo, 'checkout', '-q', '--orphan', 'devtool')
    _git(repo, 'rm', '-q', '-rf', '.')
    # Remove any leftover working-tree entries from the symlink checkout.
    subprocess.run(['rm', '-rf', 'tutorial', 'src'], cwd=repo, check=True)

    (repo / 'src' / 'real').mkdir(parents=True)
    (repo / 'src' / 'real' / 'a.swift').write_text('let x = 1\n')
    # Symlink target dereferenced into a real directory of regular files.
    (repo / 'tutorial' / 'swift').mkdir(parents=True)
    (repo / 'tutorial' / 'swift' / 'a.swift').write_text('let x = 1\n')
    # A genuinely-missing generated file that SHOULD be copied.
    (repo / 'Makefile').write_text('all:\n')
    _git(repo, 'add', '-A')
    _git(repo, 'commit', '-m', 'devtool tarball content')

    # Back to a CVE branch off the upstream tag (as prepare_cve_branch does).
    _git(repo, 'checkout', '-q', '-b', 'CVE-2026-00001', 'v1.0')
    return repo


def test_symlink_is_not_clobbered(workspace_with_symlink: Path) -> None:
    """copy_missing_files_from_devtool must not overwrite a HEAD symlink."""
    repo = workspace_with_symlink

    # Precondition: HEAD tracks tutorial/swift as a symlink (mode 120000).
    head_tree = _git(repo, 'ls-tree', '-r', 'HEAD')
    assert '120000' in head_tree
    assert 'tutorial/swift' in head_tree
    # And devtool lists the dereferenced contents as regular files.
    devtool_files = _git(repo, 'ls-tree', '-r', '--name-only', 'devtool')
    assert 'tutorial/swift/a.swift' in devtool_files

    copy_missing_files_from_devtool(repo)

    # The symlink must remain an intact symlink, not a real directory.
    swift_path = repo / 'tutorial' / 'swift'
    assert swift_path.is_symlink(), "symlink was clobbered by a real directory"

    # Working tree must stay clean under the symlink path — no staged deletion,
    # no untracked directory that would block subsequent cherry-picks.
    status = _git(repo, 'status', '--porcelain')
    dirty_under_symlink = [
        line for line in status.splitlines() if 'tutorial/swift' in line
    ]
    assert not dirty_under_symlink, (
        f"symlink path should stay clean, got:\n{chr(10).join(dirty_under_symlink)}"
    )


def test_genuinely_missing_files_still_copied(
    workspace_with_symlink: Path,
) -> None:
    """Files not under a symlink (e.g. generated Makefile) are still copied."""
    repo = workspace_with_symlink

    copy_missing_files_from_devtool(repo)

    makefile = repo / 'Makefile'
    assert makefile.exists(), "genuinely-missing file should be copied"
    assert makefile.read_text() == 'all:\n'
