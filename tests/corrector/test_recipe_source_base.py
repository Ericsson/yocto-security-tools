"""Regression test: a stable-branch recipe's CVE branch starts at its own source.

Models the binutils ``Pre-patch build failed`` rows.  The recipe builds from a
SRCREV on the 2.42 stable branch, some commits past the release tag (the
branch regenerates ``configure``), and its libtool patch is written against
that regenerated file.  Replayed onto the bare release tag the patch conflicts
in ``configure``, the conflicted path is dropped, and the build stops with
"libtool: Version mismatch error".  The CVE branch must start at
``devtool-base`` instead; a tarball recipe, whose ``devtool-base`` shares no
history with the upstream tag, keeps starting at the tag.
"""
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from cve_corrector.workspace import prepare_cve_branch, read_prep_report

CVE_ID = "CVE-2025-1176"
RECIPE = "binutils"


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(['git', *args], cwd=repo, check=True,
                            capture_output=True, text=True)
    return result.stdout.strip()


def _is_ancestor(repo: Path, ancestor: str, descendant: str) -> bool:
    return subprocess.run(['git', 'merge-base', '--is-ancestor', ancestor, descendant],
                          cwd=repo, check=False).returncode == 0


def _commit(repo: Path, files: dict[str, str], message: str) -> str:
    for name, content in files.items():
        (repo / name).write_text(content)
    _git(repo, 'add', '-A')
    _git(repo, 'commit', '-q', '-m', message)
    return _git(repo, 'rev-parse', 'HEAD')


def _init(path: Path) -> Path:
    path.mkdir()
    _git(path, 'init', '-q', '-b', 'master')
    _git(path, 'config', 'user.email', 'test@example.com')
    _git(path, 'config', 'user.name', 'Test')
    _git(path, 'config', 'commit.gpgsign', 'false')
    return path


@pytest.fixture
def stable_workspace(tmp_path: Path) -> Path:
    """Workspace whose SRCREV is past the release tag, with a conflicting patch."""
    repo = _init(tmp_path / RECIPE)
    _commit(repo, {'configure': 'libtool 2.2\n', 'ld.c': 'int ld(void) { return 0; }\n'},
            'release 2.42')
    _git(repo, 'tag', 'binutils-2_42')
    _commit(repo, {'configure': 'libtool 2.4 regenerated\n'},
            'Update version number and regenerate configure files')
    _git(repo, 'tag', 'devtool-base')
    _git(repo, 'checkout', '-q', '-b', 'devtool')
    _commit(repo, {'configure': 'libtool 2.4 regenerated, patched\n'}, 'Use libtool 2.4')
    _git(repo, 'tag', 'devtool-patched')
    return repo


@pytest.fixture
def tarball_workspace(tmp_path: Path) -> Path:
    """Workspace whose devtool-base shares no history with the upstream tag."""
    repo = _init(tmp_path / 'tarball')
    _commit(repo, {'lib.c': 'int lib(void) { return 1; }\n'}, 'upstream 1.0')
    _git(repo, 'tag', 'v1.0')
    _git(repo, 'checkout', '-q', '--orphan', 'init')
    _git(repo, 'rm', '-rfq', '--cached', '.')
    _commit(repo, {'lib.c': 'int lib(void) { return 1; }\n'}, 'initial commit')
    _git(repo, 'tag', 'devtool-base')
    _git(repo, 'checkout', '-q', '-b', 'devtool')
    _commit(repo, {'build.txt': 'cross\n'}, 'recipe patch: build tweak')
    return repo


def _prepare(repo: Path, version: str, protected: set[str]) -> tuple[bool, list[str]]:
    with patch("cve_corrector.workspace._init_submodules"), \
            patch("cve_corrector.workspace.copy_missing_files_from_devtool"), \
            patch("cve_corrector.workspace.remove_git_only_build_triggers"):
        return prepare_cve_branch(repo, version, CVE_ID, protected_paths=protected,
                                  recipe=RECIPE)


def test_the_cve_branch_starts_at_the_recipe_source(stable_workspace: Path) -> None:
    checkout_ok, skipped = _prepare(stable_workspace, '2.42', {'ld.c'})

    assert checkout_ok is True
    assert skipped == []
    report = read_prep_report(stable_workspace, RECIPE)
    assert report is not None
    # The libtool patch applies whole: nothing is dropped from it.
    assert report['partial'] == []
    assert report['dropped_paths'] == []
    assert report['applied'] == [_git(stable_workspace, 'rev-parse', 'devtool-patched')[:12]]
    assert (stable_workspace / 'configure').read_text() == 'libtool 2.4 regenerated, patched\n'
    assert _git(stable_workspace, 'branch', '--show-current') == CVE_ID
    # The branch carries the stable-branch commit past the tag.
    assert _is_ancestor(stable_workspace, 'devtool-base', 'HEAD')


def test_a_tarball_recipe_still_starts_at_the_upstream_tag(tarball_workspace: Path) -> None:
    checkout_ok, _ = _prepare(tarball_workspace, '1.0', {'lib.c'})

    assert checkout_ok is True
    # devtool-base is an unrelated root commit: the branch stays on the tag's history.
    assert _is_ancestor(tarball_workspace, 'v1.0', 'HEAD')
    assert (tarball_workspace / 'build.txt').read_text() == 'cross\n'


def test_an_existing_cve_branch_is_not_moved(stable_workspace: Path) -> None:
    _git(stable_workspace, 'checkout', '-q', '-b', CVE_ID, 'binutils-2_42')
    marker = _commit(stable_workspace, {'ld.c': 'int ld(void) { return 7; }\n'}, 'earlier work')
    _git(stable_workspace, 'checkout', '-q', 'devtool')

    _prepare(stable_workspace, '2.42', {'ld.c'})

    assert _is_ancestor(stable_workspace, marker, 'HEAD')
    assert not _is_ancestor(stable_workspace, 'devtool-base', 'HEAD')


def test_an_existing_branch_at_the_bare_tag_is_not_moved_either(stable_workspace: Path) -> None:
    _git(stable_workspace, 'checkout', '-q', '-b', CVE_ID, 'binutils-2_42')
    _git(stable_workspace, 'checkout', '-q', 'devtool')

    _prepare(stable_workspace, '2.42', {'ld.c'})

    assert not _is_ancestor(stable_workspace, 'devtool-base', 'HEAD')


def test_a_base_equal_to_the_tag_is_left_alone(tmp_path: Path, caplog) -> None:
    repo = _init(tmp_path / RECIPE)
    _commit(repo, {'ld.c': 'int ld(void) { return 0; }\n'}, 'release')
    _git(repo, 'tag', 'v1.0')
    _git(repo, 'tag', 'devtool-base')
    _git(repo, 'checkout', '-q', '-b', 'devtool')
    _commit(repo, {'build.txt': 'cross\n'}, 'recipe patch')
    head_before = _git(repo, 'rev-parse', 'v1.0')

    with caplog.at_level('INFO', logger='cve_corrector'):
        _prepare(repo, '1.0', {'ld.c'})

    assert _git(repo, 'rev-parse', 'HEAD~1') == head_before
    assert 'past the release tag' not in caplog.text
