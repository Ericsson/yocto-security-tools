# SPDX-License-Identifier: MIT
"""Regression tests for cherry_pick_to_devtool against a real git repository.

These tests build a miniature copy of a devtool workspace:

* ``main``          — upstream history with a version tag and the CVE series
* ``devtool-base``  — orphan "initial commit from upstream tarball"
* ``devtool``       — recipe patch commits on top of devtool-base
* ``<cve_id>``      — version tag + cherry-picked devtool commits
                      (tagged ``original-version``) + the CVE series

The layout matters: the devtool prep commits exist twice with different
hashes (once on ``devtool``, once on the CVE branch), which is what broke the
old commit-counting heuristic for multi-commit series.
"""
import subprocess
from pathlib import Path

import pytest

from cve_corrector.cherry_pick import cherry_pick_to_devtool, collect_cve_commits
from cve_corrector.state import WorkflowState

CVE_ID = "CVE-2026-25210"


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(['git', *args], cwd=repo, check=True,
                            capture_output=True, text=True)
    return result.stdout.strip()


def _commit(repo: Path, path: str, content: str, message: str) -> str:
    (repo / path).write_text(content)
    _git(repo, 'add', '-A')
    _git(repo, 'commit', '-m', message)
    return _git(repo, 'rev-parse', 'HEAD')


def _subjects(repo: Path, rev_range: str) -> list[str]:
    log = _git(repo, 'log', '--reverse', '--format=%s', rev_range)
    return log.splitlines() if log else []


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """Build a devtool-like workspace with a 3-commit CVE series."""
    repo = tmp_path / "expat"
    repo.mkdir()
    _git(repo, 'init', '-q', '-b', 'main')
    _git(repo, 'config', 'user.email', 'test@example.com')
    _git(repo, 'config', 'user.name', 'Test')
    _git(repo, 'config', 'commit.gpgsign', 'false')

    # Upstream release: a build-system marker keeps get_repo_subdir() at None.
    _commit(repo, 'Makefile', 'all:\n', 'build: add Makefile')
    _commit(repo, 'xmlparse.c', 'line1\nline2\n', 'release 2.6.4')
    _git(repo, 'tag', 'R_2_6_4')

    # Upstream moves on, then lands the 3-commit CVE series.
    _commit(repo, 'xmlparse.c', 'line1\nline2\nunrelated\n', 'upstream churn')
    _commit(repo, 'tag.c', 'fix1\n', 'lib: add bounds check')
    _commit(repo, 'tag.c', 'fix1\nfix2\n', 'lib: refactor helper')
    _commit(repo, 'tag.c', 'fix1\nfix2\nfix3\n',
            'lib: Introduce an integer overflow check for tag buffer')
    _git(repo, 'branch', 'series')

    # devtool workspace: orphan tarball import + recipe patch commits.
    _git(repo, 'checkout', '-q', '--orphan', 'devtool-base')
    _git(repo, 'rm', '-q', '-rf', '.')
    _git(repo, 'checkout', 'R_2_6_4', '--', '.')
    _git(repo, 'commit', '-m', 'Initial commit from upstream tarball')
    _git(repo, 'checkout', '-q', '-b', 'devtool')
    for idx in (1, 2):
        _commit(repo, f'recipe-patch-{idx}.txt', f'{idx}\n', f'recipe patch {idx}')

    # CVE branch: version tag + cherry-picked devtool commits + CVE series.
    _git(repo, 'checkout', '-q', '-b', CVE_ID, 'R_2_6_4')
    prep = _git(repo, 'rev-list', '--reverse', 'devtool-base..devtool').split()
    _git(repo, 'cherry-pick', *prep)
    _git(repo, 'tag', '-f', 'original-version')
    fix_commits = _git(repo, 'rev-list', '--reverse', 'series~3..series').split()
    _git(repo, 'cherry-pick', *fix_commits)
    return repo


def _state(workspace_path: Path) -> WorkflowState:
    return WorkflowState(
        workspace_path=workspace_path, cve_id=CVE_ID, recipe='expat',
        commit_hash='deadbeef', hash_details=[], meta_layer=None,
        skip_build=True, skip_ptest=True)


def test_collect_cve_commits_returns_full_series(workspace: Path) -> None:
    """All 3 CVE commits are collected, oldest first, without devtool prep."""
    commits = collect_cve_commits(_state(workspace))

    expected = _git(workspace, 'rev-list', '--reverse',
                    f'original-version..{CVE_ID}').split()
    assert commits == expected
    assert len(commits) == 3


def test_transfers_whole_series_to_devtool(workspace: Path) -> None:
    """The complete series lands on devtool (regression: only the tip was sent).

    The old implementation derived the commit count from
    ``original-version..CVE`` minus ``original-version..devtool``, which
    collapses to 1 as soon as the devtool branch carries recipe patches — so
    format-patch emitted only the tip commit and git am could never apply it.
    """
    devtool_before = _git(workspace, 'rev-parse', 'devtool')

    cherry_pick_to_devtool(_state(workspace))

    assert _git(workspace, 'rev-parse', '--abbrev-ref', 'HEAD') == 'devtool'
    assert _subjects(workspace, f'{devtool_before}..devtool') == [
        'lib: add bounds check',
        'lib: refactor helper',
        'lib: Introduce an integer overflow check for tag buffer',
    ]
    assert (workspace / 'tag.c').read_text() == 'fix1\nfix2\nfix3\n'


def test_skips_commits_already_on_devtool(workspace: Path) -> None:
    """Commits whose change is already on devtool are filtered by patch-id."""
    # Simulate a recipe that already carries the first commit of the series.
    _git(workspace, 'checkout', '-q', 'devtool')
    _commit(workspace, 'tag.c', 'fix1\n', 'recipe patch: lib: add bounds check')
    _git(workspace, 'checkout', '-q', CVE_ID)

    commits = collect_cve_commits(_state(workspace))

    assert len(commits) == 2
    subjects = [_git(workspace, 'log', '-1', '--format=%s', c) for c in commits]
    assert subjects == [
        'lib: refactor helper',
        'lib: Introduce an integer overflow check for tag buffer',
    ]
