"""Regression test: recipe-patch replay must diff against ``devtool-base``.

Models the libssh / exiv2 / frr / luajit ``PREP_BASE_MISMATCH`` failures with
real git. For a git ``SRC_URI`` recipe, bitbake's unpack (``git clone -n -s``)
leaves a local ``master`` that is upstream's default branch, while devtool
tags ``devtool-base`` at the recipe's SRCREV. When the recipe tracks a stable
branch, ``master..devtool`` lists every stable-only upstream commit as a
"recipe patch"; replaying those onto the release tag conflicted in the file
the CVE fix touches and aborted preparation.
"""
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from cve_corrector.workspace import prepare_cve_branch, read_prep_report

CVE_ID = "CVE-2026-55351"
RECIPE = "libssh"


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(['git', *args], cwd=repo, check=True,
                            capture_output=True, text=True)
    return result.stdout.strip()


def _commit(repo: Path, files: dict[str, str], message: str) -> str:
    for name, content in files.items():
        (repo / name).write_text(content)
    _git(repo, 'add', '-A')
    _git(repo, 'commit', '-q', '-m', message)
    return _git(repo, 'rev-parse', 'HEAD')


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """Build a devtool workspace for a git recipe on a stable branch."""
    repo = tmp_path / RECIPE
    repo.mkdir()
    _git(repo, 'init', '-q', '-b', 'master')
    _git(repo, 'config', 'user.email', 'test@example.com')
    _git(repo, 'config', 'user.name', 'Test')
    _git(repo, 'config', 'commit.gpgsign', 'false')

    _commit(repo, {'pki.c': 'int key(void) { return 0; }\n'}, 'common root')
    # Upstream master moves on independently of the stable branch.
    _commit(repo, {'pki.c': 'int key(void) { return master(); }\n'},
            'master: rework key handling')

    # Stable branch: a backport the release carries, then the release tag
    # that is the recipe's SRCREV.
    _git(repo, 'checkout', '-q', '-b', 'stable', 'HEAD~1')
    _commit(repo, {'pki.c': 'int key(void) { return stable(); }\n'},
            'stable: backport key fix')
    _git(repo, 'tag', 'v1.0')

    # devtool: tag the unpacked source, branch, then the recipe's own patch.
    _git(repo, 'tag', 'devtool-base')
    _git(repo, 'checkout', '-q', '-b', 'devtool')
    _commit(repo, {'build.txt': 'cross\n'}, 'recipe patch: build tweak')
    _git(repo, 'tag', 'devtool-patched')

    # The corrector starts the CVE branch at the release tag.
    _git(repo, 'checkout', '-q', '-b', CVE_ID, 'v1.0')
    return repo


def test_replay_uses_devtool_base_not_upstream_master(workspace: Path) -> None:
    with patch("cve_corrector.workspace._init_submodules"), \
            patch("cve_corrector.workspace.copy_missing_files_from_devtool"), \
            patch("cve_corrector.workspace.remove_git_only_build_triggers"):
        checkout_ok, skipped = prepare_cve_branch(
            workspace, None, CVE_ID, protected_paths={'pki.c'}, recipe=RECIPE)

    assert checkout_ok is True
    assert skipped == []
    report = read_prep_report(workspace, RECIPE)
    assert report is not None
    assert report['base_branch'] == 'devtool-base'
    # Only the recipe's own patch is replayed; the stable backport (already
    # in v1.0) is not mistaken for one and cannot conflict in pki.c.
    recipe_patch = _git(workspace, 'rev-parse', 'devtool-patched')
    assert report['applied'] == [recipe_patch[:12]]
    assert (workspace / 'pki.c').read_text() == 'int key(void) { return stable(); }\n'
    assert (workspace / 'build.txt').read_text() == 'cross\n'
