# SPDX-License-Identifier: MIT
"""Regression test: tarball-shipped dangling ``.git`` files.

Models python3-aiohttp (``vendor/llhttp``) and syslog-ng
(``opentelemetry-proto``) with real git. Their release tarballs contain the
vendored submodule's ``.git`` *file* (``gitdir: ../../.git/modules/<name>``)
but not the ``.git/modules`` directory it points at. ``git checkout <tag>``
then dies with ``fatal: not a git repository``, the corrector silently stays
on the devtool HEAD, and devtool's ``git add -A`` fails the same way while
parsing the recipe, so the CVE was reported as a pre-existing build failure.
"""
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from cve_corrector.workspace import _remove_dangling_gitfiles, prepare_cve_branch

CVE_ID = "CVE-2026-60001"
GITFILE = "gitdir: ../../.git/modules/vendor/sub\n"


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ['git', '-c', 'protocol.file.allow=always', *args], cwd=repo,
        check=True, capture_output=True, text=True)
    return result.stdout.strip()


def _identity(repo: Path) -> None:
    _git(repo, 'config', 'user.email', 't@example.com')
    _git(repo, 'config', 'user.name', 'T')
    _git(repo, 'config', 'commit.gpgsign', 'false')


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """Devtool workspace from a tarball with a dangling vendored gitfile."""
    sub = tmp_path / "sub"
    sub.mkdir()
    _git(sub, 'init', '-q', '-b', 'main')
    _identity(sub)
    (sub / "f").write_text("x\n")
    _git(sub, 'add', 'f')
    _git(sub, 'commit', '-q', '-m', 's')
    sub_sha = _git(sub, 'rev-parse', 'HEAD')

    # Upstream: tag v1.0 carries vendor/sub as a real submodule.
    up = tmp_path / "up"
    up.mkdir()
    _git(up, 'init', '-q', '-b', 'main')
    _identity(up)
    (up / ".gitmodules").write_text(
        f'[submodule "vendor/sub"]\n\tpath = vendor/sub\n\turl = {sub}\n')
    (up / "a.c").write_text("int a;\n")
    _git(up, 'add', 'a.c', '.gitmodules')
    _git(up, 'update-index', '--add', '--cacheinfo',
         f'160000,{sub_sha},vendor/sub')
    _git(up, 'commit', '-q', '-m', 'one')
    _git(up, 'tag', 'v1.0')

    # Workspace: tarball content; the vendored dir has a dangling gitfile.
    ws = tmp_path / "ws"
    ws.mkdir()
    _git(ws, 'init', '-q', '-b', 'master')
    _identity(ws)
    (ws / "a.c").write_text("int a;\n")
    (ws / "vendor" / "sub").mkdir(parents=True)
    (ws / "vendor" / "sub" / "f").write_text("x\n")
    (ws / "vendor" / "sub" / ".git").write_text(GITFILE)
    _git(ws, 'add', '-A')
    _git(ws, 'commit', '-q', '-m', 'Initial commit from upstream')
    _git(ws, 'tag', 'devtool-base')
    _git(ws, 'branch', 'devtool')
    _git(ws, 'remote', 'add', 'upstream', str(up))
    _git(ws, 'fetch', '-q', 'upstream', '--tags')
    return ws


def test_dangling_gitfile_is_removed(workspace: Path) -> None:
    removed = _remove_dangling_gitfiles(workspace)

    assert removed == [str(Path("vendor") / "sub" / ".git")]
    assert not (workspace / "vendor" / "sub" / ".git").exists()
    assert (workspace / "vendor" / "sub" / "f").read_text() == "x\n"


def test_valid_gitfile_and_nested_repo_are_kept(workspace: Path) -> None:
    modules = workspace / ".git" / "modules" / "vendor" / "sub"
    modules.mkdir(parents=True)
    nested = workspace / "third_party" / "lib"
    nested.mkdir(parents=True)
    _git(nested, 'init', '-q')

    assert _remove_dangling_gitfiles(workspace) == []
    assert (workspace / "vendor" / "sub" / ".git").is_file()
    assert (nested / ".git").is_dir()
    assert (workspace / ".git").is_dir()


def test_prepare_cve_branch_reaches_the_release_tag(workspace: Path) -> None:
    """Without the cleanup the version checkout failed and HEAD stayed put."""
    devtool_head = _git(workspace, 'rev-parse', 'HEAD')

    with patch("cve_corrector.workspace.copy_missing_files_from_devtool"), \
            patch("cve_corrector.workspace.remove_git_only_build_triggers"):
        # tmp_path doubles as the mirror dir: it holds ``sub``, so the
        # submodule is cloned through the mirror override that also opts in
        # to the file transport, exactly as in a real run.
        checkout_ok, _skipped = prepare_cve_branch(
            workspace, "1.0", CVE_ID, recipe="python3-aiohttp",
            mirror_dir=workspace.parent)

    assert checkout_ok is True
    assert _git(workspace, 'branch', '--show-current') == CVE_ID
    assert _git(workspace, 'rev-parse', 'HEAD') == _git(workspace, 'rev-parse', 'v1.0^{commit}')
    assert _git(workspace, 'rev-parse', 'HEAD') != devtool_head
    # The submodule update recreated a valid gitfile/gitdir for the vendored dir.
    assert _git(workspace / 'vendor' / 'sub', 'rev-parse', '--git-dir')
