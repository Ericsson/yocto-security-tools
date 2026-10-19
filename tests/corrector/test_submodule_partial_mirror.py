# SPDX-License-Identifier: MIT
"""Regression test: a partial-clone mirror must not serve a submodule.

Models the gnutls ``SKIP_BUILD_PREEXISTING`` failure with real git. The
``devel/nettle`` submodule mirror was a ``--filter=tree:0`` partial clone
missing trees of the pinned commit. ``upload-pack`` does not lazily fetch for
a client, so the submodule clone came out broken (``Could not read <tree>``)
and devtool's ``git add -A`` then failed while parsing the recipe, which the
corrector reported as a pre-existing build failure.
"""
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from cve_corrector.workspace import _init_submodules, _mirror_serves_commit


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(['git', *args], cwd=repo, check=True,
                            capture_output=True, text=True)
    return result.stdout.strip()


@pytest.fixture
def upstream(tmp_path: Path) -> tuple[Path, str]:
    """An upstream repo with a nested tree, allowing filtered clones."""
    repo = tmp_path / "nettle-upstream"
    (repo / "src" / "lib").mkdir(parents=True)
    _git(repo, 'init', '-q', '-b', 'master')
    _git(repo, 'config', 'user.email', 't@example.com')
    _git(repo, 'config', 'user.name', 'T')
    _git(repo, 'config', 'uploadpack.allowFilter', 'true')
    (repo / "src" / "lib" / "aes.c").write_text("int aes;\n")
    _git(repo, 'add', '-A')
    _git(repo, 'commit', '-q', '-m', 'one')
    (repo / "src" / "lib" / "aes.c").write_text("int aes2;\n")
    _git(repo, 'commit', '-q', '-am', 'two')
    return repo, _git(repo, 'rev-parse', 'HEAD~1')


def test_partial_clone_mirror_is_reported_incomplete(tmp_path, upstream):
    repo, pinned = upstream
    partial = tmp_path / "partial"
    _git(tmp_path, 'clone', '-q', '--bare', '--filter=tree:0',
         f'file://{repo}', str(partial))
    full = tmp_path / "full"
    _git(tmp_path, 'clone', '-q', '--bare', str(repo), str(full))

    assert _mirror_serves_commit(partial, pinned) is False
    assert _mirror_serves_commit(full, pinned) is True
    assert _mirror_serves_commit(full, 'f' * 40) is False


def test_init_submodules_skips_incomplete_mirror(tmp_path, upstream):
    repo, pinned = upstream
    mirror_dir = tmp_path / "mirrors"
    mirror_dir.mkdir()
    _git(tmp_path, 'clone', '-q', '--bare', '--filter=tree:0',
         f'file://{repo}', str(mirror_dir / 'nettle'))

    # Superproject pinning the submodule at the commit the mirror lacks.
    workspace = tmp_path / "gnutls"
    workspace.mkdir()
    _git(workspace, 'init', '-q', '-b', 'main')
    _git(workspace, 'config', 'user.email', 't@example.com')
    _git(workspace, 'config', 'user.name', 'T')
    url = 'https://gitlab.com/gnutls/nettle.git'
    (workspace / '.gitmodules').write_text(
        f'[submodule "devel/nettle"]\n\tpath = devel/nettle\n\turl = {url}\n')
    _git(workspace, 'update-index', '--add', '--cacheinfo',
         f'160000,{pinned},devel/nettle')
    _git(workspace, 'add', '.gitmodules')
    _git(workspace, 'commit', '-q', '-m', 'pin nettle')

    with patch('cve_corrector.workspace.run_cmd', return_value=0) as mock_cmd:
        _init_submodules(workspace, mirror_dir=mirror_dir)

    # The incomplete mirror is not substituted: the .gitmodules URL stays.
    config_calls = [c[0][0] for c in mock_cmd.call_args_list
                    if c[0][0][:2] == ['git', 'config']]
    assert config_calls == []
    update = [c[0][0] for c in mock_cmd.call_args_list if 'update' in c[0][0]][0]
    assert 'protocol.file.allow=always' not in update
