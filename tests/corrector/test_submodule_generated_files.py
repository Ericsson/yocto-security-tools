# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Generated files that a release tarball ships inside a vendored submodule.

python3-aiohttp's tarball contains ``vendor/llhttp/build/llhttp.h``: a file
generated from the llhttp sources, never committed to llhttp's own history.
After the corrector checks out the upstream tag and populates the submodule
from its pinned commit, that directory is missing and ``do_compile`` dies on
``fatal error: ../vendor/llhttp/build/llhttp.h: No such file or directory``,
which the run reports as a pre-existing build failure.

``copy_missing_files_from_devtool`` deliberately skips submodule paths (the
superproject must not track regular files under a gitlink), so nothing filled
the gap. The files must instead land inside the checked-out submodule, as
untracked content that git status ignores, so the tree stays clean.
"""
import os
import stat
import subprocess
from pathlib import Path

import pytest

from cve_corrector.git_ops import copy_missing_files_from_devtool

_SUB = 'vendor/llhttp'
_HEADER = '#define LLHTTP_VERSION 9\n'


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ['git', '-c', 'protocol.file.allow=always', *args], cwd=repo,
        check=True, capture_output=True, text=True)
    return result.stdout.strip()


def _init(repo: Path) -> None:
    repo.mkdir(parents=True)
    _git(repo, 'init', '-q', '-b', 'main')
    for key, value in (('user.email', 't@t.com'), ('user.name', 'T'),
                       ('commit.gpgsign', 'false')):
        _git(repo, 'config', key, value)


def _write(root: Path, rel: str, text: str, mode: int | None = None) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    if mode is not None:
        path.chmod(mode)


def _build_workspace(tmp_path: Path, escape_target: Path | None = None,
                     extra_files: dict[str, str] | None = None,
                     linked_dir: Path | None = None) -> Path:
    """Upstream tag with a submodule, plus a tarball-style ``devtool`` branch.

    The ``devtool`` branch holds the submodule's files as regular files and,
    in addition, generated ``build/`` output the submodule's history lacks.
    The returned workspace is on a CVE branch off the tag with the submodule
    initialised, as ``prepare_cve_branch`` leaves it.
    """
    sub = tmp_path / 'llhttp-upstream'
    _init(sub)
    _write(sub, 'src/llhttp.c', 'int parse(void) { return 0; }\n')
    _git(sub, 'add', '-A')
    _git(sub, 'commit', '-q', '-m', 'llhttp sources')

    repo = tmp_path / 'aiohttp'
    _init(repo)
    _write(repo, 'aiohttp/parser.c', '#include "../vendor/llhttp/build/llhttp.h"\n')
    _git(repo, 'add', '-A')
    _git(repo, 'commit', '-q', '-m', 'aiohttp')
    _git(repo, 'submodule', 'add', str(sub), _SUB)
    _git(repo, 'commit', '-q', '-m', 'add llhttp')
    _git(repo, 'tag', 'v3.9.5')

    # Tarball import: submodule files as plain files, plus generated output.
    _git(repo, 'checkout', '-q', '--orphan', 'devtool')
    _git(repo, 'rm', '-q', '-rf', '--cached', '.')
    subprocess.run(['rm', '-rf', str(repo / _SUB)], check=True)
    _write(repo, 'aiohttp/parser.c', '#include "../vendor/llhttp/build/llhttp.h"\n')
    # Same name as a tracked submodule file, different content: must not win.
    _write(repo, f'{_SUB}/src/llhttp.c', 'int parse(void) { return 42; }\n')
    _write(repo, f'{_SUB}/build/llhttp.h', _HEADER)
    _write(repo, f'{_SUB}/build/c/llhttp.c', 'int generated(void);\n')
    _write(repo, f'{_SUB}/build/gen.sh', '#!/bin/sh\n', mode=0o755)
    if escape_target is not None:
        os.symlink(escape_target, repo / _SUB / 'build' / 'escape')
    for rel, text in (extra_files or {}).items():
        _write(repo, f'{_SUB}/{rel}', text)
    _git(repo, 'add', '-A')
    _git(repo, 'commit', '-q', '-m', 'tarball')

    _git(repo, 'checkout', '-q', '-f', '-b', 'CVE-2026-00001', 'v3.9.5')
    _git(repo, 'submodule', 'update', '--init', '--recursive')
    return repo


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    return _build_workspace(tmp_path)


def test_generated_submodule_files_are_copied_into_the_checkout(workspace: Path) -> None:
    assert not (workspace / _SUB / 'build').exists()

    copy_missing_files_from_devtool(workspace)

    assert (workspace / _SUB / 'build' / 'llhttp.h').read_text() == _HEADER
    assert (workspace / _SUB / 'build' / 'c' / 'llhttp.c').exists()
    mode = (workspace / _SUB / 'build' / 'gen.sh').stat().st_mode
    assert mode & stat.S_IXUSR


def test_worktree_stays_clean_after_the_copy(workspace: Path) -> None:
    """A dirty superproject would block every later cherry-pick."""
    copy_missing_files_from_devtool(workspace)

    assert _git(workspace, 'status', '--porcelain') == ''
    assert _git(workspace / _SUB, 'status', '--porcelain') == ''
    # The gitlink recorded by the tag is untouched.
    assert _git(workspace, 'diff', '--stat', 'v3.9.5') == ''


def test_tracked_submodule_files_are_not_overwritten(workspace: Path) -> None:
    copy_missing_files_from_devtool(workspace)

    pinned = (workspace / _SUB / 'src' / 'llhttp.c').read_text()
    assert pinned == 'int parse(void) { return 0; }\n'


def test_second_call_changes_nothing(workspace: Path) -> None:
    copy_missing_files_from_devtool(workspace)
    exclude = Path(_git(workspace / _SUB, 'rev-parse', '--path-format=absolute',
                        '--git-path', 'info/exclude'))
    first = exclude.read_text()

    copy_missing_files_from_devtool(workspace)

    assert exclude.read_text() == first
    assert _git(workspace, 'status', '--porcelain') == ''


def test_copy_is_reapplied_after_a_clean(workspace: Path) -> None:
    """``_clean_and_reset_sstate`` cleans, then calls the copy again."""
    copy_missing_files_from_devtool(workspace)
    _git(workspace / _SUB, 'clean', '-fdx', '-q')
    assert not (workspace / _SUB / 'build').exists()

    copy_missing_files_from_devtool(workspace)

    assert (workspace / _SUB / 'build' / 'llhttp.h').read_text() == _HEADER
    assert _git(workspace, 'status', '--porcelain') == ''


def test_uninitialised_submodule_directory_is_left_alone(workspace: Path) -> None:
    """If the update failed, the path is not a repository: copy nothing there.

    Files written under an empty gitlink directory would be untracked content
    of the superproject and make ``git add -A`` fail.
    """
    _git(workspace, 'submodule', 'deinit', '-f', _SUB)
    assert not (workspace / _SUB / '.git').exists()

    copy_missing_files_from_devtool(workspace)

    assert not (workspace / _SUB / 'build').exists()


def test_symlinks_in_the_tarball_are_not_recreated(tmp_path: Path) -> None:
    outside = tmp_path / 'outside'
    outside.mkdir()
    workspace = _build_workspace(tmp_path, escape_target=outside)

    copy_missing_files_from_devtool(workspace)

    assert not os.path.lexists(workspace / _SUB / 'build' / 'escape')
    assert list(outside.iterdir()) == []
    assert (workspace / _SUB / 'build' / 'llhttp.h').exists()


def test_glob_characters_in_names_are_copied_and_excluded_literally(
        tmp_path: Path) -> None:
    """Names that look like patterns must not hide unrelated untracked files."""
    workspace = _build_workspace(tmp_path, extra_files={
        'build/gen[1].h': 'a\n', 'build/what?.h': 'b\n', 'build/star*.h': 'c\n',
        'build/#hash.h': 'd\n', 'build/!bang.h': 'e\n'})

    copy_missing_files_from_devtool(workspace)

    for name in ('gen[1].h', 'what?.h', 'star*.h', '#hash.h', '!bang.h'):
        assert (workspace / _SUB / 'build' / name).exists(), name
    assert _git(workspace, 'status', '--porcelain') == ''
    # A later, unrelated file that an unescaped ``star*.h`` / ``gen[1].h`` /
    # ``what?.h`` pattern would swallow stays visible to git.
    for name in ('starfish.h', 'gen1.h', 'whatx.h'):
        (workspace / _SUB / 'build' / name).write_text('x\n')
    untracked = _git(workspace / _SUB, 'status', '--porcelain',
                     '--untracked-files=all').splitlines()
    assert sorted(untracked) == [
        '?? build/gen1.h', '?? build/starfish.h', '?? build/whatx.h']


def test_symlinked_parent_directory_cannot_redirect_the_copy(tmp_path: Path) -> None:
    """A pre-existing symlink in the checkout must not carry files outside it."""
    workspace = _build_workspace(tmp_path)
    outside = tmp_path / 'outside'
    outside.mkdir()
    (workspace / _SUB / 'build').mkdir()
    os.symlink(outside, workspace / _SUB / 'build' / 'c')

    copy_missing_files_from_devtool(workspace)

    assert list(outside.iterdir()) == []
    assert not (outside / 'llhttp.c').exists()
    assert (workspace / _SUB / 'build' / 'llhttp.h').exists()
