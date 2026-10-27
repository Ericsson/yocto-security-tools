# SPDX-License-Identifier: MIT
"""fetch_mirrors.sh must leave no partial-clone mirror behind.

A --filter=tree:0 mirror cannot serve a fetch (upload-pack does not lazily
fetch for a client), which made the corrector fail on libpam without ever
reaching the AI. The script cloned complete mirrors but left an existing
partial one as it was.
"""
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).with_name('fetch_mirrors.sh')


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(['git', *args], cwd=repo, check=check, capture_output=True, text=True)


def _sh(mirror_dir: Path, snippet: str) -> subprocess.CompletedProcess:
    """Run *snippet* with the script's functions defined (the script is sourced, not run)."""
    return subprocess.run(['bash', '-c', f'source "{SCRIPT}"; {snippet}'], check=False,
                          capture_output=True, text=True, env={'MIRROR_DIR': str(mirror_dir),
                                                               'PATH': '/usr/bin:/bin'})


@pytest.fixture
def mirrors(tmp_path: Path) -> dict[str, Path]:
    up = tmp_path / 'up'
    (up / 'd').mkdir(parents=True)
    _git(up, 'init', '-q', '-b', 'main')
    for key, val in (('user.email', 't@e.x'), ('user.name', 'T'), ('uploadpack.allowFilter', 'true')):
        _git(up, 'config', key, val)
    (up / 'd' / 'f').write_text('1\n')
    _git(up, 'add', '-A')
    _git(up, 'commit', '-q', '-m', 'one')
    _git(up, 'tag', 'v1')
    git_dir = tmp_path / 'git'
    git_dir.mkdir()
    url = f'file://{up}'
    _git(tmp_path, 'clone', '-q', '--bare', url, str(git_dir / 'complete'))
    _git(tmp_path, 'clone', '-q', '--bare', '--filter=tree:0', url, str(git_dir / 'partial'))
    # something new upstream after both clones
    (up / 'd' / 'f2').write_text('2\n')
    _git(up, 'add', '-A')
    _git(up, 'commit', '-q', '-m', 'two')
    _git(up, 'tag', 'v2')
    # a tag on a commit no branch reaches: only the explicit tag refspec brings it
    _git(up, 'checkout', '-q', '--detach')
    (up / 'd' / 'f3').write_text('3\n')
    _git(up, 'add', '-A')
    _git(up, 'commit', '-q', '-m', 'three')
    _git(up, 'tag', 'v3')
    _git(up, 'checkout', '-q', 'main')
    return {'dir': git_dir, 'complete': git_dir / 'complete', 'partial': git_dir / 'partial',
            'scratch': tmp_path / 'scratch'}


def _can_fetch_from(mirror: Path, scratch: Path) -> bool:
    scratch.mkdir(exist_ok=True)
    _git(scratch, 'init', '-q')
    return _git(scratch, 'fetch', '-q', '--tags', str(mirror), check=False).returncode == 0


def test_a_partial_mirror_is_detected_and_a_complete_one_is_not(mirrors):
    assert _sh(mirrors['dir'], f'is_partial_mirror "{mirrors["partial"]}"').returncode == 0
    assert _sh(mirrors['dir'], f'is_partial_mirror "{mirrors["complete"]}"').returncode != 0


def test_a_partial_mirror_cannot_serve_a_fetch_before_the_conversion(mirrors):
    assert not _can_fetch_from(mirrors['partial'], mirrors['scratch'])


def test_make_mirror_full_turns_a_partial_mirror_into_one_that_serves_fetches(mirrors):
    result = _sh(mirrors['dir'], f'make_mirror_full "{mirrors["partial"]}"')
    assert result.returncode == 0, result.stderr

    assert _sh(mirrors['dir'], f'is_partial_mirror "{mirrors["partial"]}"').returncode != 0
    assert _can_fetch_from(mirrors['partial'], mirrors['scratch'])
    # nothing missing from any ref, and the tag created after the clone arrived
    missing = _git(mirrors['partial'], 'rev-list', '--objects', '--all', '--missing=print').stdout
    assert not [line for line in missing.splitlines() if line.startswith('?')]
    assert {'v2', 'v3'} <= set(_git(mirrors['partial'], 'tag').stdout.split())


def test_make_mirror_full_reports_failure_and_keeps_the_marker(mirrors):
    _git(mirrors['partial'], 'config', 'remote.origin.url', 'file:///nonexistent')
    result = _sh(mirrors['dir'], f'make_mirror_full "{mirrors["partial"]}"')
    assert result.returncode != 0
    assert _sh(mirrors['dir'], f'is_partial_mirror "{mirrors["partial"]}"').returncode == 0


def test_running_the_script_still_processes_the_mirrors(tmp_path):
    """Sourcing only defines the functions; executing the script must still run the loop."""
    stub = tmp_path / 'bin'
    stub.mkdir()
    (stub / 'git').write_text('#!/bin/bash\nexit 1\n')
    (stub / 'git').chmod(0o755)
    result = subprocess.run(['bash', str(SCRIPT)], check=False, capture_output=True, text=True,
                            env={'MIRROR_DIR': str(tmp_path / 'm'),
                                 'PATH': f'{stub}:/usr/bin:/bin'})
    assert 'Done: 0 succeeded' in result.stdout
    assert 'Cloning xz from' in result.stdout


def test_running_the_script_converts_an_existing_partial_mirror(tmp_path):
    stub = tmp_path / 'bin'
    stub.mkdir()
    (stub / 'git').write_text(
        '#!/bin/bash\n[[ "$*" == *"--get remote.origin.promisor"* ]] && echo true\nexit 1\n')
    (stub / 'git').chmod(0o755)
    (tmp_path / 'm' / 'xz').mkdir(parents=True)
    result = subprocess.run(['bash', str(SCRIPT)], check=False, capture_output=True, text=True,
                            env={'MIRROR_DIR': str(tmp_path / 'm'),
                                 'PATH': f'{stub}:/usr/bin:/bin'})
    assert 'Converting partial mirror xz to a complete one' in result.stdout
    assert 'Updating xz' not in result.stdout
