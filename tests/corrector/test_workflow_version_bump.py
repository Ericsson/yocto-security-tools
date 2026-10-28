# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""initialize_cve_workflow must not trust version-bump commits as CVE fixes.

Regression for CVE-2026-78135 (strongswan): OSV recorded the "Version bump to
6.1.0" release commit as the fix.  Blaming it found the 6.1.0rc1 bump, so a
vulnerable 5.9.14 recipe was marked not applicable via CVE_STATUS.
"""
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from cve_corrector.state import MetadataError
from cve_corrector.workflow import WorkflowConfig, initialize_cve_workflow


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(['git', *args], cwd=repo, check=True,
                          capture_output=True, text=True).stdout.strip()


def _commit(repo: Path, files: dict[str, str], message: str) -> str:
    for name, content in files.items():
        (repo / name).write_text(content)
        _git(repo, 'add', name)
    _git(repo, 'commit', '-m', message)
    return _git(repo, 'rev-parse', 'HEAD')


@pytest.fixture
def repo(tmp_path):
    """Vulnerable code since 5.9.7; 6.1.0 = real fix + version bump."""
    repo = tmp_path / 'ws'
    repo.mkdir()
    _git(repo, 'init')
    _git(repo, 'config', 'user.email', 'test@test.com')
    _git(repo, 'config', 'user.name', 'Test')
    _commit(repo, {'configure.ac': 'AC_INIT([5.9.7])\n',
                   'tm.c': 'a\nvulnerable\nb\n'}, 'Version bump to 5.9.7')
    _git(repo, 'tag', '5.9.7')
    _commit(repo, {'configure.ac': 'AC_INIT([6.1.0rc1])\n'},
            'Version bump to 6.1.0rc1')
    _git(repo, 'tag', '6.1.0rc1')
    fix = _commit(repo, {'tm.c': 'a\nfixed\nb\n'}, 'ikev2: reject early CHILD_SA')
    bump = _commit(repo, {'configure.ac': 'AC_INIT([6.1.0])\n'},
                   'Version bump to 6.1.0')
    _git(repo, 'tag', '6.1.0')
    _git(repo, 'checkout', '-q', '5.9.7')
    return repo, fix, bump


def _config():
    return WorkflowConfig(
        mirror_path=None, mirror_dir=None, meta_layer=None,
        skip_build=True, clean=False, skip_ptest=True, edit_mode=False)


def _run(repo, hashes):
    cve_data = {'CVE-2026-78135': {'name': 'strongswan', 'hashes': hashes,
                                   'hash_details': []}}
    with patch('cve_corrector.workflow.check_cve_status', return_value=None), \
         patch('cve_corrector.workflow.check_cve_patch_in_src_uri', return_value=None), \
         patch('cve_corrector.workflow.setup_devtool_workspace',
               return_value=(repo, '5.9.14')), \
         patch('cve_corrector.workflow.setup_upstream_remote', return_value=None), \
         patch('cve_corrector.workflow.prepare_cve_branch', return_value=(True, [])), \
         patch('cve_corrector.workflow.collect_fix_commit_paths', return_value=set()), \
         patch('cve_corrector.workflow.check_vulnerability_origin',
               side_effect=RuntimeError('reached origin check')) as origin:
        try:
            initialize_cve_workflow(cve_data, 'CVE-2026-78135', _config())
        except RuntimeError:
            pass
    return origin


def test_only_version_bump_fix_raises_metadata_error(repo):
    ws, _, bump = repo
    with pytest.raises(MetadataError, match='version bumps'):
        _run(ws, [bump])


def test_real_fix_alongside_bump_proceeds(repo):
    ws, fix, bump = repo
    origin = _run(ws, [bump, fix])
    origin.assert_called_once()
