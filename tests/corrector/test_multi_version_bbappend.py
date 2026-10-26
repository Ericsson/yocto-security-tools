# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""--bbappend into a layer that ships the recipe in several versions.

A layer can carry e.g. ``liburcu_0.13.4.bb``, ``liburcu_0.15.7.bb``
and a ``liburcu_%.bbappend`` for every version. A fix for the selected
version must land in that version's own bbappend and ``${BP}`` patch
directory — never in the wildcard bbappend, which would apply it to every
other version as well.
"""
import re
import subprocess
from pathlib import Path

import pytest

import cve_corrector.recipe_ops as recipe_ops
from cve_corrector.meta_layer import write_cve_status
from cve_corrector.recipe_ops import (
    _find_recipe_file,
    _split_src_uri_line,
    seed_versioned_bbappend,
    update_recipe_patch,
    versioned_bbappend,
)
from tests.helpers import git

WILDCARD_TEXT = 'BBCLASSEXTEND += "nativesdk"\n'


@pytest.fixture(autouse=True)
def _clear_selected_file_cache():
    recipe_ops._selected_recipe_file.cache_clear()
    yield
    recipe_ops._selected_recipe_file.cache_clear()


def _layer(tmp_path: Path, versions=('0.15.3', '0.15.7'), recipe='foo') -> Path:
    layer = tmp_path / 'meta-extras'
    (layer / 'conf').mkdir(parents=True)
    (layer / 'conf' / 'layer.conf').write_text('BBFILE_COLLECTIONS += "extras"\n')
    rdir = layer / 'recipes-support' / recipe
    rdir.mkdir(parents=True)
    for v in versions:
        (rdir / f'{recipe}_{v}.bb').write_text(f'SUMMARY = "{recipe} {v}"\n')
    (rdir / f'{recipe}_%.bbappend').write_text(WILDCARD_TEXT)
    return layer


def _select(monkeypatch, selected: Path | None):
    """Make bitbake-getvar FILE report ``selected``."""
    def fake(cmd, cwd=None):
        out = f'{selected}\n' if selected and 'FILE' in cmd else ''
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr='')
    monkeypatch.setattr(recipe_ops, 'run_cmd_capture', fake)


class TestVersionedBbappend:
    def test_single_version_never_asks_bitbake(self, tmp_path, monkeypatch):
        layer = _layer(tmp_path, versions=('1.0',))

        def boom(*a, **k):
            raise AssertionError('bitbake-getvar must not run for a single-version layer')
        monkeypatch.setattr(recipe_ops, 'run_cmd_capture', boom)

        assert versioned_bbappend(layer, 'foo') is None

    def test_selected_version_in_layer(self, tmp_path, monkeypatch):
        layer = _layer(tmp_path)
        bb = layer / 'recipes-support/foo/foo_0.15.7.bb'
        _select(monkeypatch, bb)

        assert versioned_bbappend(layer, 'foo') == bb.with_suffix('.bbappend')

    def test_selected_version_outside_layer(self, tmp_path, monkeypatch):
        layer = _layer(tmp_path)
        upstream = tmp_path / 'oe-core/recipes-support/foo/foo_0.14.2.bb'
        upstream.parent.mkdir(parents=True)
        upstream.write_text('')
        _select(monkeypatch, upstream)

        assert versioned_bbappend(layer, 'foo') is None

    def test_similar_recipe_names_do_not_count(self, tmp_path, monkeypatch):
        """foo-utils_1.0.bb is not a second version of foo."""
        layer = _layer(tmp_path, versions=('1.0',))
        (layer / 'recipes-support/foo/foo-utils_1.0.bb').write_text('')
        _select(monkeypatch, layer / 'recipes-support/foo/foo_1.0.bb')

        assert versioned_bbappend(layer, 'foo') is None


class TestFindRecipeFile:
    def test_ignores_wildcard_bbappend(self, tmp_path, monkeypatch):
        """Without this, liburcu_%.bbappend (sorts first) was the target."""
        layer = _layer(tmp_path)
        bb = layer / 'recipes-support/foo/foo_0.15.7.bb'
        _select(monkeypatch, bb)

        assert _find_recipe_file(layer, 'foo') == bb
        bb.with_suffix('.bbappend').write_text('PR = "r1"\n')
        assert _find_recipe_file(layer, 'foo') == bb.with_suffix('.bbappend')

    def test_other_version_bbappend_is_not_picked(self, tmp_path, monkeypatch):
        layer = _layer(tmp_path)
        (layer / 'recipes-support/foo/foo_0.15.3.bbappend').write_text('')
        _select(monkeypatch, layer / 'recipes-support/foo/foo_0.15.7.bb')

        assert _find_recipe_file(layer, 'foo') == layer / 'recipes-support/foo/foo_0.15.7.bb'


class TestSeed:
    def test_creates_file(self, tmp_path):
        target = tmp_path / 'foo_1.0.bbappend'
        seed_versioned_bbappend(target)
        assert target.read_text() == 'FILESEXTRAPATHS:prepend := "${THISDIR}/${BP}:"\n'

    def test_prepends_to_existing(self, tmp_path):
        target = tmp_path / 'foo_1.0.bbappend'
        target.write_text('PR = "r1"\n')
        seed_versioned_bbappend(target)
        assert target.read_text().splitlines() == [
            'FILESEXTRAPATHS:prepend := "${THISDIR}/${BP}:"', '', 'PR = "r1"']

    def test_keeps_existing_filesextrapaths(self, tmp_path):
        target = tmp_path / 'foo_1.0.bbappend'
        text = 'FILESEXTRAPATHS:prepend := "${THISDIR}/files:"\n'
        target.write_text(text)
        seed_versioned_bbappend(target)
        assert target.read_text() == text


def test_write_cve_status_creates_versioned_bbappend(tmp_path, monkeypatch):
    # The patch export needs a build dir (BBPATH); not what this test is about.
    monkeypatch.setattr('cve_corrector.meta_layer._export_commit_patch', lambda *a, **k: None)
    layer = _layer(tmp_path)
    git(layer, 'init')
    git(layer, 'add', '-A')
    git(layer, 'commit', '-m', 'init')
    bb = layer / 'recipes-support/foo/foo_0.15.7.bb'
    _select(monkeypatch, bb)

    assert write_cve_status(layer, 'foo', 'CVE-2026-1', 'not-applicable-config: x',
                            skip_confirm=True)

    text = bb.with_suffix('.bbappend').read_text()
    assert text.startswith('CVE_STATUS[CVE-2026-1]')
    assert (layer / 'recipes-support/foo/foo_%.bbappend').read_text() == WILDCARD_TEXT


def test_patch_rename_and_split_stay_in_selected_version(tmp_path, monkeypatch):
    """Another version already fixed the same CVE with the same generic patch name."""
    layer = _layer(tmp_path)
    rdir = layer / 'recipes-support/foo'
    other = rdir / 'foo_0.15.3.bbappend'
    other_text = 'SRC_URI += "file://0001-fix.patch file://CVE-2026-1-1.patch"\n'
    other.write_text(other_text)
    mine = rdir / 'foo_0.15.7.bbappend'
    mine.write_text('SRC_URI += "file://0001-fix.patch file://CVE-2026-1-2.patch"\n')
    _select(monkeypatch, rdir / 'foo_0.15.7.bb')

    update_recipe_patch('foo', 'CVE-2026-1-1.patch', '0001-fix.patch', layer)
    _split_src_uri_line('CVE-2026-1', layer, 'foo')

    assert other.read_text() == other_text
    assert 'file://CVE-2026-1-1.patch \\\n' in mine.read_text()
    assert '0001-fix.patch' not in mine.read_text()


# --- end-to-end: finish with --bbappend into a multi-version layer ---

def test_workflow_bbappend_into_multi_version_layer(tmp_path, make_upstream_repo, make_workspace,
                                                    mock_bitbake_env, monkeypatch):
    from cve_corrector.workflow import WorkflowConfig
    from tests.helpers import run_workflow

    bare, hashes = make_upstream_repo(
        files={'src/a.c': 'vulnerable\n'}, version_tag='v0.15.7',
        fix_commits=[{'files': {'src/a.c': 'fixed\n'}, 'message': 'a: fix overflow'}])
    ws = make_workspace(bare, 'foo', 'v0.15.7')

    layer = _layer(tmp_path)
    rdir = layer / 'recipes-support/foo'
    # The same CVE was already fixed for 0.15.3, with the same patch name.
    (rdir / 'foo-0.15.3').mkdir()
    (rdir / 'foo-0.15.3/CVE-2026-1.patch').write_text('0.15.3 fix\n')
    other = rdir / 'foo_0.15.3.bbappend'
    other.write_text('SRC_URI += "file://CVE-2026-1.patch"\n')
    git(layer, 'init')
    git(layer, 'add', '-A')
    git(layer, 'commit', '-m', 'init')

    mock_bitbake_env(ws, layer, 'foo', '0.15.7')
    selected = rdir / 'foo_0.15.7.bb'
    update_calls = []
    mocked_run = subprocess.run

    def fake_update_recipe(cmd):
        """Mimic devtool update-recipe -a (no -w): <FILE stem>.bbappend,
        patches in the bbappend's ${THISDIR}/<dir> FILESEXTRAPATHS entry."""
        append = selected.with_suffix('.bbappend')
        text = append.read_text() if append.exists() else ''
        match = re.search(r'FILESEXTRAPATHS:prepend := "\$\{THISDIR\}/([^:]+):"', text)
        subdir = match.group(1).replace('${BP}', 'foo-0.15.7') if match else 'foo'
        out = rdir / subdir
        out.mkdir(exist_ok=True)
        subprocess.run(['git', 'format-patch', 'devtool-base..devtool', '-o', str(out)],
                       cwd=ws, check=True, capture_output=True)
        names = sorted(p.name for p in out.glob('0*.patch'))
        append.write_text(text + 'SRC_URI += "' + ' '.join(f'file://{n}' for n in names) + '"\n')

    def wrapper(cmd, *args, **kwargs):
        if cmd and str(cmd[0]) == 'devtool' and len(cmd) > 1 and cmd[1] == 'update-recipe':
            update_calls.append([str(c) for c in cmd])
            fake_update_recipe(cmd)
            return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')
        if cmd and str(cmd[0]) == 'bitbake-getvar' and 'FILE' in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout=f'{selected}\n', stderr='')
        return mocked_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, 'run', wrapper)

    cve_id = 'CVE-2026-1'
    cve_data = {cve_id: {'name': 'foo', 'hashes': hashes, 'hash_details': [
        {'hash': hashes[0], 'url': f'https://example.com/commit/{hashes[0]}', 'source': 'test'}]}}
    config = WorkflowConfig(mirror_path=None, mirror_dir=None, meta_layer=layer,
                            skip_build=True, clean=False, skip_ptest=True,
                            edit_mode=False, skip_cve_applicability=True, bbappend=True)

    assert run_workflow(cve_data, cve_id, config) == 0

    assert update_calls and all('-w' not in c for c in update_calls)
    committed = git(layer, 'show', '--name-only', '--format=', 'HEAD').stdout.split()
    assert sorted(committed) == [
        'recipes-support/foo/foo-0.15.7/CVE-2026-1.patch',
        'recipes-support/foo/foo_0.15.7.bbappend',
    ]
    mine = (rdir / 'foo_0.15.7.bbappend').read_text()
    assert mine.startswith('FILESEXTRAPATHS:prepend := "${THISDIR}/${BP}:"')
    assert 'file://CVE-2026-1.patch' in mine
    # Other versions and the wildcard bbappend are untouched.
    assert (rdir / 'foo_%.bbappend').read_text() == WILDCARD_TEXT
    assert other.read_text() == 'SRC_URI += "file://CVE-2026-1.patch"\n'
    assert (rdir / 'foo-0.15.3/CVE-2026-1.patch').read_text() == '0.15.3 fix\n'


def test_workflow_single_version_layer_keeps_own_bbappend(tmp_path, make_upstream_repo,
                                                         make_workspace, mock_bitbake_env,
                                                         monkeypatch):
    """A layer providing one version with its own <recipe>_<PV>.bbappend.

    Previously devtool's new <recipe>_%.bbappend was renamed onto the
    existing <recipe>_<PV>.bbappend, replacing everything in it.
    """
    from cve_corrector.workflow import WorkflowConfig
    from tests.helpers import run_workflow

    bare, hashes = make_upstream_repo(
        files={'src/a.c': 'vulnerable\n'}, version_tag='v1.0',
        fix_commits=[{'files': {'src/a.c': 'fixed\n'}, 'message': 'a: fix overflow'}])
    ws = make_workspace(bare, 'foo', 'v1.0')
    layer = _layer(tmp_path, versions=('1.0',))
    rdir = layer / 'recipes-support/foo'
    (rdir / 'foo_%.bbappend').unlink()
    own = rdir / 'foo_1.0.bbappend'
    own.write_text('DEFAULT_PREFERENCE = "-1"\n')
    git(layer, 'init')
    git(layer, 'add', '-A')
    git(layer, 'commit', '-m', 'init')

    mock_bitbake_env(ws, layer, 'foo', '1.0')
    selected = rdir / 'foo_1.0.bb'
    update_calls = []
    mocked_run = subprocess.run

    def wrapper(cmd, *args, **kwargs):
        if cmd and str(cmd[0]) == 'devtool' and len(cmd) > 1 and cmd[1] == 'update-recipe':
            update_calls.append([str(c) for c in cmd])
            text = own.read_text()
            out = rdir / 'foo-1.0'
            out.mkdir(exist_ok=True)
            subprocess.run(['git', 'format-patch', 'devtool-base..devtool', '-o', str(out)],
                           cwd=ws, check=True, capture_output=True)
            names = sorted(p.name for p in out.glob('0*.patch'))
            own.write_text(text + 'SRC_URI += "' + ' '.join(f'file://{n}' for n in names) + '"\n')
            return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')
        if cmd and str(cmd[0]) == 'bitbake-getvar' and 'FILE' in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout=f'{selected}\n', stderr='')
        return mocked_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, 'run', wrapper)

    cve_id = 'CVE-2026-2'
    cve_data = {cve_id: {'name': 'foo', 'hashes': hashes, 'hash_details': [
        {'hash': hashes[0], 'url': f'https://example.com/commit/{hashes[0]}', 'source': 'test'}]}}
    config = WorkflowConfig(mirror_path=None, mirror_dir=None, meta_layer=layer,
                            skip_build=True, clean=False, skip_ptest=True,
                            edit_mode=False, skip_cve_applicability=True, bbappend=True)

    assert run_workflow(cve_data, cve_id, config) == 0
    assert update_calls and all('-w' not in c for c in update_calls)
    text = own.read_text()
    assert 'DEFAULT_PREFERENCE = "-1"' in text
    assert f'file://{cve_id}.patch' in text
    assert (rdir / f'foo-1.0/{cve_id}.patch').exists()
    assert not (rdir / 'foo_%.bbappend').exists()
