# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""bbappend placement for layers devtool cannot lay out correctly.

meta-lts-collab keeps bbappends under BBFILES_DYNAMIC subdirectories
(``meta-core/...``) that ``devtool finish`` does not know about.
"""
import subprocess
from pathlib import Path
from unittest.mock import patch

from cve_corrector.recipe_ops import relocate_new_bbappends, resolve_bbappend_dir


def _proc(stdout='', rc=0):
    return subprocess.CompletedProcess([], rc, stdout=stdout, stderr='')


LTS_LAYER_CONF = '''\
BBFILES += "${LAYERDIR}/recipes-*/*/*.bb \\
            ${LAYERDIR}/recipes-*/*/*.bbappend"
BBFILE_COLLECTIONS += "meta-lts-collab"
BBFILES_DYNAMIC += "\\
    core:${LAYERDIR}/meta-core/*/*/*.bbappend \\
    core:${LAYERDIR}/meta-core/*/*/*.bb \\
    openembedded-layer:${LAYERDIR}/meta-oe/*/*/*.bbappend \\
    "
'''


def _lts_layer(tmp_path: Path) -> Path:
    layer = tmp_path / 'meta-lts-collab'
    (layer / 'conf').mkdir(parents=True)
    (layer / 'conf' / 'layer.conf').write_text(LTS_LAYER_CONF)
    return layer


def _oe_core(tmp_path: Path) -> Path:
    """A minimal oe-core 'meta' layer with recipes-support/curl/curl_7.82.0.bb."""
    meta = tmp_path / 'poky' / 'meta'
    (meta / 'conf').mkdir(parents=True)
    (meta / 'conf' / 'layer.conf').write_text('BBFILE_COLLECTIONS += "core"\n')
    recipe = meta / 'recipes-support' / 'curl' / 'curl_7.82.0.bb'
    recipe.parent.mkdir(parents=True)
    recipe.write_text('')
    return recipe


def _devtool_stray(layer: Path) -> Path:
    """What devtool finish writes into meta-lts-collab for curl."""
    stray = layer / 'recipes-support' / 'curl' / 'curl_%.bbappend'
    (stray.parent / 'curl').mkdir(parents=True)
    (stray.parent / 'curl' / 'CVE-2026-1.patch').write_text('patch\n')
    stray.write_text('FILESEXTRAPATHS:prepend := "${THISDIR}/${PN}:"\n\n'
                     'SRC_URI += "file://CVE-2026-1.patch"\n')
    return stray


class TestResolveBbappendDir:
    def test_existing_bbappend_wins(self, tmp_path):
        layer = _lts_layer(tmp_path)
        existing = layer / 'meta-core' / 'recipes-support' / 'curl' / 'curl_7.82.0.bbappend'
        existing.parent.mkdir(parents=True)
        existing.write_text('')
        with patch("cve_corrector.recipe_ops.run_cmd_capture") as mock_run:
            assert resolve_bbappend_dir(layer, 'curl') == existing.parent
        mock_run.assert_not_called()

    def test_override_wins(self, tmp_path):
        layer = _lts_layer(tmp_path)
        override = layer / 'meta-core' / 'custom'
        assert resolve_bbappend_dir(layer, 'curl', override) == override

    def test_bbfiles_dynamic_layout(self, tmp_path):
        layer = _lts_layer(tmp_path)
        recipe = _oe_core(tmp_path)
        with patch("cve_corrector.recipe_ops.run_cmd_capture",
                   return_value=_proc(f'{recipe}\n')):
            assert resolve_bbappend_dir(layer, 'curl') == (
                layer / 'meta-core' / 'recipes-support' / 'curl')

    def test_unmatched_collection(self, tmp_path):
        layer = _lts_layer(tmp_path)
        recipe = _oe_core(tmp_path)
        conf = recipe.parents[2] / 'conf' / 'layer.conf'
        conf.write_text('BBFILE_COLLECTIONS += "other-layer"\n')
        with patch("cve_corrector.recipe_ops.run_cmd_capture",
                   return_value=_proc(f'{recipe}\n')):
            assert resolve_bbappend_dir(layer, 'curl') is None

    def test_plain_layer_keeps_devtool_placement(self, tmp_path):
        layer = tmp_path / 'meta-mine'
        (layer / 'conf').mkdir(parents=True)
        (layer / 'conf' / 'layer.conf').write_text(
            'BBFILES += "${LAYERDIR}/recipes-*/*/*.bbappend"\n')
        with patch("cve_corrector.recipe_ops.run_cmd_capture") as mock_run:
            assert resolve_bbappend_dir(layer, 'curl') is None
        mock_run.assert_not_called()


class TestRelocateNewBbappends:
    def test_merges_into_existing_lts_collab_bbappend(self, tmp_path):
        layer = _lts_layer(tmp_path)
        target = layer / 'meta-core' / 'recipes-support' / 'curl' / 'curl_7.82.0.bbappend'
        (target.parent / 'files').mkdir(parents=True)
        (target.parent / 'files' / 'CVE-2026-0.patch').write_text('old\n')
        target.write_text('FILESEXTRAPATHS:prepend := "${THISDIR}/files:"\n\n'
                          'SRC_URI += "\\\n    file://CVE-2026-0.patch \\\n"\n')
        pre_existing = {target}
        stray = _devtool_stray(layer)

        relocate_new_bbappends(layer, 'curl', target.parent, pre_existing)

        assert not stray.exists()
        assert not (layer / 'recipes-support').exists()
        assert (target.parent / 'files' / 'CVE-2026-1.patch').read_text() == 'patch\n'
        assert target.read_text() == (
            'FILESEXTRAPATHS:prepend := "${THISDIR}/files:"\n\n'
            'SRC_URI += "\\\n'
            '    file://CVE-2026-0.patch \\\n'
            '    file://CVE-2026-1.patch \\\n'
            '"\n')

    def test_creates_bbappend_in_dynamic_dir(self, tmp_path):
        layer = _lts_layer(tmp_path)
        target_dir = layer / 'meta-core' / 'recipes-support' / 'curl'
        stray = _devtool_stray(layer)

        relocate_new_bbappends(layer, 'curl', target_dir, set())

        target = target_dir / 'curl_%.bbappend'
        assert not stray.exists()
        assert (target_dir / 'files' / 'CVE-2026-1.patch').exists()
        assert target.read_text() == (
            'FILESEXTRAPATHS:prepend := "${THISDIR}/files:"\n\n'
            'SRC_URI += "\\\n    file://CVE-2026-1.patch \\\n"\n')

    def test_same_directory_is_left_alone(self, tmp_path):
        layer = _lts_layer(tmp_path)
        stray = _devtool_stray(layer)
        before = stray.read_text()
        relocate_new_bbappends(layer, 'curl', stray.parent, set())
        assert stray.read_text() == before
        assert (stray.parent / 'curl' / 'CVE-2026-1.patch').exists()

    def test_no_target_dir_is_noop(self, tmp_path):
        layer = _lts_layer(tmp_path)
        stray = _devtool_stray(layer)
        relocate_new_bbappends(layer, 'curl', None, set())
        assert stray.exists()


# --- end-to-end: finish into a meta-lts-collab-shaped layer ---

def test_workflow_finish_into_lts_collab_layout(tmp_path, make_upstream_repo, make_workspace,
                                                mock_bitbake_env, monkeypatch):
    """devtool's stray bbappend lands in meta-core/... next to the existing one."""
    import tests.conftest as conftest_mod
    from cve_corrector.workflow import WorkflowConfig
    from tests.helpers import git, run_workflow

    bare, hashes = make_upstream_repo(
        files={'lib/url.c': 'vulnerable\n'}, version_tag='curl-7_82_0',
        fix_commits=[{'files': {'lib/url.c': 'fixed\n'}, 'message': 'url: fix overflow'}])
    ws = make_workspace(bare, 'curl', 'curl-7_82_0')

    layer = _lts_layer(tmp_path)
    git(layer, 'init')
    target = layer / 'meta-core' / 'recipes-support' / 'curl' / 'curl_7.82.0.bbappend'
    (target.parent / 'files').mkdir(parents=True)
    (target.parent / 'files' / 'CVE-2026-0.patch').write_text('old\n')
    target.write_text('FILESEXTRAPATHS:prepend := "${THISDIR}/files:"\n\n'
                      'SRC_URI += "\\\n    file://CVE-2026-0.patch \\\n"\n')
    git(layer, 'add', '-A')
    git(layer, 'commit', '-m', 'init')

    mock_bitbake_env(ws, layer, 'curl', '7.82.0')

    def fake_finish(workspace_path, meta_layer, recipe):
        """Mimic devtool finish: bbappend at the oe-core-relative path."""
        stray = meta_layer / 'recipes-support' / 'curl' / 'curl_%.bbappend'
        (stray.parent / 'curl').mkdir(parents=True)
        subprocess.run(['git', 'format-patch', 'devtool-base..devtool', '-o',
                        str(stray.parent / 'curl')], cwd=workspace_path,
                       check=True, capture_output=True)
        names = sorted(p.name for p in (stray.parent / 'curl').glob('*.patch'))
        stray.write_text('FILESEXTRAPATHS:prepend := "${THISDIR}/${PN}:"\n\n'
                         'SRC_URI += "' + ' '.join(f'file://{n}' for n in names) + '"\n')
        return 0

    monkeypatch.setattr(conftest_mod, 'devtool_finish_sim', fake_finish)

    cve_id = 'CVE-2026-1'
    cve_data = {cve_id: {'name': 'curl', 'hashes': hashes, 'hash_details': [
        {'hash': hashes[0], 'url': f'https://example.com/commit/{hashes[0]}', 'source': 'test'}]}}
    config = WorkflowConfig(mirror_path=None, mirror_dir=None, meta_layer=layer,
                            skip_build=True, clean=False, skip_ptest=True,
                            edit_mode=False, skip_cve_applicability=True)

    assert run_workflow(cve_data, cve_id, config) == 0

    committed = git(layer, 'show', '--name-only', '--format=', 'HEAD').stdout.split()
    assert sorted(committed) == [
        'meta-core/recipes-support/curl/curl_7.82.0.bbappend',
        f'meta-core/recipes-support/curl/files/{cve_id}.patch',
    ]
    assert not (layer / 'recipes-support').exists()
    text = target.read_text()
    assert 'file://CVE-2026-0.patch' in text and f'file://{cve_id}.patch' in text
