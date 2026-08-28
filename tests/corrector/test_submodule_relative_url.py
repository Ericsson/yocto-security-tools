# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for relative submodule URL resolution in workspace.py.

glib's ``.gitmodules`` points at its gvdb submodule *relatively*
(``url = ../../GNOME/gvdb.git``). Git resolves that against the superproject's
remote, so in a cve-corrector workspace whose ``upstream`` remote is a local
bare mirror (``/home/user/git/glib``) it resolves to a nonexistent sibling
path (``/home/user/GNOME/gvdb.git``). Submodule init then fails, and glib's own
``meson.build`` bootstrap fails with "git submodule failed to init", which the
corrector reports as a pre-existing build failure (exit 10).
"""
import shutil
from unittest.mock import MagicMock, patch

import pytest

from cve_corrector.workspace import (
    _init_submodules,
    _submodule_base_url,
    resolve_relative_submodule_url,
)
from tests.helpers import git

GLIB_GITMODULES = (
    '[submodule "subprojects/gvdb"]\n'
    '\tpath = subprojects/gvdb\n'
    '\turl = ../../GNOME/gvdb.git\n'
    '\tbranch = 0854af0fdb6d527a8d1999835ac2c5059976c210\n'
    '\tshallow = true\n'
)


class TestResolveRelativeSubmoduleUrl:
    def test_glib_gvdb(self):
        assert resolve_relative_submodule_url(
            'https://gitlab.gnome.org/GNOME/glib.git', '../../GNOME/gvdb.git'
        ) == 'https://gitlab.gnome.org/GNOME/gvdb.git'

    def test_single_parent_stays_in_namespace(self):
        assert resolve_relative_submodule_url(
            'https://github.com/org/super.git', '../sub.git'
        ) == 'https://github.com/org/sub.git'

    def test_dot_slash_appends_like_git(self):
        assert resolve_relative_submodule_url(
            'https://github.com/org/super.git', './sub.git'
        ) == 'https://github.com/org/super.git/sub.git'

    def test_trailing_slash_and_git_suffix_tolerated(self):
        assert resolve_relative_submodule_url(
            'git://gitlab.gnome.org/GNOME/glib/', '../../GNOME/gvdb.git'
        ) == 'git://gitlab.gnome.org/GNOME/gvdb.git'

    def test_scp_style_base(self):
        assert resolve_relative_submodule_url(
            'git@gitlab.gnome.org:GNOME/glib.git', '../gvdb.git'
        ) == 'git@gitlab.gnome.org:GNOME/gvdb.git'

    def test_local_path_base(self):
        assert resolve_relative_submodule_url(
            '/home/user/git/glib', '../gvdb.git'
        ) == '/home/user/git/gvdb.git'

    def test_absolute_url_is_not_resolved(self):
        assert resolve_relative_submodule_url(
            'https://gitlab.gnome.org/GNOME/glib.git',
            'https://github.com/org/sub.git') is None

    def test_no_base_url(self):
        assert resolve_relative_submodule_url('', '../sub.git') is None

    def test_escaping_past_root(self):
        assert resolve_relative_submodule_url(
            'https://host/only', '../../../sub.git') is None


class TestSubmoduleBaseUrl:
    @patch('cve_corrector.workspace.run_cmd_capture')
    def test_remote_upstream_is_used(self, mock_capture, tmp_path):
        mock_capture.return_value = MagicMock(
            returncode=0, stdout='https://gitlab.gnome.org/GNOME/glib.git\n')
        assert _submodule_base_url(tmp_path, None) == \
            'https://gitlab.gnome.org/GNOME/glib.git'

    @patch('cve_corrector.workspace.run_cmd_capture')
    def test_local_mirror_falls_back_to_fix_urls(self, mock_capture, tmp_path):
        """A local mirror path cannot anchor a relative submodule URL."""
        mock_capture.return_value = MagicMock(
            returncode=0, stdout='/home/user/git/glib\n')
        base = _submodule_base_url(tmp_path, [{
            'url': 'https://gitlab.gnome.org/GNOME/glib/-/commit/abc123'}])
        assert base is not None
        assert 'gitlab.gnome.org' in base
        assert not base.startswith('/')


class TestInitSubmodulesUrlOverride:
    @pytest.fixture
    def workspace(self, tmp_path):
        ws = tmp_path / 'glib-2.0'
        ws.mkdir()
        (ws / '.gitmodules').write_text(GLIB_GITMODULES)
        return ws

    @patch('cve_corrector.workspace._gitmodules_entries',
           return_value=[('subprojects/gvdb', '../../GNOME/gvdb.git')])
    @patch('cve_corrector.workspace.run_cmd_capture')
    @patch('cve_corrector.workspace.run_cmd', return_value=0)
    def test_relative_url_rewritten_when_mirror_is_upstream(
            self, mock_cmd, mock_capture, mock_entries, workspace):
        mock_capture.return_value = MagicMock(
            returncode=0, stdout='/home/user/git/glib\n')

        _init_submodules(workspace, hash_details=[{
            'url': 'https://gitlab.gnome.org/GNOME/glib/-/commit/abc'}])

        config_calls = [c[0][0] for c in mock_cmd.call_args_list
                        if c[0][0][:2] == ['git', 'config']]
        assert config_calls == [[
            'git', 'config', 'submodule.subprojects/gvdb.url',
            'https://gitlab.gnome.org/GNOME/gvdb.git']]

    @patch('cve_corrector.workspace._gitmodules_entries',
           return_value=[('subprojects/gvdb', '../../GNOME/gvdb.git')])
    @patch('cve_corrector.workspace.run_cmd_capture')
    @patch('cve_corrector.workspace.run_cmd', return_value=0)
    def test_local_submodule_mirror_preferred(
            self, mock_cmd, mock_capture, mock_entries, workspace, tmp_path):
        """A mirrored submodule is fetched locally, like the superproject."""
        mirror_dir = tmp_path / 'mirrors'
        (mirror_dir / 'gvdb.git').mkdir(parents=True)
        mock_capture.return_value = MagicMock(
            returncode=0, stdout='/home/user/git/glib\n')

        _init_submodules(workspace, mirror_dir=mirror_dir)

        config_calls = [c[0][0] for c in mock_cmd.call_args_list
                        if c[0][0][:2] == ['git', 'config']]
        assert config_calls == [[
            'git', 'config', 'submodule.subprojects/gvdb.url',
            str((mirror_dir / 'gvdb.git').absolute())]]
        # Local transports are blocked for submodules by default
        # (CVE-2022-39253); the update must opt in explicitly.
        update_call = [c[0][0] for c in mock_cmd.call_args_list
                       if 'update' in c[0][0]][0]
        assert update_call[:3] == ['git', '-c', 'protocol.file.allow=always']

    @patch('cve_corrector.workspace._gitmodules_entries',
           return_value=[('modules/oniguruma',
                          'https://github.com/kkos/oniguruma.git')])
    @patch('cve_corrector.workspace.run_cmd_capture')
    @patch('cve_corrector.workspace.run_cmd', return_value=0)
    def test_absolute_url_untouched(self, mock_cmd, mock_capture, mock_entries,
                                   workspace):
        mock_capture.return_value = MagicMock(returncode=0, stdout='')

        _init_submodules(workspace)

        assert not [c[0][0] for c in mock_cmd.call_args_list
                    if c[0][0][:2] == ['git', 'config']]
        update_call = [c[0][0] for c in mock_cmd.call_args_list
                       if 'update' in c[0][0]][0]
        assert update_call[:2] == ['git', 'submodule']


class TestInitSubmodulesIntegration:
    """Real git repos: the glib/gvdb layout that produced the exit-10 skip."""

    @pytest.fixture
    def glib_like_workspace(self, tmp_path):
        """Superproject with a relative submodule URL and a local mirror set.

        Returns:
            Tuple of (workspace path, mirror dir, submodule file name).
        """
        mirrors = tmp_path / 'mirrors'
        mirrors.mkdir()

        # The submodule project (gvdb) and its bare mirror.
        sub = tmp_path / 'gvdb'
        sub.mkdir()
        git(sub, 'init', '-q', '-b', 'main')
        (sub / 'gvdb.h').write_text('#define GVDB 1\n')
        git(sub, 'add', '-A')
        git(sub, 'commit', '-m', 'init gvdb')
        git(tmp_path, 'clone', '-q', '--bare', str(sub), str(mirrors / 'gvdb.git'))

        # The superproject, wired to the submodule the way glib is.
        ws = tmp_path / 'workspace' / 'sources' / 'glib-2.0'
        ws.mkdir(parents=True)
        git(ws, 'init', '-q', '-b', 'main')
        (ws / 'meson.build').write_text("project('glib')\n")
        git(ws, 'add', '-A')
        git(ws, 'commit', '-m', 'initial')
        git(ws, '-c', 'protocol.file.allow=always', 'submodule', 'add', '-q',
            str(sub), 'subprojects/gvdb')
        git(ws, 'commit', '-m', 'add gvdb submodule')

        # Upstream records the submodule *relatively*, which cannot resolve
        # against the local mirror used as the workspace's upstream remote.
        (ws / '.gitmodules').write_text(
            '[submodule "subprojects/gvdb"]\n'
            '\tpath = subprojects/gvdb\n'
            '\turl = ../../GNOME/gvdb.git\n'
        )
        git(ws, 'add', '.gitmodules')
        git(ws, 'commit', '-m', 'use relative submodule url')

        # A fresh devtool checkout has neither submodule config, content, nor
        # a previously cloned submodule repo under .git/modules — 'deinit'
        # alone keeps the latter, which would make the submodule resolvable
        # without ever consulting the configured URL.
        git(ws, 'submodule', 'deinit', '-f', 'subprojects/gvdb')
        shutil.rmtree(ws / '.git' / 'modules' / 'subprojects' / 'gvdb')
        git(ws, 'remote', 'add', 'upstream', str(mirrors / 'glib.git'))
        return ws, mirrors

    def test_relative_url_with_local_mirror_populates_submodule(
            self, glib_like_workspace):
        ws, mirrors = glib_like_workspace
        assert not (ws / 'subprojects' / 'gvdb' / 'gvdb.h').exists()

        _init_submodules(
            ws,
            hash_details=[{'url': 'https://gitlab.gnome.org/GNOME/glib/'
                                  '-/commit/abc123'}],
            mirror_dir=mirrors)

        assert (ws / 'subprojects' / 'gvdb' / 'gvdb.h').read_text() == \
            '#define GVDB 1\n'
        assert git(ws, 'status', '--porcelain').stdout.strip() == ''

    def test_unresolvable_relative_url_leaves_submodule_empty(
            self, glib_like_workspace):
        """Without a mirror or a deducible upstream, init fails but is soft."""
        ws, _ = glib_like_workspace

        _init_submodules(ws)

        assert not (ws / 'subprojects' / 'gvdb' / 'gvdb.h').exists()
