# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Shared pytest fixtures for cve_corrector scenario tests.

These fixtures create real git repos in tmp_path for git operations but mock
devtool/bitbake commands, providing fast feedback during refactoring without
needing the full Yocto build environment.
"""
import subprocess
from pathlib import Path
from typing import Optional

import pytest

from tests.helpers import devtool_finish_sim, git, git_hash

# ---------------------------------------------------------------------------
# Auto-mark tests using git fixtures as integration tests
# ---------------------------------------------------------------------------

def pytest_collection_modifyitems(items):
    """Auto-mark tests that use git repo fixtures as integration."""
    git_fixtures = {'make_upstream_repo', 'make_workspace', 'make_meta_layer',
                    'mock_bitbake_env'}
    for item in items:
        if git_fixtures & set(item.fixturenames):
            item.add_marker(pytest.mark.integration)


# ---------------------------------------------------------------------------
# Factory fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def make_upstream_repo(tmp_path):
    """Factory: create a bare upstream repo with version tag and fix commits."""

    def _factory(files: dict, version_tag: str, fix_commits: list,
                 monorepo_prefix: Optional[str] = None):
        bare = tmp_path / 'upstream.git'
        git(tmp_path, 'init', '--bare', '--initial-branch=main', str(bare))

        work = tmp_path / 'upstream_work'
        git(tmp_path, 'clone', str(bare), str(work))

        # Initial commit with files
        for path, content in files.items():
            full = path if not monorepo_prefix else f"{monorepo_prefix}/{path}"
            fpath = work / full
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_text(content)
        git(work, 'add', '-A')
        git(work, 'commit', '-m', 'Initial commit')
        git(work, 'tag', version_tag)

        # Fix commits
        hashes = []
        for fix in fix_commits:
            for path, content in fix['files'].items():
                full = path if not monorepo_prefix else f"{monorepo_prefix}/{path}"
                fpath = work / full
                fpath.parent.mkdir(parents=True, exist_ok=True)
                fpath.write_text(content)
            git(work, 'add', '-A')
            git(work, 'commit', '-m', fix['message'])
            hashes.append(git_hash(work))

        git(work, 'push', 'origin', '--all')
        git(work, 'push', 'origin', '--tags')
        return bare, hashes

    return _factory


@pytest.fixture
def make_workspace(tmp_path):
    """Factory: create a devtool-like workspace from upstream bare repo."""

    def _factory(upstream_bare: Path, recipe: str, version_tag: str,
                 existing_patch_commits: Optional[list] = None):
        ws = tmp_path / 'build' / 'workspace' / 'sources' / recipe
        git(tmp_path, 'clone', str(upstream_bare), str(ws))

        git(ws, 'checkout', '-B', 'main', version_tag)
        git(ws, 'branch', 'devtool-base')
        git(ws, 'checkout', '-b', 'devtool')

        if existing_patch_commits:
            for patch in existing_patch_commits:
                for path, content in patch['files'].items():
                    fpath = ws / path
                    fpath.parent.mkdir(parents=True, exist_ok=True)
                    fpath.write_text(content)
                git(ws, 'add', '-Af')
                git(ws, 'commit', '-m', patch['message'])

        # Rename origin to upstream
        git(ws, 'remote', 'rename', 'origin', 'upstream')
        git(ws, 'fetch', 'upstream', '--tags')
        return ws

    return _factory


@pytest.fixture
def make_meta_layer(tmp_path):
    """Factory: create a meta-layer git repo with recipe and patches."""

    def _factory(recipe: str, version: str,
                 existing_patches: Optional[dict] = None,
                 src_uri_entries: Optional[list] = None):
        meta = tmp_path / 'meta-layer'
        meta.mkdir(parents=True, exist_ok=True)
        git(meta, 'init')
        git(meta, 'commit', '--allow-empty', '-m', 'init')

        recipe_dir = meta / 'recipes-core' / recipe
        recipe_dir.mkdir(parents=True)

        # Build SRC_URI content
        entries = list(src_uri_entries or [])
        if existing_patches:
            for fname in sorted(existing_patches.keys()):
                entry = f'file://{fname}'
                if entry not in entries:
                    entries.append(entry)

        if entries:
            src_lines = 'SRC_URI = " \\\n'
            for e in entries:
                entry = e if e.startswith('file://') else f'file://{e}'
                src_lines += f'           {entry} \\\n'
            src_lines += '           "\n'
        else:
            src_lines = 'SRC_URI = ""\n'

        bb = recipe_dir / f'{recipe}_{version}.bb'
        bb.write_text(f'SUMMARY = "{recipe}"\n{src_lines}')

        if existing_patches:
            for fname, content in existing_patches.items():
                (recipe_dir / fname).write_text(content)

        git(meta, 'add', '-A')
        git(meta, 'commit', '-m', f'Add {recipe}')
        return meta

    return _factory


@pytest.fixture
def mock_bitbake_env(monkeypatch):
    """Factory: mock devtool/bitbake commands, pass git through."""

    def _factory(workspace_path: Path, meta_layer: Path, recipe: str,
                 version: str, devtool_finish_fails: bool = False):
        import cve_corrector.ptest as ptest_mod

        build_dir = workspace_path.parent.parent.parent  # build/
        bbpath = str(build_dir)

        # Create required dirs
        (build_dir / 'workspace' / 'cve_corrector').mkdir(parents=True, exist_ok=True)
        conf_dir = build_dir / 'conf'
        conf_dir.mkdir(parents=True, exist_ok=True)
        (conf_dir / 'local.conf').write_text('')

        monkeypatch.setenv('BBPATH', bbpath)

        recipe_bb = next(meta_layer.glob(f'**/{recipe}_*.bb'), None)
        recipe_path_str = str(recipe_bb) if recipe_bb else ''

        orig_subprocess_run = subprocess.run

        build_called = []

        def _is_bitbake_cmd(cmd):
            if not cmd:
                return False
            prog = str(cmd[0])
            return prog in ('devtool', 'bitbake', 'bitbake-layers', 'bitbake-getvar')

        def mock_subprocess_run(cmd, *args, **kwargs):
            if not _is_bitbake_cmd(cmd):
                return orig_subprocess_run(cmd, *args, **kwargs)

            prog = str(cmd[0])
            if prog == 'bitbake-getvar':
                cmd_str = ' '.join(str(c) for c in cmd)
                if 'PTEST_ENABLED' in cmd_str:
                    stdout = 'PTEST_ENABLED="1"\n'
                elif 'DISTRO_FEATURES' in cmd_str:
                    stdout = 'DISTRO_FEATURES="ptest"\n'
                elif 'PV' in cmd_str:
                    stdout = f'PV="{version}"\n'
                else:
                    stdout = ''
                return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr='')

            if prog == 'bitbake-layers':
                return subprocess.CompletedProcess(cmd, 0, stdout=f'{recipe_path_str}\n', stderr='')

            if prog == 'devtool':
                subcmd = cmd[1] if len(cmd) > 1 else ''
                if subcmd == 'finish':
                    if devtool_finish_fails:
                        return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='')
                    devtool_finish_sim(workspace_path, meta_layer, recipe)
                    return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')
                if subcmd == 'build':
                    build_called.append(list(cmd))
                if subcmd == 'status':
                    return subprocess.CompletedProcess(
                        cmd, 0, stdout=f'{recipe}: {workspace_path}\n', stderr='')
                return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')

            return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')

        monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
        monkeypatch.setattr(ptest_mod, 'run_ptest', lambda recipe, **kw: "PASSED: 10, FAILED: 0")
        monkeypatch.setattr(ptest_mod, 'check_ptest_in_recipe', lambda recipe: True)

        # Also patch the references imported into workflow module
        import cve_corrector.workflow as workflow_mod
        monkeypatch.setattr(workflow_mod, 'run_ptest', lambda recipe, **kw: "PASSED: 10, FAILED: 0")
        monkeypatch.setattr(workflow_mod, 'check_ptest_in_recipe', lambda recipe: True)

        return build_called

    return _factory
