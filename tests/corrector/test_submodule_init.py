# SPDX-License-Identifier: MIT
"""Tests for _init_submodules in workspace.py.

Reproduces the bug where recipes built from tarballs that include submodule
content (e.g. jq with modules/) cause cherry-pick failures because:
1. The upstream tag has .gitmodules but submodules are not initialized
2. copy_missing_files_from_devtool() copies submodule files as untracked
3. The dirty working tree blocks git cherry-pick

The fix: _init_submodules() runs 'git submodule update --init --recursive'
after checkout to properly populate submodule directories as tracked content.
"""
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cve_corrector.workspace import _init_submodules


def _git(repo: Path, *args: str, env: dict | None = None) -> str:
    cmd_env = None
    if env:
        import os
        cmd_env = {**os.environ, **env}
    result = subprocess.run(
        ['git', *args], cwd=repo, check=True,
        capture_output=True, text=True, env=cmd_env,
    )
    return result.stdout.strip()


def _commit(repo: Path, path: str, content: str, message: str) -> str:
    filepath = repo / path
    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_text(content)
    _git(repo, 'add', '-A')
    _git(repo, 'commit', '-m', message)
    return _git(repo, 'rev-parse', 'HEAD')


class TestInitSubmodules:
    """Unit tests for _init_submodules helper."""

    def test_no_gitmodules_is_noop(self, tmp_path: Path) -> None:
        """When .gitmodules doesn't exist, nothing happens."""
        repo = tmp_path / "repo"
        repo.mkdir()
        _git(repo, 'init', '-q')
        _git(repo, 'config', 'user.email', 'test@test.com')
        _git(repo, 'config', 'user.name', 'Test')
        _git(repo, 'config', 'commit.gpgsign', 'false')
        _commit(repo, 'file.c', 'int main() {}', 'initial')

        # Should not raise, should be a no-op
        _init_submodules(repo)

    @patch("cve_corrector.workspace.run_cmd", return_value=0)
    def test_calls_submodule_update_when_gitmodules_exists(
        self, mock_run_cmd: MagicMock, tmp_path: Path
    ) -> None:
        """When .gitmodules exists, git submodule update --init is called."""
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        (workspace / '.gitmodules').write_text(
            '[submodule "modules/oniguruma"]\n'
            '\tpath = modules/oniguruma\n'
            '\turl = https://github.com/kkos/oniguruma.git\n'
        )

        _init_submodules(workspace)

        # 'submodule init' seeds the local config, then update populates the
        # working tree. An absolute URL needs no override, so no git config
        # call sits between them.
        assert [c[0][0] for c in mock_run_cmd.call_args_list] == [
            ['git', 'submodule', 'init'],
            ['git', 'submodule', 'update', '--init', '--recursive'],
        ]
        assert mock_run_cmd.call_args_list[-1][1] == {'cwd': workspace}

    @patch("cve_corrector.workspace.run_cmd", return_value=1)
    def test_failure_is_non_fatal(
        self, mock_run_cmd: MagicMock, tmp_path: Path
    ) -> None:
        """Submodule init failure is a warning, not an error."""
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        (workspace / '.gitmodules').write_text(
            '[submodule "modules/oniguruma"]\n'
            '\tpath = modules/oniguruma\n'
            '\turl = https://github.com/kkos/oniguruma.git\n'
        )

        # Should not raise even when command fails
        _init_submodules(workspace)
        assert ['git', 'submodule', 'update', '--init', '--recursive'] in [
            c[0][0] for c in mock_run_cmd.call_args_list]


class TestInitSubmodulesIntegration:
    """Integration test with a real git repo and submodule.

    Uses ``git -c protocol.file.allow=always`` to permit local file:// clones,
    which newer git versions block by default (CVE-2022-39253 mitigation).
    """

    @pytest.fixture
    def workspace_with_submodule(self, tmp_path: Path) -> tuple[Path, Path]:
        """Create a workspace mimicking the jq submodule scenario.

        Layout:
        - submodule_repo: a small git repo (simulates oniguruma)
        - main_repo: has .gitmodules referencing submodule_repo,
          with a 'devtool' branch containing the submodule content
          as regular files (simulating what devtool extracts from a tarball)
        """
        # Create the "submodule" repository
        sub_repo = tmp_path / "oniguruma"
        sub_repo.mkdir()
        _git(sub_repo, 'init', '-q', '-b', 'main')
        _git(sub_repo, 'config', 'user.email', 'test@test.com')
        _git(sub_repo, 'config', 'user.name', 'Test')
        _git(sub_repo, 'config', 'commit.gpgsign', 'false')
        _commit(sub_repo, 'onig.h', '#define ONIG_VERSION 6', 'init oniguruma')
        _commit(sub_repo, 'regcomp.c', 'int compile() { return 0; }', 'add regcomp')

        # Create the main repo (simulates jq upstream)
        main_repo = tmp_path / "jq"
        main_repo.mkdir()
        _git(main_repo, 'init', '-q', '-b', 'main')
        _git(main_repo, 'config', 'user.email', 'test@test.com')
        _git(main_repo, 'config', 'user.name', 'Test')
        _git(main_repo, 'config', 'commit.gpgsign', 'false')
        # Allow local file:// protocol for submodule operations
        _git(main_repo, 'config', 'protocol.file.allow', 'always')

        # Initial commit with source code
        _commit(main_repo, 'jq.c', 'int main() { return jq_run(); }', 'initial jq')

        # Add submodule (needs protocol.file.allow for local paths)
        _git(main_repo, '-c', 'protocol.file.allow=always',
             'submodule', 'add', str(sub_repo), 'modules/oniguruma')
        _git(main_repo, 'commit', '-m', 'add oniguruma submodule')
        _git(main_repo, 'tag', 'jq-1.7.1')

        # Add a fix commit after the tag (the CVE fix)
        _commit(main_repo, 'jq.c',
                'int main() { if (!validate()) return 1; return jq_run(); }',
                'fix: add input validation')

        # Now create devtool-style branches (simulating tarball extraction).
        # devtool-base: orphan with the tarball content (submodule files
        # included as regular tracked files — this is what OE does)
        _git(main_repo, 'checkout', '-q', '--orphan', 'devtool-base')
        _git(main_repo, 'rm', '-q', '-rf', '.')

        # Write all files as if extracted from tarball (including submodule content)
        _commit(main_repo, 'jq.c', 'int main() { return jq_run(); }', 'tarball: jq.c')
        (main_repo / 'modules' / 'oniguruma').mkdir(parents=True, exist_ok=True)
        (main_repo / 'modules' / 'oniguruma' / 'onig.h').write_text(
            '#define ONIG_VERSION 6')
        (main_repo / 'modules' / 'oniguruma' / 'regcomp.c').write_text(
            'int compile() { return 0; }')
        _git(main_repo, 'add', '-A')
        _git(main_repo, 'commit', '-m', 'tarball: submodule files')

        # devtool branch: recipe patches on top of devtool-base
        _git(main_repo, 'checkout', '-q', '-b', 'devtool')
        _commit(main_repo, 'Makefile', 'all: jq\n', 'recipe: add Makefile')

        return main_repo, sub_repo

    def test_submodule_init_prevents_dirty_tree(
        self, workspace_with_submodule: tuple[Path, Path]
    ) -> None:
        """Without _init_submodules, copy_missing_files leaves dirty tree.

        With _init_submodules, submodule files are tracked and
        copy_missing_files_from_devtool skips them (they already exist).
        """
        main_repo, _ = workspace_with_submodule

        # Checkout the upstream tag on a new branch (like prepare_cve_branch does)
        _git(main_repo, 'checkout', '-b', 'CVE-2026-99999', 'jq-1.7.1')

        # Run submodule init (the fix)
        _init_submodules(main_repo)

        # Verify submodule files are populated
        assert (main_repo / 'modules' / 'oniguruma' / 'onig.h').exists()
        assert (main_repo / 'modules' / 'oniguruma' / 'regcomp.c').exists()

        # Working tree should be clean after submodule init
        status = _git(main_repo, 'status', '--porcelain')
        assert status == "", f"Expected clean tree, got:\n{status}"

    def test_without_fix_submodule_files_would_be_copied(
        self, workspace_with_submodule: tuple[Path, Path]
    ) -> None:
        """Demonstrate the bug scenario: devtool has submodule files as blobs.

        Without the fix, copy_missing_files_from_devtool would copy submodule
        files (which are regular blobs on the devtool branch) into the working
        tree, making it dirty. The fix skips files under submodule paths.

        This test verifies that the submodule path filter works by confirming
        that submodule files exist on devtool but are correctly excluded.
        """
        from cve_corrector.git_ops import _get_submodule_paths

        main_repo, _ = workspace_with_submodule

        # Checkout the upstream tag on a new branch WITHOUT submodule init
        _git(main_repo, 'checkout', '-b', 'CVE-2026-99998', 'jq-1.7.1')

        # Verify the precondition: devtool has files under submodule paths
        devtool_files = _git(main_repo, 'ls-tree', '-r', '--name-only', 'devtool')
        assert 'modules/oniguruma/onig.h' in devtool_files

        # Verify the submodule path filter detects the submodule
        submodule_paths = _get_submodule_paths(main_repo)
        assert 'modules/oniguruma' in submodule_paths

        # Verify that HEAD's tree does NOT list the submodule files as blobs
        # (it only has the gitlink entry)
        head_files = _git(main_repo, 'ls-tree', '-r', '--name-only', 'HEAD')
        assert 'modules/oniguruma/onig.h' not in head_files

    def test_with_submodule_init_tree_is_clean_after_copy(
        self, workspace_with_submodule: tuple[Path, Path]
    ) -> None:
        """With the fix: init submodules first, then copy_missing_files is safe.

        After submodule init, the submodule files are tracked. When
        copy_missing_files_from_devtool runs, those files already exist
        in HEAD's tree, so they're not copied as untracked content.
        """
        from cve_corrector.git_ops import copy_missing_files_from_devtool

        main_repo, _ = workspace_with_submodule

        # Checkout the upstream tag on a new branch
        _git(main_repo, 'checkout', '-b', 'CVE-2026-99997', 'jq-1.7.1')

        # Apply the fix
        _init_submodules(main_repo)

        # Now copy missing files
        copy_missing_files_from_devtool(main_repo)

        # The tree should remain clean (or at most have untracked files
        # that are NOT in submodule directories)
        status = _git(main_repo, 'status', '--porcelain')
        submodule_dirty = [
            line for line in status.splitlines()
            if 'modules/oniguruma' in line
        ]
        assert not submodule_dirty, (
            f"Submodule files should not appear as dirty:\n"
            f"{chr(10).join(submodule_dirty)}"
        )
