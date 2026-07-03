# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for _ensure_layer_branch pre-flight check."""
import subprocess
from unittest.mock import patch

import pytest

from cve_corrector.state import GitError
from cve_corrector.workflow import (
    WorkflowConfig,
    _ensure_layer_branch,
    initialize_cve_workflow,
)


def _config(meta_layer):
    """Minimal WorkflowConfig for the pre-flight test."""
    return WorkflowConfig(
        mirror_path=None, mirror_dir=None, meta_layer=meta_layer,
        skip_build=False, clean=False, skip_ptest=False, edit_mode=False)


def _init_repo(path):
    """Create a git repo with one commit."""
    subprocess.run(['git', 'init', str(path)], check=True, capture_output=True)
    subprocess.run(['git', 'config', 'user.email', 'test@test.com'],
                   cwd=path, check=True, capture_output=True)
    subprocess.run(['git', 'config', 'user.name', 'Test'],
                   cwd=path, check=True, capture_output=True)
    (path / 'f.txt').write_text('x')
    subprocess.run(['git', 'add', '.'], cwd=path, check=True, capture_output=True)
    subprocess.run(['git', 'commit', '-m', 'init'], cwd=path, check=True,
                   capture_output=True)


def test_ensure_layer_branch_on_branch(tmp_path):
    """No error when meta-layer is on a branch."""
    _init_repo(tmp_path)
    _ensure_layer_branch(tmp_path)  # should not raise


def test_ensure_layer_branch_detached_head(tmp_path):
    """Raises GitError when meta-layer has detached HEAD."""
    _init_repo(tmp_path)
    subprocess.run(['git', 'checkout', '--detach'], cwd=tmp_path, check=True,
                   capture_output=True)
    with pytest.raises(GitError, match="detached HEAD"):
        _ensure_layer_branch(tmp_path)


@patch("cve_corrector.workflow.setup_devtool_workspace")
def test_initialize_fails_fast_on_detached_meta_layer(mock_setup, tmp_path):
    """The detached-HEAD guard runs before the expensive workspace setup."""
    _init_repo(tmp_path)
    subprocess.run(['git', 'checkout', '--detach'], cwd=tmp_path, check=True,
                   capture_output=True)
    cve_data = {"CVE-2026-0001": {"name": "bzip2", "hashes": ["abc123"],
                                  "hash_details": []}}
    with pytest.raises(GitError, match="detached HEAD"):
        initialize_cve_workflow(cve_data, "CVE-2026-0001", _config(tmp_path))
    # devtool modify / ptest / build must not have started
    mock_setup.assert_not_called()


@patch("cve_corrector.workflow.setup_devtool_workspace",
       side_effect=RuntimeError("stop after pre-flight"))
def test_initialize_passes_preflight_when_on_branch(mock_setup, tmp_path):
    """When the meta-layer is on a branch, the pre-flight passes and setup runs."""
    _init_repo(tmp_path)  # left on default branch
    cve_data = {"CVE-2026-0001": {"name": "bzip2", "hashes": ["abc123"],
                                  "hash_details": []}}
    # Not a GitError: pre-flight passed and we reached setup_devtool_workspace.
    with pytest.raises(RuntimeError, match="stop after pre-flight"):
        initialize_cve_workflow(cve_data, "CVE-2026-0001", _config(tmp_path))
    mock_setup.assert_called_once()
