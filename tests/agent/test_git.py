# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent.git — git helpers and scope hooks."""
import json
import os
from unittest.mock import patch as mock_patch

from cve_agent.git import (
    get_all_upstream_shas,
    get_changed_files,
    get_upstream_sha,
    install_scope_hook,
    remove_scope_hook,
)

# --- get_upstream_sha ---

def test_get_upstream_sha_from_state(tmp_path):
    # Set up directory structure: workspace/sources/recipe -> build dir 3 levels up
    ws = tmp_path / "build" / "workspace" / "sources" / "busybox"
    ws.mkdir(parents=True)
    state_dir = tmp_path / "build" / "workspace" / "cve_corrector"
    state_dir.mkdir(parents=True)
    (state_dir / "busybox.json").write_text(
        json.dumps({"commit_hash": "abc123"}))
    result = get_upstream_sha({}, ws)
    assert result == "abc123"


def test_get_upstream_sha_from_cve_info(tmp_path):
    ws = tmp_path / "build" / "workspace" / "sources" / "foo"
    ws.mkdir(parents=True)
    cve_info = {"hashes": ["def456"]}
    result = get_upstream_sha(cve_info, ws)
    assert result == "def456"


def test_get_upstream_sha_unknown(tmp_path):
    ws = tmp_path / "build" / "workspace" / "sources" / "foo"
    ws.mkdir(parents=True)
    assert get_upstream_sha({}, ws) == "unknown"


# --- get_all_upstream_shas ---

def test_get_all_upstream_shas_series(tmp_path):
    ws = tmp_path / "build" / "workspace" / "sources" / "expat"
    ws.mkdir(parents=True)
    state_dir = tmp_path / "build" / "workspace" / "cve_corrector"
    state_dir.mkdir(parents=True)
    (state_dir / "expat.json").write_text(json.dumps({
        "commit_hash": "main",
        "series_state": {"commits": ["aaa", "bbb", "ccc"]}
    }))
    result = get_all_upstream_shas({}, ws)
    assert result == ["aaa", "bbb", "ccc"]


def test_get_all_upstream_shas_single(tmp_path):
    ws = tmp_path / "build" / "workspace" / "sources" / "foo"
    ws.mkdir(parents=True)
    state_dir = tmp_path / "build" / "workspace" / "cve_corrector"
    state_dir.mkdir(parents=True)
    (state_dir / "foo.json").write_text(json.dumps({"commit_hash": "abc"}))
    result = get_all_upstream_shas({}, ws)
    assert result == ["abc"]


# --- get_changed_files ---

def test_get_changed_files(tmp_path):
    with mock_patch("cve_agent.git.run_git_stdout",
                    return_value="a.c\nb.c\n\nc.c"):
        result = get_changed_files(["diff", "--name-only"], tmp_path)
    assert result == {"a.c", "b.c", "c.c"}


# --- install_scope_hook / remove_scope_hook ---

def test_install_scope_hook(tmp_path):
    ws = tmp_path / "repo"
    (ws / ".git" / "hooks").mkdir(parents=True)
    install_scope_hook(ws, {"file_a.c", "file_b.c"})
    hook = ws / ".git" / "hooks" / "pre-commit"
    assert hook.exists()
    assert os.access(hook, os.X_OK)
    # Filenames are written to a separate data file, not inlined in the script
    allowed_file = ws / ".git" / "hooks" / "cve-agent-allowed-files"
    assert allowed_file.exists()
    allowed_content = allowed_file.read_text()
    assert "file_a.c" in allowed_content
    assert "file_b.c" in allowed_content


def test_install_scope_hook_backup(tmp_path):
    ws = tmp_path / "repo"
    hooks_dir = ws / ".git" / "hooks"
    hooks_dir.mkdir(parents=True)
    existing = hooks_dir / "pre-commit"
    existing.write_text("#!/bin/bash\necho old")
    install_scope_hook(ws, {"a.c"})
    assert (hooks_dir / "pre-commit.bak").read_text() == "#!/bin/bash\necho old"


def test_remove_scope_hook(tmp_path):
    ws = tmp_path / "repo"
    hooks_dir = ws / ".git" / "hooks"
    hooks_dir.mkdir(parents=True)
    (hooks_dir / "pre-commit").write_text("#!/bin/bash\nscope hook")
    (hooks_dir / "pre-commit.bak").write_text("#!/bin/bash\noriginal")
    remove_scope_hook(ws)
    assert not (hooks_dir / "pre-commit.bak").exists()
    assert (hooks_dir / "pre-commit").read_text() == "#!/bin/bash\noriginal"
