# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent.git — git helpers and scope hooks."""
import json
import os
import subprocess
from unittest.mock import patch as mock_patch

from cve_agent.commit_notes import MAX_WORDS_SOFT
from cve_agent.git import (
    get_all_upstream_shas,
    get_changed_files,
    get_upstream_sha,
    install_notes_hook,
    install_scope_hook,
    remove_notes_hook,
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


# --- install_notes_hook / remove_notes_hook ---

def test_install_notes_hook(tmp_path):
    ws = tmp_path / "repo"
    (ws / ".git" / "hooks").mkdir(parents=True)
    install_notes_hook(ws)
    hook = ws / ".git" / "hooks" / "commit-msg"
    assert hook.exists()
    assert os.access(hook, os.X_OK)
    assert "cve_agent.commit_notes" in hook.read_text()


def test_install_notes_hook_backup(tmp_path):
    ws = tmp_path / "repo"
    hooks_dir = ws / ".git" / "hooks"
    hooks_dir.mkdir(parents=True)
    (hooks_dir / "commit-msg").write_text("#!/bin/bash\necho old")
    install_notes_hook(ws)
    assert (hooks_dir / "commit-msg.bak").read_text() == "#!/bin/bash\necho old"


def test_remove_notes_hook_restores_backup(tmp_path):
    ws = tmp_path / "repo"
    hooks_dir = ws / ".git" / "hooks"
    hooks_dir.mkdir(parents=True)
    (hooks_dir / "commit-msg").write_text("#!/bin/bash\nnotes hook")
    (hooks_dir / "commit-msg.bak").write_text("#!/bin/bash\noriginal")
    remove_notes_hook(ws)
    assert not (hooks_dir / "commit-msg.bak").exists()
    assert (hooks_dir / "commit-msg").read_text() == "#!/bin/bash\noriginal"


def test_remove_notes_hook_without_backup(tmp_path):
    ws = tmp_path / "repo"
    hooks_dir = ws / ".git" / "hooks"
    hooks_dir.mkdir(parents=True)
    (hooks_dir / "commit-msg").write_text("#!/bin/bash\nnotes hook")
    remove_notes_hook(ws)
    assert not (hooks_dir / "commit-msg").exists()


# --- notes hook against real git ---

def _git(ws, *args, check=True):
    return subprocess.run(["git", *args], cwd=ws,
                          capture_output=True, text=True, check=check)


def _init_repo(tmp_path, install=True):
    """Create a git repo with one staged file, ready to commit."""
    ws = tmp_path / "repo"
    ws.mkdir()
    _git(ws, "init", "-q")
    _git(ws, "config", "user.email", "t@example.com")
    _git(ws, "config", "user.name", "Tester")
    _git(ws, "config", "commit.gpgsign", "false")
    (ws / "a.c").write_text("int main(void) { return 0; }\n")
    _git(ws, "add", "a.c")
    if install:
        install_notes_hook(ws)
    return ws


def _commit(ws, message):
    msg_file = ws.parent / "msg.txt"
    msg_file.write_text(message, encoding="utf-8")
    return _git(ws, "commit", "-F", str(msg_file), check=False)


def _stanza(*bullets):
    body = "\n".join(f"- {b}" for b in bullets)
    return f"Fix a bug\n\nConflicts Resolved:\n\na.c (1 conflict):\n{body}\n"


def test_notes_hook_rejects_over_budget_commit(tmp_path):
    ws = _init_repo(tmp_path)
    long_bullet = " ".join(f"w{i}" for i in range(30))
    result = _commit(ws, _stanza(long_bullet, long_bullet))
    assert result.returncode != 0
    assert "REJECTED a.c" in result.stderr
    # Nothing was committed — the message can be shortened and retried.
    assert _git(ws, "rev-parse", "HEAD", check=False).returncode != 0


def test_notes_hook_accepts_compliant_commit(tmp_path):
    ws = _init_repo(tmp_path)
    result = _commit(ws, _stanza("Adapted foo_v2() to the stable foo_v1() API."))
    assert result.returncode == 0, result.stderr
    assert "REJECTED" not in result.stderr


def test_notes_hook_warns_but_accepts_soft_violation(tmp_path):
    ws = _init_repo(tmp_path)
    soft = " ".join(f"w{i}" for i in range(MAX_WORDS_SOFT + 4))
    result = _commit(ws, _stanza(soft))
    assert result.returncode == 0, result.stderr
    assert "WARNING" in result.stderr


def test_notes_hook_fails_open_when_the_checker_cannot_run(tmp_path):
    """A broken environment must not block a commit — that would deadlock."""
    ws = _init_repo(tmp_path)
    hook = ws / ".git" / "hooks" / "commit-msg"
    hook.write_text(
        hook.read_text(encoding="utf-8").replace(
            "-m cve_agent.commit_notes", "-m cve_agent.does_not_exist"),
        encoding="utf-8",
    )
    result = _commit(ws, _stanza("Adapted foo_v2() to the stable API."))
    assert result.returncode == 0, result.stderr
    assert "could not run" in result.stderr


def test_notes_hook_rejects_then_accepts_a_shortened_cherry_pick(tmp_path):
    """The real recovery path: reject on --continue, shorten, --continue again."""
    ws = _init_repo(tmp_path, install=False)
    _git(ws, "commit", "-q", "-m", "base")
    _git(ws, "checkout", "-q", "-b", "upstream")
    (ws / "a.c").write_text("int main(void) { return 1; }\n")
    _git(ws, "commit", "-qam", "upstream change")
    upstream_sha = _git(ws, "rev-parse", "HEAD").stdout.strip()
    _git(ws, "checkout", "-q", "-")
    (ws / "a.c").write_text("int main(void) { return 2; }\n")
    _git(ws, "commit", "-qam", "stable change")

    conflict = _git(ws, "cherry-pick", upstream_sha, check=False)
    assert conflict.returncode != 0
    (ws / "a.c").write_text("int main(void) { return 1; }\n")
    _git(ws, "add", "a.c")

    install_notes_hook(ws)
    merge_msg = ws / ".git" / "MERGE_MSG"
    long_bullet = " ".join(f"w{i}" for i in range(30))
    merge_msg.write_text(_stanza(long_bullet, long_bullet), encoding="utf-8")
    rejected = _git(ws, "cherry-pick", "--no-edit", "--continue", check=False)
    assert rejected.returncode != 0
    assert "REJECTED a.c" in rejected.stderr
    # The cherry-pick is still in progress and the message survived.
    assert (ws / ".git" / "CHERRY_PICK_HEAD").exists()
    assert merge_msg.exists()

    merge_msg.write_text(_stanza("Kept the upstream return value."),
                         encoding="utf-8")
    accepted = _git(ws, "cherry-pick", "--no-edit", "--continue", check=False)
    assert accepted.returncode == 0, accepted.stderr
    assert "Kept the upstream return value." in _git(
        ws, "log", "-1", "--format=%B").stdout
