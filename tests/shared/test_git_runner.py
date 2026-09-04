# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Regression tests for shared.git_runner text decoding and identity resolution.

Reproduces the crash from a git repo containing a commit whose diff
contains a byte that is invalid UTF-8 (0xA4, as hit by cve-agent on
CVE-2026-39956): subprocess with text=True decodes using errors='strict'
and raises UnicodeDecodeError, aborting the whole run. run_capture() and
run_git_stdout() must use shared.TEXT_ERRORS ('replace') instead.

Also covers resolve_git_identity(), which reads user.name/user.email from
*global* git config only (git config --global), used to seed
GIT_AUTHOR_*/GIT_COMMITTER_* env vars for sandboxed backend sessions that
otherwise have no git identity (the "Committer identity unknown" failure
observed in a real cve-agent --backend openai session). Those tests isolate
global config via a temp $HOME so they never read or depend on the real
operator's ~/.gitconfig.
"""
from pathlib import Path

from shared.git_runner import resolve_git_identity, run_capture, run_git_stdout


def _make_repo_with_invalid_utf8_content(tmp_path: Path) -> Path:
    """Create a git repo with a tracked file containing an invalid UTF-8 byte."""
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir()
    env = {
        "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@test.com",
        "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@test.com",
        "GIT_TERMINAL_PROMPT": "0", "PATH": "/usr/bin:/bin",
    }
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, env=env)

    # 0xa4 is not a valid UTF-8 start byte — the exact byte from the traceback.
    bad_file = repo / "notes.txt"
    bad_file.write_bytes(b"line one\n\xa4 not valid utf-8\nline three\n")

    subprocess.run(["git", "add", "notes.txt"], cwd=repo, check=True, env=env)
    subprocess.run(["git", "commit", "-q", "-m", "Add notes"], cwd=repo,
                   check=True, env=env)
    return repo


def test_run_git_stdout_does_not_raise_on_invalid_utf8(tmp_path):
    repo = _make_repo_with_invalid_utf8_content(tmp_path)

    # Previously: UnicodeDecodeError from subprocess.communicate() (text=True
    # defaults to errors='strict'), matching the traceback in the bug report.
    output = run_git_stdout(["show", "HEAD"], cwd=repo)

    assert "Add notes" in output
    assert "\ufffd" in output  # invalid byte replaced, not raised


def test_run_capture_does_not_raise_on_invalid_utf8(tmp_path):
    repo = _make_repo_with_invalid_utf8_content(tmp_path)

    result = run_capture(["git", "show", "HEAD"], cwd=repo)

    assert result.returncode == 0
    assert "\ufffd" in result.stdout


def _isolated_global_config_home(tmp_path: Path, name: str = "", email: str = "") -> Path:
    """Create a fake $HOME with a global gitconfig, isolated from the real one."""
    import subprocess

    home = tmp_path / "home"
    home.mkdir()
    env = {"HOME": str(home), "PATH": "/usr/bin:/bin", "GIT_TERMINAL_PROMPT": "0"}
    if name:
        subprocess.run(
            ["git", "config", "--global", "user.name", name],
            check=True, env=env)
    if email:
        subprocess.run(
            ["git", "config", "--global", "user.email", email],
            check=True, env=env)
    return home


def test_resolve_git_identity_reads_global_config(tmp_path, monkeypatch):
    home = _isolated_global_config_home(
        tmp_path, name="Global Operator", email="operator@example.com")
    monkeypatch.setenv("HOME", str(home))

    identity = resolve_git_identity()

    assert identity == ("Global Operator", "operator@example.com")


def test_resolve_git_identity_returns_none_without_global_config(tmp_path, monkeypatch):
    home = _isolated_global_config_home(tmp_path)  # no user.name/user.email set
    monkeypatch.setenv("HOME", str(home))

    assert resolve_git_identity() is None


def test_resolve_git_identity_returns_none_when_only_name_configured(tmp_path, monkeypatch):
    home = _isolated_global_config_home(tmp_path, name="Only Name")
    monkeypatch.setenv("HOME", str(home))

    assert resolve_git_identity() is None
