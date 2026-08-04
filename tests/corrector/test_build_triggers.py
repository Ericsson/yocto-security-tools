# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for remove_git_only_build_triggers (git-vs-tarball dependency fix)."""
import subprocess
from pathlib import Path

import pytest

from cve_corrector.git_ops import remove_git_only_build_triggers


def _git_init(repo: Path) -> None:
    """Initialize a git repo with user config."""
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"],
                   cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"],
                   cwd=repo, check=True, capture_output=True)


def _git_commit(repo: Path, msg: str) -> None:
    """Stage all and commit."""
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", msg],
                   cwd=repo, check=True, capture_output=True)


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """Git repo simulating gnutls: devtool branch = tarball (no prime-check.c),
    HEAD = git checkout (has prime-check.c triggering libev4 via configure.ac).
    """
    repo = tmp_path / "gnutls"
    repo.mkdir()
    _git_init(repo)

    # Tarball layout — no prime-check.c
    (repo / "configure.ac").write_text(
        'SUITE_FILE="${srcdir}/tests/suite/prime-check.c"\n'
        'if test "$full_test_suite" = yes && test ! -f "$SUITE_FILE";then\n'
        '\tfull_test_suite=no\n'
        'fi\n'
    )
    (repo / "lib").mkdir()
    (repo / "lib" / "gnutls.c").write_text("/* main lib */\n")
    _git_commit(repo, "Initial tarball content")
    subprocess.run(["git", "branch", "devtool"], cwd=repo,
                   check=True, capture_output=True)

    # Git-only test file (upstream tag checkout)
    (repo / "tests" / "suite").mkdir(parents=True)
    (repo / "tests" / "suite" / "prime-check.c").write_text("int main() {}\n")
    _git_commit(repo, "Add git-only test suite file")
    return repo


def test_removes_git_only_trigger_file(workspace: Path):
    """prime-check.c is removed — it triggers libev4 and isn't in the tarball."""
    assert (workspace / "tests" / "suite" / "prime-check.c").exists()
    remove_git_only_build_triggers(workspace)
    assert not (workspace / "tests" / "suite" / "prime-check.c").exists()


def test_preserves_file_that_exists_in_tarball(workspace: Path):
    """configure.ac (in both git and tarball) is NOT removed."""
    remove_git_only_build_triggers(workspace)
    assert (workspace / "configure.ac").exists()


def test_noop_when_no_configure_ac(tmp_path: Path):
    """No-op when configure.ac doesn't exist."""
    repo = tmp_path / "no_configure"
    repo.mkdir()
    _git_init(repo)
    (repo / "main.c").write_text("int main() {}\n")
    _git_commit(repo, "init")
    subprocess.run(["git", "branch", "devtool"], cwd=repo,
                   check=True, capture_output=True)
    remove_git_only_build_triggers(repo)


def test_noop_when_trigger_file_exists_in_tarball(tmp_path: Path):
    """File is kept when it exists in both git tree and tarball."""
    repo = tmp_path / "both"
    repo.mkdir()
    _git_init(repo)
    (repo / "tests" / "suite").mkdir(parents=True)
    (repo / "tests" / "suite" / "prime-check.c").write_text("int main() {}\n")
    (repo / "configure.ac").write_text(
        'SUITE_FILE="${srcdir}/tests/suite/prime-check.c"\n'
        'if test "$full_test_suite" = yes && test ! -f "$SUITE_FILE";then\n'
        '\tfull_test_suite=no\n'
        'fi\n'
    )
    _git_commit(repo, "init")
    subprocess.run(["git", "branch", "devtool"], cwd=repo,
                   check=True, capture_output=True)

    remove_git_only_build_triggers(repo)
    assert (repo / "tests" / "suite" / "prime-check.c").exists()


def test_handles_literal_path_in_test_f(tmp_path: Path):
    """Detects literal 'test -f ${srcdir}/path' checks."""
    repo = tmp_path / "literal"
    repo.mkdir()
    _git_init(repo)
    (repo / "configure.ac").write_text(
        'if test -f "${srcdir}/extra/check.sh"; then\n'
        '    enable_extra=yes\n'
        'fi\n'
    )
    _git_commit(repo, "init tarball")
    subprocess.run(["git", "branch", "devtool"], cwd=repo,
                   check=True, capture_output=True)

    (repo / "extra").mkdir()
    (repo / "extra" / "check.sh").write_text("#!/bin/sh\n")
    _git_commit(repo, "add git-only check")

    remove_git_only_build_triggers(repo)
    assert not (repo / "extra" / "check.sh").exists()
