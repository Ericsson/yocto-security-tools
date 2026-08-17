# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Synthetic tests for deterministic cross-layout patch transfer."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from cve_agent.handoff import validate_repository_handoff
from cve_corrector.handoff import emit_handoff
from cve_corrector.state import WorkflowState
from cve_corrector.transfer import (
    TransferCode,
    TransferError,
    transfer_commits,
    transfer_manifest_path,
)


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def _new_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "build" / "workspace" / "sources" / "recipe"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "source")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "user.email", "test@example.com")
    return repo


def _source_change(
    repo: Path, path: str, old: bytes, new: bytes,
) -> tuple[str, str]:
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(old)
    parent = _commit(repo, "source base")
    target.write_bytes(new)
    commit = _commit(repo, "security fix")
    return parent, commit


def _orphan_target(repo: Path, files: dict[str, bytes]) -> str:
    _git(repo, "checkout", "-q", "--orphan", "target")
    _git(repo, "rm", "-q", "-rf", ".")
    for path, content in files.items():
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return _commit(repo, "target import")


def _transfer(repo: Path, commit: str, **kwargs: object):
    return transfer_commits(
        repo, [commit], "recipe", "CVE-2026-1703", **kwargs)


def test_exact_path_transfer_and_manifest(tmp_path):
    repo = _new_repo(tmp_path)
    parent, commit = _source_change(repo, "src/api.c", b"old\n", b"fixed\n")
    _git(repo, "checkout", "-q", "-b", "target", parent)

    manifest = _transfer(repo, commit)

    assert (repo / "src/api.c").read_bytes() == b"fixed\n"
    assert manifest.entries[0].mapping_method == "exact"
    assert manifest.final_changed_paths == ("src/api.c",)
    retained = json.loads(transfer_manifest_path(repo, "recipe").read_text())
    assert retained["verification"] == "verified"
    assert retained["target_final_head"] == _git(repo, "rev-parse", "HEAD")

    repeated = _transfer(repo, commit)
    assert repeated.final_changed_paths == ()
    assert repeated.omitted_already_present_paths == ("src/api.c",)


def test_configured_source_prefix_transfer(tmp_path):
    repo = _new_repo(tmp_path)
    _, commit = _source_change(
        repo, "upstream/pkg/api.c", b"old\n", b"fixed\n")
    _orphan_target(repo, {"pkg/api.c": b"old\n"})

    manifest = _transfer(repo, commit, source_prefix="upstream")

    assert (repo / "pkg/api.c").read_bytes() == b"fixed\n"
    assert manifest.entries[0].mapping_method == "configured_prefix"


def test_python_style_unique_suffix_uses_strong_content_anchor(tmp_path):
    repo = _new_repo(tmp_path)
    _, commit = _source_change(
        repo, "python/tests/test_install.py", b"assert old\n", b"assert fixed\n")
    _orphan_target(repo, {"Lib/tests/test_install.py": b"assert old\n"})

    manifest = _transfer(repo, commit)

    entry = manifest.entries[0]
    assert entry.target_new_path == "Lib/tests/test_install.py"
    assert entry.mapping_method == "unique_content_anchor"
    assert entry.old_anchor_sha256


def test_ambiguous_duplicate_anchor_rejected_without_target_change(tmp_path):
    repo = _new_repo(tmp_path)
    _, commit = _source_change(
        repo, "python/tests/test_api.py", b"same\n", b"fixed\n")
    head = _orphan_target(repo, {
        "a/tests/test_api.py": b"same\n",
        "b/tests/test_api.py": b"same\n",
    })

    with pytest.raises(TransferError) as raised:
        _transfer(repo, commit)
    assert raised.value.code is TransferCode.AMBIGUOUS_MAPPING
    assert _git(repo, "rev-parse", "HEAD") == head
    assert _git(repo, "status", "--porcelain") == ""


def test_absent_source_test_path_rejected_without_target_change(tmp_path):
    repo = _new_repo(tmp_path)
    _, commit = _source_change(
        repo, "tests/new-layout.py", b"old\n", b"fixed\n")
    head = _orphan_target(repo, {"tests/different.py": b"unrelated\n"})

    with pytest.raises(TransferError) as raised:
        _transfer(repo, commit)
    assert raised.value.code is TransferCode.NO_TARGET_PATH
    assert _git(repo, "rev-parse", "HEAD") == head
    assert _git(repo, "status", "--porcelain") == ""


def test_rename_delete_and_create_with_explicit_creation_mapping(tmp_path):
    repo = _new_repo(tmp_path)
    for path, content in {
        "src/old.c": b"old\n", "src/delete.c": b"delete\n",
    }.items():
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    _commit(repo, "source base")
    _git(repo, "mv", "src/old.c", "src/new.c")
    (repo / "src/delete.c").unlink()
    (repo / "src/added.c").write_bytes(b"added\n")
    commit = _commit(repo, "reshape fix")
    _orphan_target(repo, {
        "pkg/old.c": b"old\n", "pkg/delete.c": b"delete\n",
    })

    manifest = _transfer(
        repo, commit, explicit_mapping={"src/added.c": "pkg/added.c"})

    assert not (repo / "pkg/old.c").exists()
    assert not (repo / "pkg/delete.c").exists()
    assert (repo / "pkg/new.c").read_bytes() == b"old\n"
    assert (repo / "pkg/added.c").read_bytes() == b"added\n"
    assert set(manifest.final_changed_paths) == {
        "pkg/old.c", "pkg/new.c", "pkg/delete.c", "pkg/added.c"}


@pytest.mark.parametrize("kind", ["mode", "symlink", "binary"])
def test_unsupported_changes_are_rejected_and_rolled_back(tmp_path, kind):
    repo = _new_repo(tmp_path)
    path = repo / "file"
    path.write_bytes(b"old\n")
    parent = _commit(repo, "base")
    if kind == "mode":
        path.chmod(0o755)
    elif kind == "symlink":
        path.unlink()
        os.symlink("elsewhere", path)
    else:
        path.write_bytes(b"fixed\0binary")
    commit = _commit(repo, "unsupported fix")
    _git(repo, "checkout", "-q", "-b", "target", parent)
    head = _git(repo, "rev-parse", "HEAD")

    with pytest.raises(TransferError) as raised:
        _transfer(repo, commit)
    assert raised.value.code is TransferCode.UNSUPPORTED_FILE_TYPE
    assert _git(repo, "rev-parse", "HEAD") == head
    assert _git(repo, "status", "--porcelain") == ""


def test_unique_context_allows_legitimate_branch_adaptation(tmp_path):
    repo = _new_repo(tmp_path)
    _, commit = _source_change(
        repo, "api.c", b"header\nvulnerable\nfooter\n",
        b"header\nfixed\nfooter\n")
    _orphan_target(repo, {
        "api.c": b"branch-only\nheader\nvulnerable\nfooter\n",
    })

    _transfer(repo, commit)

    assert (repo / "api.c").read_bytes() == (
        b"branch-only\nheader\nfixed\nfooter\n")


def test_unique_one_sided_context_allows_branch_adapted_insertion(tmp_path):
    repo = _new_repo(tmp_path)
    _, commit = _source_change(
        repo,
        "setup.cfg",
        (b"testing =\n\t# upstream-only comment\n\tfirst\n\tlast\n\n"
         b"testing-integration =\n"),
        (b"testing =\n\t# upstream-only comment\n\tfirst\n\tlast\n"
         b"\tsecurity-helper\n\ntesting-integration =\n"),
    )
    _orphan_target(repo, {
        "setup.cfg": (
            b"testing =\n\t# stable-only comment\n\tfirst\n\tlast\n"
            b"testing-integration = \n"
        ),
    })

    _transfer(repo, commit)

    assert (repo / "setup.cfg").read_bytes() == (
        b"testing =\n\t# stable-only comment\n\tfirst\n\tlast\n"
        b"\tsecurity-helper\ntesting-integration = \n"
    )


def test_tied_partial_context_rejects_ambiguous_insertion(tmp_path):
    repo = _new_repo(tmp_path)
    _, commit = _source_change(
        repo,
        "setup.cfg",
        b"first\nlast\ntail\n",
        b"first\nlast\nsecurity-helper\ntail\n",
    )
    head = _orphan_target(repo, {
        "setup.cfg": (
            b"first\nlast\nbranch-a\nfirst\nlast\nbranch-b\n"
        ),
    })

    with pytest.raises(TransferError) as raised:
        _transfer(repo, commit)

    assert raised.value.code is TransferCode.CONTEXT_MISMATCH
    assert _git(repo, "rev-parse", "HEAD") == head
    assert _git(repo, "status", "--porcelain") == ""


def test_leading_dash_path_is_passed_safely_after_double_dash(tmp_path):
    repo = _new_repo(tmp_path)
    parent, commit = _source_change(repo, "-option.c", b"old\n", b"fixed\n")
    _git(repo, "checkout", "-q", "-b", "target", parent)

    _transfer(repo, commit)

    assert (repo / "-option.c").read_bytes() == b"fixed\n"


def test_context_mismatch_rolls_back(tmp_path):
    repo = _new_repo(tmp_path)
    _, commit = _source_change(
        repo, "api.c", b"prefix\nrepeat\nsuffix\n",
        b"prefix\nfixed\nsuffix\n")
    head = _orphan_target(repo, {
        "api.c": b"prefix\nrepeat\nsuffix\nprefix\nrepeat\nsuffix\n",
    })

    with pytest.raises(TransferError) as raised:
        _transfer(repo, commit)
    assert raised.value.code is TransferCode.CONTEXT_MISMATCH
    assert _git(repo, "rev-parse", "HEAD") == head
    assert _git(repo, "status", "--porcelain") == ""


def test_successful_layout_transfer_becomes_handoff_scope(tmp_path):
    repo = _new_repo(tmp_path)
    parent, commit = _source_change(
        repo, "upstream/api.c", b"old\n", b"fixed\n")
    _git(repo, "tag", "original-version", parent)
    _orphan_target(repo, {"downstream/api.c": b"old\n"})
    _transfer(
        repo, commit,
        explicit_mapping={"upstream/api.c": "downstream/api.c"})
    state = WorkflowState(
        workspace_path=repo, cve_id="CVE-2026-1703", recipe="recipe",
        commit_hash=commit, hash_details=[], meta_layer=None,
        skip_build=False, skip_ptest=True,
        transfer_path_map={"upstream/api.c": "downstream/api.c"},
    )

    manifest = emit_handoff(
        state, repo.parent.parent / "cve_corrector")

    assert manifest.allowed_paths == ("downstream/api.c",)
    assert validate_repository_handoff(
        repo, "CVE-2026-1703", required=True) == manifest
