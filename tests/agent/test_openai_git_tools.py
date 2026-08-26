# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Security and behavior tests for the native typed Git runtime."""
import os
import stat
import subprocess
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from cve_agent.git import install_scope_hook, remove_scope_hook
from cve_agent.openai_deadline import SessionDeadline
from cve_agent.openai_git_tools import (
    GIT_TOOL_CONTRACTS,
    MAX_GIT_MESSAGE_BYTES,
    NATIVE_TOOL_CONTRACTS,
    GitCommandExecutor,
    GitToolLimits,
    GitToolRuntime,
    build_cherry_pick_message,
    native_openai_tool_schemas,
)
from cve_agent.openai_tools import TOOL_CONTRACTS


def _git(repo: Path, *args: str, check: bool = True,
         input_text: str | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        input=input_text,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        env={
            **os.environ,
            "GIT_EDITOR": "true",
            "GIT_TERMINAL_PROMPT": "0",
        },
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"git {' '.join(args)} failed: {result.stderr or result.stdout}")
    return result


def _commit(repo: Path, message: str) -> str:
    _git(repo, "commit", "-m", message)
    return _git(repo, "rev-parse", "HEAD").stdout.strip()


@pytest.fixture
def repository(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "CVE Test")
    _git(repo, "config", "user.email", "cve@example.com")
    (repo / "a.c").write_text("base\n", encoding="utf-8")
    (repo / "b.c").write_text("base b\n", encoding="utf-8")
    _git(repo, "add", "--", "a.c", "b.c")
    base = _commit(repo, "base subject\n\nbase body")
    branch = _git(repo, "branch", "--show-current").stdout.strip()
    return repo, base, branch


def _runtime(repo: Path, allowed: set[str], **kwargs) -> GitToolRuntime:
    return GitToolRuntime(
        repo,
        allowed,
        model="gpt-test",
        timeout_seconds=30,
        **kwargs,
    )


def _make_source_commit(repo: Path, branch: str, path: str = "a.c",
                        content: str = "upstream\n",
                        message: str = "upstream subject\n\nupstream body") -> str:
    _git(repo, "checkout", "-q", "-b", "source")
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    _git(repo, "add", "--", path)
    commit = _commit(repo, message)
    _git(repo, "checkout", "-q", branch)
    return commit


def test_contracts_and_schemas_share_one_closed_registry():
    schemas = {
        item["function"]["name"]: item["function"]["parameters"]
        for item in native_openai_tool_schemas()
    }
    assert set(NATIVE_TOOL_CONTRACTS) == set(TOOL_CONTRACTS) | set(GIT_TOOL_CONTRACTS)
    assert set(schemas) == set(NATIVE_TOOL_CONTRACTS)
    for parameters in schemas.values():
        assert parameters["additionalProperties"] is False


def test_no_generic_command_or_unsafe_git_input_fields():
    forbidden = {
        "argv", "command", "commands", "config", "environment", "executable",
        "flags", "hook", "options", "pathspec", "shell", "subcommand",
    }
    assert not ({"git", "run_git", "run_process", "execute_bash"}
                & set(GIT_TOOL_CONTRACTS))
    for contract in GIT_TOOL_CONTRACTS.values():
        assert not (set(contract.fields) & forbidden)


def test_status_is_parsed_for_clean_modified_staged_untracked_and_deleted(repository):
    repo, _, _ = repository
    runtime = _runtime(repo, {"a.c", "b.c", "new.c"})
    clean = runtime.dispatch("git_status", {})
    assert clean.success
    assert clean.payload["staged"] == []
    assert clean.payload["unstaged"] == []

    (repo / "a.c").write_text("modified\n", encoding="utf-8")
    (repo / "new.c").write_text("new\n", encoding="utf-8")
    (repo / "b.c").unlink()
    _git(repo, "add", "--", "a.c")
    status = runtime.dispatch("git_status", {})
    assert status.success
    assert status.payload["staged"] == ["a.c"]
    assert status.payload["untracked"] == ["new.c"]
    assert "b.c" in status.payload["unstaged"]
    assert status.payload["deleted"] == ["b.c"]
    assert status.payload["branch"]["head"]


def test_status_and_unmerged_files_parse_conflict(repository):
    repo, _, branch = repository
    source = _make_source_commit(repo, branch)
    (repo / "a.c").write_text("stable\n", encoding="utf-8")
    _git(repo, "add", "--", "a.c")
    _commit(repo, "stable change")
    runtime = _runtime(repo, {"a.c"})
    started = runtime.dispatch("git_cherry_pick_start", {"revision": source})
    assert started.success and started.payload["conflicted"] is True

    status = runtime.dispatch("git_status", {})
    assert status.payload["conflicted"] == ["a.c"]
    assert status.payload["operations"]["cherry_pick"] is True
    unmerged = runtime.dispatch("git_unmerged_files", {})
    assert unmerged.success
    assert unmerged.payload["files"][0]["path"] == "a.c"
    assert {item["stage"] for item in unmerged.payload["files"][0]["stages"]} == {1, 2, 3}


@pytest.mark.parametrize(
    ("marker", "key", "is_directory"),
    [
        ("CHERRY_PICK_HEAD", "cherry_pick", False),
        ("MERGE_HEAD", "merge", False),
        ("rebase-merge", "rebase", True),
        ("REVERT_HEAD", "revert", False),
    ],
)
def test_all_operation_markers_are_reported(repository, marker, key, is_directory):
    repo, _, _ = repository
    runtime = _runtime(repo, {"a.c"})
    target = repo / ".git" / marker
    if is_directory:
        target.mkdir()
    else:
        target.write_text("marker\n", encoding="utf-8")
    status = runtime.dispatch("git_status", {})
    assert status.payload["operations"][key] is True


@pytest.mark.parametrize(
    "revision",
    ["", "-HEAD", "HEAD\nmain", "HEAD\x00main", "a" * 257, "HEAD main"],
)
def test_revision_validator_rejects_unsafe_tokens(repository, revision):
    repo, _, _ = repository
    runtime = _runtime(repo, {"a.c"})
    result = runtime.dispatch("git_show", {"revision": revision})
    assert not result.success
    assert result.error_kind in {"validation", "policy"}
    assert runtime.mutation_generation == 0


def test_revision_must_resolve_to_commit_not_blob(repository):
    repo, _, _ = repository
    blob = _git(repo, "hash-object", "-w", "--stdin", input_text="blob\n").stdout.strip()
    runtime = _runtime(repo, {"a.c"})
    result = runtime.dispatch("git_show", {"revision": blob})
    assert not result.success
    assert result.error_kind == "policy"


def test_replace_refs_cannot_substitute_inspected_commit(repository):
    repo, base, _ = repository
    tree = _git(repo, "show", "-s", "--format=%T", base).stdout.strip()
    replacement = _git(
        repo, "commit-tree", tree, input_text="replacement subject\n").stdout.strip()
    _git(repo, "replace", base, replacement)
    runtime = _runtime(repo, {"a.c"})
    result = runtime.dispatch("git_show", {"revision": base})
    assert result.success
    assert result.payload["message"].startswith("base subject")
    assert "replacement subject" not in result.payload["message"]


def test_diff_show_and_log_are_bounded_and_structured(repository):
    repo, base, _ = repository
    (repo / "a.c").write_text("changed\n", encoding="utf-8")
    runtime = _runtime(repo, {"a.c"})
    working = runtime.dispatch("git_diff", {"mode": "working", "paths": ["a.c"]})
    assert working.success and "+changed" in working.payload["diff"]
    shown = runtime.dispatch("git_show", {"revision": base, "paths": ["a.c"]})
    assert shown.success
    assert shown.payload["commit"] == base
    assert shown.payload["message"].startswith("base subject")
    logged = runtime.dispatch("git_log", {"count": 1, "path": "a.c"})
    assert logged.success
    assert len(logged.payload["entries"]) == 1
    assert logged.payload["entries"][0]["commit"] == base


def test_revision_range_is_resolved_to_immutable_commits(repository):
    repo, base, _ = repository
    (repo / "a.c").write_text("next\n", encoding="utf-8")
    _git(repo, "add", "--", "a.c")
    head = _commit(repo, "next")
    runtime = _runtime(repo, {"a.c"})
    result = runtime.dispatch(
        "git_diff", {"mode": "revision", "revision": f"{base}..{head}"})
    assert result.success
    assert result.payload["revision"] == f"{base}..{head}"


def test_external_diff_textconv_pager_alias_and_credentials_do_not_execute(repository):
    repo, _, _ = repository
    marker = repo / "external-ran"
    helper = repo / "evil-helper"
    helper.write_text(f"#!/bin/sh\ntouch {marker}\ncat\n", encoding="utf-8")
    helper.chmod(0o755)
    (repo / ".gitattributes").write_text("*.c diff=evil\n", encoding="utf-8")
    _git(repo, "config", "diff.evil.command", str(helper))
    _git(repo, "config", "diff.evil.textconv", str(helper))
    _git(repo, "config", "core.pager", str(helper))
    _git(repo, "config", "alias.log", f"!{helper}")
    _git(repo, "config", "credential.helper", f"!{helper}")
    (repo / "a.c").write_text("changed\n", encoding="utf-8")
    runtime = _runtime(repo, {"a.c"})
    assert runtime.dispatch("git_diff", {"mode": "working"}).success
    assert runtime.dispatch("git_log", {"count": 1}).success
    assert not marker.exists()


def test_subprocess_argv_and_environment_are_fixed_and_filtered(repository):
    repo, _, _ = repository
    real_popen = subprocess.Popen
    calls = []

    def recording_popen(*args, **kwargs):
        calls.append((args, kwargs))
        return real_popen(*args, **kwargs)

    with patch.dict(os.environ, {
        "OPENAI_API_KEY": "model-secret",
        "GITHUB_TOKEN": "github-secret",
        "AWS_SECRET_ACCESS_KEY": "aws-secret",
        "GIT_SSH": "/tmp/secret-ssh",
        "GIT_SSH_COMMAND": "ssh -i /tmp/secret-key",
        "SSH_AUTH_SOCK": "/tmp/secret-agent",
        "HTTP_PROXY": "http://user:secret@proxy.example",
        "https_proxy": "http://user:secret@proxy.example",
        "LC_MESSAGES": "host-locale",
        "PATH": os.environ["PATH"],
        "HOME": os.environ.get("HOME", "/tmp"),
    }, clear=True), patch(
        "cve_agent.openai_git_tools.subprocess.Popen",
        side_effect=recording_popen,
    ):
        runtime = _runtime(repo, {"a.c"})
        assert runtime.dispatch("git_status", {}).success

    assert calls
    for args, kwargs in calls:
        command = args[0]
        assert command[:2] == ["git", "--no-pager"]
        assert kwargs["shell"] is False
        assert kwargs["cwd"] == repo.resolve()
        environment = kwargs["env"]
        assert "OPENAI_API_KEY" not in environment
        assert "GITHUB_TOKEN" not in environment
        assert "AWS_SECRET_ACCESS_KEY" not in environment
        assert "GIT_SSH" not in environment
        assert "GIT_SSH_COMMAND" not in environment
        assert "SSH_AUTH_SOCK" not in environment
        assert "HTTP_PROXY" not in environment
        assert "https_proxy" not in environment
        assert "LC_MESSAGES" not in environment
        assert environment["LC_ALL"] == "C"
        assert environment["GIT_TERMINAL_PROMPT"] == "0"
        assert environment["GIT_LITERAL_PATHSPECS"] == "1"
        assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
        assert environment["GIT_CONFIG_GLOBAL"] == os.devnull


def test_workspace_path_entry_cannot_replace_git_executable(repository):
    repo, _, _ = repository
    marker = repo / "fake-git-ran"
    fake_git = repo / "git"
    fake_git.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
    fake_git.chmod(0o755)
    with patch.dict(
        os.environ,
        {"PATH": f"{repo}{os.pathsep}{os.environ['PATH']}"},
        clear=False,
    ):
        runtime = _runtime(repo, {"a.c"})
        assert runtime.dispatch("git_status", {}).success
    assert not marker.exists()


@pytest.mark.parametrize(
    "path",
    ["space name.c", "-leading.c", "semi;colon.c", "unicodé.c", "line\nbreak.c"],
)
def test_exact_staging_handles_weird_filenames(repository, path):
    repo, _, _ = repository
    target = repo / path
    target.write_text("one\n", encoding="utf-8")
    _git(repo, "add", "--", path)
    _commit(repo, f"add {path}")
    target.write_text("two\n", encoding="utf-8")
    runtime = _runtime(repo, {path})
    result = runtime.dispatch("git_stage", {"paths": [path]})
    assert result.success
    staged = _git(repo, "diff", "--cached", "--name-only", "-z").stdout
    assert staged == f"{path}\x00"


@pytest.mark.parametrize(
    "path",
    ["*.c", "a?.c", "[ab].c", ":(top)a.c", ":!a.c", "src"],
)
def test_pathspec_magic_globs_and_directory_staging_are_rejected(repository, path):
    repo, _, _ = repository
    if path == "src":
        (repo / "src").mkdir()
    runtime = _runtime(repo, {path})
    result = runtime.dispatch("git_stage", {"paths": [path]})
    assert not result.success
    assert result.error_kind == "policy"


def test_duplicate_and_unauthorized_staging_are_rejected(repository):
    repo, _, _ = repository
    runtime = _runtime(repo, {"a.c"})
    duplicate = runtime.dispatch("git_stage", {"paths": ["a.c", "./a.c"]})
    unauthorized = runtime.dispatch("git_stage", {"paths": ["b.c"]})
    assert not duplicate.success and duplicate.error_kind == "policy"
    assert not unauthorized.success and unauthorized.error_kind == "policy"


def test_stage_unstage_remove_and_generation(repository):
    repo, _, _ = repository
    (repo / "a.c").write_text("changed\n", encoding="utf-8")
    runtime = _runtime(repo, {"a.c", "b.c"})
    assert runtime.mutation_generation == 0
    staged = runtime.dispatch("git_stage", {"paths": ["a.c"]})
    assert staged.success and staged.audit.generation == 1
    unstaged = runtime.dispatch("git_unstage", {"paths": ["a.c"]})
    assert unstaged.success and unstaged.audit.generation == 2
    removed = runtime.dispatch("git_remove", {"paths": ["b.c"]})
    assert removed.success and removed.audit.generation == 3
    failed = runtime.dispatch("git_stage", {"paths": ["missing.c"]})
    assert not failed.success and failed.audit.generation == 3


def test_remove_stages_a_tracked_file_already_deleted_from_worktree(repository):
    repo, _, _ = repository
    (repo / "a.c").unlink()
    runtime = _runtime(repo, {"a.c"})
    result = runtime.dispatch("git_remove", {"paths": ["a.c"]})
    assert result.success
    assert _git(repo, "diff", "--cached", "--name-only").stdout.strip() == "a.c"


def test_stage_reauthorizes_after_race(repository):
    repo, _, _ = repository

    def race(tool, path):
        if tool == "git_stage":
            path.unlink()
            path.symlink_to(repo / "b.c")

    runtime = _runtime(repo, {"a.c"}, before_operation=race)
    result = runtime.dispatch("git_stage", {"paths": ["a.c"]})
    assert not result.success and result.error_kind == "policy"
    assert runtime.mutation_generation == 0


def test_cherry_pick_starts_when_every_changed_path_is_allowed(repository):
    repo, _, branch = repository
    source = _make_source_commit(repo, branch)
    runtime = _runtime(repo, {"a.c"})
    result = runtime.dispatch("git_cherry_pick_start", {"revision": source})
    assert result.success
    assert result.payload["conflicted"] is False
    assert runtime.mutation_generation == 1
    message = _git(repo, "log", "-1", "--format=%B").stdout
    assert f"(cherry picked from commit {source})" in message


def test_cherry_pick_refuses_worktree_hardlink_before_mutation(
        repository, tmp_path):
    repo, base, branch = repository
    source = _make_source_commit(repo, branch)
    outside = tmp_path / "outside.c"
    outside.write_text("base\n", encoding="utf-8")
    (repo / "a.c").unlink()
    os.link(outside, repo / "a.c")
    runtime = _runtime(repo, {"a.c"})
    result = runtime.dispatch("git_cherry_pick_start", {"revision": source})
    assert not result.success and result.error_kind == "policy"
    assert result.payload["rejected_paths"] == ["a.c"]
    assert outside.read_text(encoding="utf-8") == "base\n"
    assert _git(repo, "rev-parse", "HEAD").stdout.strip() == base


def test_cherry_pick_start_refuses_preexisting_staged_content(repository):
    repo, base, branch = repository
    source = _make_source_commit(repo, branch)
    (repo / "b.c").write_text("pre-staged\n", encoding="utf-8")
    _git(repo, "add", "--", "b.c")
    runtime = _runtime(repo, {"a.c", "b.c"})
    result = runtime.dispatch("git_cherry_pick_start", {"revision": source})
    assert not result.success and result.error_kind == "policy"
    assert result.payload["staged"] == ["b.c"]
    assert _git(repo, "rev-parse", "HEAD").stdout.strip() == base


def test_cherry_pick_refuses_all_paths_if_one_is_out_of_scope(repository):
    repo, base, branch = repository
    _git(repo, "checkout", "-q", "-b", "source")
    (repo / "a.c").write_text("upstream a\n", encoding="utf-8")
    (repo / "b.c").write_text("upstream b\n", encoding="utf-8")
    _git(repo, "add", "--", "a.c", "b.c")
    source = _commit(repo, "two paths")
    _git(repo, "checkout", "-q", branch)
    runtime = _runtime(repo, {"a.c"})
    result = runtime.dispatch("git_cherry_pick_start", {"revision": source})
    assert not result.success and result.error_kind == "policy"
    assert result.payload["rejected_paths"] == ["b.c"]
    assert _git(repo, "rev-parse", "HEAD").stdout.strip() == base
    assert runtime.mutation_generation == 0


def test_root_commit_changed_paths_are_preflighted(tmp_path):
    repo = tmp_path / "root-repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "CVE Test")
    _git(repo, "config", "user.email", "cve@example.com")
    (repo / "base.c").write_text("base\n", encoding="utf-8")
    _git(repo, "add", "--", "base.c")
    _commit(repo, "base")
    branch = _git(repo, "branch", "--show-current").stdout.strip()
    _git(repo, "checkout", "-q", "--orphan", "source-root")
    _git(repo, "rm", "-q", "-rf", "--cached", ".")
    for path in repo.iterdir():
        if path.name != ".git" and path.is_file():
            path.unlink()
    (repo / "root.c").write_text("root\n", encoding="utf-8")
    _git(repo, "add", "--", "root.c")
    root_commit = _commit(repo, "source root")
    _git(repo, "checkout", "-q", branch)
    runtime = _runtime(repo, {"root.c"})
    result = runtime.dispatch("git_cherry_pick_start", {"revision": root_commit})
    assert result.success
    assert result.payload["changed_paths"] == ["root.c"]


def test_rename_copy_and_deletion_paths_are_all_preflighted(repository):
    repo, _, branch = repository
    _git(repo, "checkout", "-q", "-b", "source")
    _git(repo, "mv", "a.c", "renamed.c")
    (repo / "copy.c").write_text((repo / "b.c").read_text(encoding="utf-8"), encoding="utf-8")
    (repo / "b.c").unlink()
    _git(repo, "add", "-A")
    source = _commit(repo, "rename copy delete")
    _git(repo, "checkout", "-q", branch)
    runtime = _runtime(repo, {"renamed.c", "copy.c"})
    result = runtime.dispatch("git_cherry_pick_start", {"revision": source})
    assert not result.success
    rejected = set(result.payload["rejected_paths"])
    assert "a.c" in rejected
    assert "b.c" in rejected


def test_gitlink_change_is_refused_before_mutation(repository):
    repo, base, branch = repository
    _git(repo, "checkout", "-q", "-b", "source")
    _git(repo, "update-index", "--add", "--cacheinfo", f"160000,{base},module")
    source = _commit(repo, "add gitlink")
    _git(repo, "checkout", "-q", branch)
    runtime = _runtime(repo, {"module"})
    result = runtime.dispatch("git_cherry_pick_start", {"revision": source})
    assert not result.success and result.error_kind == "policy"
    assert result.payload["rejected_paths"] == ["module"]
    assert runtime.mutation_generation == 0


def test_symlink_change_is_refused_before_mutation(repository):
    repo, base, branch = repository
    _git(repo, "checkout", "-q", "-b", "source")
    (repo / "a.c").unlink()
    (repo / "a.c").symlink_to("b.c")
    _git(repo, "add", "--", "a.c")
    source = _commit(repo, "replace file with symlink")
    _git(repo, "checkout", "-q", branch)
    runtime = _runtime(repo, {"a.c"})
    result = runtime.dispatch("git_cherry_pick_start", {"revision": source})
    assert not result.success and result.error_kind == "policy"
    assert result.payload["rejected_paths"] == ["a.c"]
    assert _git(repo, "rev-parse", "HEAD").stdout.strip() == base


def test_submodule_status_parses_gitlinks_without_materializing_them(repository):
    repo, base, _ = repository
    _git(repo, "update-index", "--add", "--cacheinfo", f"160000,{base},module")
    _commit(repo, "gitlink")
    runtime = _runtime(repo, {"module"})
    result = runtime.dispatch("git_submodule_status", {})
    assert result.success
    assert result.payload["submodules"] == [{
        "path": "module", "recorded_commit": base, "stage": 0,
    }]
    assert not (repo / "module").exists()


def test_conflict_restore_stage_continue_and_trusted_message(repository):
    repo, _, branch = repository
    editor_marker = repo / "editor-ran"
    editor = repo / "evil-editor"
    editor.write_text(f"#!/bin/sh\ntouch {editor_marker}\n", encoding="utf-8")
    editor.chmod(0o755)
    _git(repo, "config", "core.editor", str(editor))
    _git(repo, "config", "sequence.editor", str(editor))
    source = _make_source_commit(
        repo, branch, message="upstream subject\n\nupstream body\n\nSigned-off-by: Up Stream")
    (repo / "a.c").write_text("stable\n", encoding="utf-8")
    _git(repo, "add", "--", "a.c")
    _commit(repo, "stable")
    runtime = _runtime(repo, {"a.c"})
    assert runtime.dispatch(
        "git_cherry_pick_start", {"revision": source}).payload["conflicted"] is True
    restored = runtime.dispatch(
        "git_restore_conflict", {"path": "a.c", "side": "theirs"})
    assert restored.success
    assert runtime.dispatch("git_stage", {"paths": ["a.c"]}).success
    continued = runtime.dispatch(
        "git_cherry_pick_continue", {"resolution_note": "adapted stable API"})
    assert continued.success
    message = _git(repo, "log", "-1", "--format=%B").stdout
    assert message.startswith("upstream subject\n\nupstream body")
    assert "Signed-off-by: Up Stream" in message
    assert message.count("Backport-resolution: adapted stable API") == 1
    assert message.count("Assisted-by: openai:gpt-test") == 1
    assert not editor_marker.exists()


def test_commit_message_builder_is_idempotent_and_preserves_original():
    original = (
        "subject\n\nbody\n\n(cherry picked from commit abc)\n\n"
        " Backport-Resolution: spoofed note\n\n"
        "\tASSISTED-BY: OPENAI:spoofed-model\n\n"
        "Backport-resolution: old note\n\nAssisted-by: openai:old-model\n")
    first = build_cherry_pick_message(original, "new note", "new-model")
    second = build_cherry_pick_message(first, "new note", "new-model")
    assert first == second
    assert first.startswith("subject\n\nbody\n\n(cherry picked from commit abc)")
    assert first.count("Backport-resolution:") == 1
    assert first.count("Assisted-by: openai:") == 1


def test_abort_and_skip_require_active_cherry_pick(repository):
    repo, _, _ = repository
    runtime = _runtime(repo, {"a.c"})
    for tool in ("git_cherry_pick_abort", "git_cherry_pick_skip"):
        result = runtime.dispatch(tool, {})
        assert not result.success and result.error_kind == "policy"
    assert runtime.mutation_generation == 0


@pytest.mark.parametrize("action", ["abort", "skip"])
def test_abort_and_skip_active_single_conflict(repository, action):
    repo, before, branch = repository
    source = _make_source_commit(repo, branch)
    (repo / "a.c").write_text("stable\n", encoding="utf-8")
    _git(repo, "add", "--", "a.c")
    before = _commit(repo, "stable")
    runtime = _runtime(repo, {"a.c"})
    runtime.dispatch("git_cherry_pick_start", {"revision": source})
    result = runtime.dispatch(f"git_cherry_pick_{action}", {})
    assert result.success
    assert _git(repo, "rev-parse", "HEAD").stdout.strip() == before
    assert not (repo / ".git" / "CHERRY_PICK_HEAD").exists()


@pytest.mark.parametrize("action", ["abort", "skip"])
def test_abort_and_skip_refuse_unrelated_tracked_changes(repository, action):
    repo, _, branch = repository
    source = _make_source_commit(repo, branch)
    (repo / "a.c").write_text("stable\n", encoding="utf-8")
    _git(repo, "add", "--", "a.c")
    before = _commit(repo, "stable")
    runtime = _runtime(repo, {"a.c", "b.c"})
    runtime.dispatch("git_cherry_pick_start", {"revision": source})
    (repo / "b.c").write_text("unrelated user edit\n", encoding="utf-8")
    result = runtime.dispatch(f"git_cherry_pick_{action}", {})
    assert not result.success and result.error_kind == "policy"
    assert result.payload["rejected_paths"] == ["b.c"]
    assert _git(repo, "rev-parse", "HEAD").stdout.strip() == before
    assert (repo / "b.c").read_text(encoding="utf-8") == "unrelated user edit\n"
    assert (repo / ".git" / "CHERRY_PICK_HEAD").exists()


def test_unauthorized_staged_path_is_caught_before_continue(repository):
    repo, _, branch = repository
    source = _make_source_commit(repo, branch)
    (repo / "a.c").write_text("stable\n", encoding="utf-8")
    _git(repo, "add", "--", "a.c")
    _commit(repo, "stable")
    runtime = _runtime(repo, {"a.c"})
    runtime.dispatch("git_cherry_pick_start", {"revision": source})
    runtime.dispatch("git_restore_conflict", {"path": "a.c", "side": "theirs"})
    runtime.dispatch("git_stage", {"paths": ["a.c"]})
    (repo / "outside.c").write_text("outside\n", encoding="utf-8")
    _git(repo, "add", "--", "outside.c")
    result = runtime.dispatch("git_cherry_pick_continue", {})
    assert not result.success and result.error_kind == "policy"
    assert result.payload["rejected_paths"] == ["outside.c"]
    assert (repo / ".git" / "CHERRY_PICK_HEAD").exists()


def test_allowed_but_unexpected_staged_path_is_caught_before_continue(repository):
    repo, _, branch = repository
    source = _make_source_commit(repo, branch)
    (repo / "a.c").write_text("stable\n", encoding="utf-8")
    _git(repo, "add", "--", "a.c")
    _commit(repo, "stable")
    runtime = _runtime(repo, {"a.c", "b.c"})
    runtime.dispatch("git_cherry_pick_start", {"revision": source})
    runtime.dispatch("git_restore_conflict", {"path": "a.c", "side": "theirs"})
    runtime.dispatch("git_stage", {"paths": ["a.c"]})
    (repo / "b.c").write_text("unexpected\n", encoding="utf-8")
    _git(repo, "add", "--", "b.c")
    result = runtime.dispatch("git_cherry_pick_continue", {})
    assert not result.success and result.error_kind == "policy"
    assert result.payload["rejected_paths"] == ["b.c"]
    assert (repo / ".git" / "CHERRY_PICK_HEAD").exists()


def test_missing_tracked_symlink_cannot_be_staged_by_typed_tool(repository):
    repo, _, _ = repository
    (repo / "a.c").unlink()
    (repo / "a.c").symlink_to("b.c")
    _git(repo, "add", "--", "a.c")
    _commit(repo, "tracked symlink")
    (repo / "a.c").unlink()
    runtime = _runtime(repo, {"a.c"})
    result = runtime.dispatch("git_stage", {"paths": ["a.c"]})
    assert not result.success and result.error_kind == "policy"


def test_symlink_staged_outside_runtime_is_caught_before_continue(repository):
    repo, _, branch = repository
    source = _make_source_commit(repo, branch)
    (repo / "a.c").write_text("stable\n", encoding="utf-8")
    _git(repo, "add", "--", "a.c")
    _commit(repo, "stable")
    runtime = _runtime(repo, {"a.c"})
    runtime.dispatch("git_cherry_pick_start", {"revision": source})
    (repo / "a.c").unlink()
    (repo / "a.c").symlink_to("b.c")
    _git(repo, "add", "--", "a.c")
    result = runtime.dispatch("git_cherry_pick_continue", {})
    assert not result.success and result.error_kind == "policy"
    assert result.payload["rejected_paths"] == ["a.c"]


@pytest.mark.parametrize("kind", ["hardlink", "fifo", "oversized"])
def test_hostile_cherry_pick_message_is_refused_without_external_mutation(
        repository, tmp_path, kind):
    if kind == "fifo" and not hasattr(os, "mkfifo"):
        pytest.skip("requires POSIX FIFOs")
    repo, _, branch = repository
    source = _make_source_commit(repo, branch)
    (repo / "a.c").write_text("stable\n", encoding="utf-8")
    _git(repo, "add", "--", "a.c")
    _commit(repo, "stable")
    runtime = _runtime(repo, {"a.c"})
    runtime.dispatch("git_cherry_pick_start", {"revision": source})
    runtime.dispatch("git_restore_conflict", {"path": "a.c", "side": "theirs"})
    runtime.dispatch("git_stage", {"paths": ["a.c"]})
    message = repo / ".git" / "MERGE_MSG"
    message.unlink()
    outside = tmp_path / "outside-message"
    outside.write_text("must survive\n", encoding="utf-8")
    if kind == "hardlink":
        os.link(outside, message)
    elif kind == "fifo":
        os.mkfifo(message)
    else:
        message.write_bytes(b"x" * (MAX_GIT_MESSAGE_BYTES + 1))
    started = time.monotonic()
    result = runtime.dispatch("git_cherry_pick_continue", {})
    assert time.monotonic() - started < 1
    assert not result.success
    assert result.error_kind in {"policy", "operation"}
    assert outside.read_text(encoding="utf-8") == "must survive\n"
    assert (repo / ".git" / "CHERRY_PICK_HEAD").exists()


def test_oversized_sequencer_metadata_cannot_enable_skip(repository):
    repo, _, branch = repository
    source = _make_source_commit(repo, branch)
    (repo / "a.c").write_text("stable\n", encoding="utf-8")
    _git(repo, "add", "--", "a.c")
    _commit(repo, "stable")
    runtime = _runtime(repo, {"a.c"})
    runtime.dispatch("git_cherry_pick_start", {"revision": source})
    sequencer = repo / ".git" / "sequencer"
    sequencer.mkdir()
    (sequencer / "todo").write_bytes(b"x" * (64 * 1024 + 1))
    result = runtime.dispatch("git_cherry_pick_skip", {})
    assert not result.success and result.error_kind == "operation"
    assert (repo / ".git" / "CHERRY_PICK_HEAD").exists()


def test_scope_hook_remains_defense_in_depth_for_unauthorized_staging(repository):
    repo, _, _ = repository
    install_scope_hook(repo, {"a.c"})
    try:
        (repo / "outside.c").write_text("outside\n", encoding="utf-8")
        _git(repo, "add", "--", "outside.c")
        rejected = _git(repo, "commit", "-m", "outside", check=False)
        assert rejected.returncode != 0
        assert "BLOCKED by CVE agent" in rejected.stderr
    finally:
        remove_scope_hook(repo)


def test_scope_hook_catches_unauthorized_file_added_after_final_preflight(repository):
    repo, _, branch = repository
    source = _make_source_commit(repo, branch)
    (repo / "a.c").write_text("stable\n", encoding="utf-8")
    _git(repo, "add", "--", "a.c")
    _commit(repo, "stable")
    runtime = _runtime(repo, {"a.c"})
    runtime.dispatch("git_cherry_pick_start", {"revision": source})
    runtime.dispatch("git_restore_conflict", {"path": "a.c", "side": "theirs"})
    runtime.dispatch("git_stage", {"paths": ["a.c"]})
    (repo / "outside.c").write_text("outside\n", encoding="utf-8")

    original_run = runtime._executor.run
    introduced = False

    def introduce_after_preflight(operation, argv, output_limit=None):
        nonlocal introduced
        if operation == "cherry_pick_continue" and not introduced:
            introduced = True
            _git(repo, "add", "--", "outside.c")
        return original_run(operation, argv, output_limit)

    install_scope_hook(repo, {"a.c"})
    try:
        with patch.object(runtime._executor, "run", side_effect=introduce_after_preflight):
            result = runtime.dispatch("git_cherry_pick_continue", {})
        assert not result.success and result.error_kind == "operation"
        assert "BLOCKED by CVE agent" in result.payload["error"]
        assert (repo / ".git" / "CHERRY_PICK_HEAD").exists()
    finally:
        remove_scope_hook(repo)


def test_session_snapshot_captures_head_and_initial_operation_state(repository):
    repo, head, _ = repository
    runtime = _runtime(repo, {"a.c"})
    assert runtime.repository_snapshot.head == head
    assert runtime.repository_snapshot.operations == {
        "cherry_pick": False, "merge": False, "rebase": False, "revert": False,
    }


def test_executor_bounds_output_and_enforces_timeout(tmp_path):
    repo = tmp_path / "executor"
    repo.mkdir()
    noisy = tmp_path / "fake-git"
    noisy.write_text(
        "#!/usr/bin/env python3\n"
        "import sys, time\n"
        "if sys.argv[-1] == 'slow':\n"
        "    time.sleep(10)\n"
        "else:\n"
        "    sys.stdout.write('x' * 10000)\n",
        encoding="utf-8",
    )
    noisy.chmod(noisy.stat().st_mode | stat.S_IXUSR)
    limits = GitToolLimits(max_output_bytes=64, max_command_seconds=1)
    executor = GitCommandExecutor(repo, SessionDeadline.from_timeout(5), limits)
    with patch("cve_agent.openai_git_tools.GIT_EXECUTABLE", str(noisy)):
        bounded = executor.run("status", ["status"])
        started = time.monotonic()
        timed = executor.run("status", ["status", "slow"])
    assert len(bounded.stdout.encode()) == 64
    assert bounded.stdout_truncated is True
    assert timed.timed_out is True
    assert time.monotonic() - started < 3


def test_no_forbidden_git_forms_appear_in_runtime_source():
    source = Path(__file__).parents[2] / "cve_agent" / "openai_git_tools.py"
    text = source.read_text(encoding="utf-8")
    for forbidden in (
        "reset --hard", "clean -", "push --force",
        "hooksPath", "submodule update", "submodule foreach",
    ):
        assert forbidden not in text


def test_audit_records_paths_and_revision_without_message_content(repository):
    repo, head, _ = repository
    runtime = _runtime(repo, {"a.c"})
    shown = runtime.dispatch("git_show", {"revision": head, "paths": ["a.c"]})
    audit = shown.audit.to_dict()
    assert audit["revision"] == head
    assert audit["paths"] == ["a.c"]
    assert "base subject" not in str(audit)
