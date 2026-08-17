# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for native build, approval, deadline, and finish host tools."""
import hashlib
import io
import json
import os
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from cve_agent.openai_deadline import RuntimeTimeoutError, SessionDeadline
from cve_agent.openai_host_tools import (
    BUILD_LOG_NAME,
    COMPLETE_TOOL_CONTRACTS,
    MAX_BUILD_LOG_BYTES,
    MAX_BUILD_TAIL_BYTES,
    ApprovalDecision,
    BuildCommandResult,
    ConsoleApprovalProvider,
    ControlledBuildRunner,
    OpenAIHostToolRuntime,
    TrustedAgentDirectory,
    complete_openai_tool_schemas,
)
from cve_agent.openai_tools import ToolPolicyError
from cve_agent.orchestrator import _read_conclusion, _read_escalation


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


@pytest.fixture
def host_repository(tmp_path):
    repo = tmp_path / "workspace" / "sources" / "recipe"
    repo.mkdir(parents=True)
    agent = tmp_path / "workspace" / "cve_agent" / "recipe"
    agent.mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "CVE Test")
    _git(repo, "config", "user.email", "cve@example.com")
    (repo / "a.c").write_text("base\n", encoding="utf-8")
    (repo / "b.c").write_text("base b\n", encoding="utf-8")
    _git(repo, "add", "--", "a.c", "b.c")
    _git(repo, "commit", "-m", "base")
    return repo, agent


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeApproval:
    def __init__(self, *decisions: ApprovalDecision) -> None:
        self.decisions = list(decisions)
        self.requests = []
        self.timeouts = []

    def request(self, request, timeout):
        self.requests.append(request)
        self.timeouts.append(timeout)
        return self.decisions.pop(0)


class FakeBuildRunner:
    def __init__(self, agent: Path, returncode: int = 0,
                 timed_out: bool = False, tail: str = "build output") -> None:
        self.agent = agent
        self.returncode = returncode
        self.timed_out = timed_out
        self.tail = tail
        self.calls = []

    def run(self, recipe: str) -> BuildCommandResult:
        self.calls.append(recipe)
        return BuildCommandResult(
            returncode=self.returncode,
            duration=1.25,
            timed_out=self.timed_out,
            tail=self.tail,
            truncated=False,
            total_output_bytes=len(self.tail.encode()),
            log_path=self.agent / BUILD_LOG_NAME,
        )


def _runtime(repo: Path, agent: Path, allowed: set[str] | None = None,
             build_runner=None, **kwargs) -> OpenAIHostToolRuntime:
    return OpenAIHostToolRuntime(
        repo,
        {"a.c"} if allowed is None else allowed,
        model="gpt-test",
        timeout_seconds=30,
        agent_root=agent,
        build_runner=build_runner or FakeBuildRunner(agent),
        **kwargs,
    )


def test_complete_schemas_are_closed_and_build_has_no_model_fields():
    schemas = {
        item["function"]["name"]: item["function"]["parameters"]
        for item in complete_openai_tool_schemas()
    }
    assert set(schemas) == set(COMPLETE_TOOL_CONTRACTS)
    assert schemas["build_recipe"]["properties"] == {}
    assert schemas["build_recipe"]["additionalProperties"] is False
    assert schemas["finish"]["properties"]["status"]["enum"] == [
        "done", "not_applicable", "needs_human"]


def test_deadline_monotonically_decreases_and_expires():
    clock = FakeClock()
    deadline = SessionDeadline.from_timeout(10, clock)
    assert deadline.remaining() == 10
    clock.advance(2.5)
    assert deadline.remaining() == 7.5
    clock.advance(8)
    assert deadline.remaining() == 0
    with pytest.raises(RuntimeTimeoutError):
        deadline.require("test")


def test_build_exact_argv_cwd_environment_log_and_generation(host_repository):
    repo, agent = host_repository
    runtime = _runtime(repo, agent, build_runner=None)
    runtime._build_runner = ControlledBuildRunner(
        repo, runtime.artifacts, runtime.deadline)
    real_popen = subprocess.Popen
    captured = {}
    script = (
        "import os,sys; "
        "print(os.getenv('OPENAI_API_KEY','absent')); "
        "print(os.getenv('AWS_SECRET_ACCESS_KEY','absent')); "
        f"print('prefix-' + 'x' * {MAX_BUILD_TAIL_BYTES + 4096}); "
        "sys.exit(0)"
    )

    def launch_safe_helper(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return real_popen([sys.executable, "-c", script], **kwargs)

    with patch.dict(os.environ, {
        "OPENAI_API_KEY": "model-secret",
        "AWS_SECRET_ACCESS_KEY": "aws-secret",
        "GITHUB_TOKEN": "github-secret",
        "GIT_SSH_COMMAND": "ssh -i /tmp/secret-key",
        "SSH_AUTH_SOCK": "/tmp/secret-agent",
        "HTTPS_PROXY": "http://user:secret@proxy.example",
    }), patch(
        "cve_agent.openai_host_tools.subprocess.Popen",
        side_effect=launch_safe_helper,
    ):
        result = runtime.dispatch("build_recipe", {})

    assert result.success
    assert captured["command"] == ["devtool", "build", "recipe"]
    assert captured["kwargs"]["cwd"] == repo.resolve()
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["start_new_session"] is True
    environment = captured["kwargs"]["env"]
    assert "OPENAI_API_KEY" not in environment
    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert "GITHUB_TOKEN" not in environment
    assert "GIT_SSH_COMMAND" not in environment
    assert "SSH_AUTH_SOCK" not in environment
    assert "HTTPS_PROXY" not in environment
    assert environment["LC_ALL"] == "C"
    assert runtime.validated_generation == 0
    assert result.payload["truncated"] is True
    assert len(result.payload["tail"].encode()) <= MAX_BUILD_TAIL_BYTES
    log_path = agent / BUILD_LOG_NAME
    log_text = log_path.read_text(encoding="utf-8")
    assert "prefix-" in log_text
    assert "model-secret" not in log_text
    assert stat.S_IMODE(log_path.stat().st_mode) == 0o600


def test_build_log_hardlink_is_refused_without_truncating_target(
        host_repository, tmp_path):
    repo, agent = host_repository
    outside = tmp_path / "outside.log"
    outside.write_text("must survive\n", encoding="utf-8")
    os.link(outside, agent / BUILD_LOG_NAME)
    runtime = _runtime(repo, agent, build_runner=None)
    runtime._build_runner = ControlledBuildRunner(
        repo, runtime.artifacts, runtime.deadline)
    with patch("cve_agent.openai_host_tools.subprocess.Popen") as popen:
        result = runtime.dispatch("build_recipe", {})
    assert not result.success and result.error_kind == "policy"
    assert outside.read_text(encoding="utf-8") == "must survive\n"
    popen.assert_not_called()


def test_build_log_is_bounded_while_output_is_fully_drained(host_repository):
    repo, agent = host_repository
    runtime = _runtime(repo, agent, build_runner=None)
    runtime._build_runner = ControlledBuildRunner(
        repo, runtime.artifacts, runtime.deadline)
    real_popen = subprocess.Popen
    output = "z" * 512

    def launch_helper(command, **kwargs):
        return real_popen(
            [sys.executable, "-c", f"print({output!r}, end='')"], **kwargs)

    with patch("cve_agent.openai_host_tools.MAX_BUILD_LOG_BYTES", 64), patch(
        "cve_agent.openai_host_tools.subprocess.Popen", side_effect=launch_helper,
    ):
        result = runtime.dispatch("build_recipe", {})
    assert result.success
    assert result.payload["total_output_bytes"] == len(output)
    assert result.payload["log_truncated"] is True
    assert (agent / BUILD_LOG_NAME).stat().st_size == 64
    assert MAX_BUILD_LOG_BYTES > 64


def test_build_log_writer_retries_partial_writes_and_rejects_no_progress():
    class PartialWriter(io.BytesIO):
        def write(self, data):
            return super().write(bytes(data[:2]))

    writer = PartialWriter()
    ControlledBuildRunner._write_all(writer, b"abcdef")
    assert writer.getvalue() == b"abcdef"

    class StalledWriter(io.BytesIO):
        def write(self, data):
            return 0

    with pytest.raises(OSError, match="short build log write"):
        ControlledBuildRunner._write_all(StalledWriter(), b"x")


def test_nonzero_exit_beats_textual_success(host_repository):
    repo, agent = host_repository
    runner = FakeBuildRunner(agent, returncode=3, tail="BUILD SUCCESSFUL")
    runtime = _runtime(repo, agent, build_runner=runner)
    result = runtime.dispatch("build_recipe", {})
    assert not result.success and result.error_kind == "operation"
    assert result.payload["exit_status"] == 3
    assert runtime.validated_generation is None


def test_timed_out_build_returns_partial_output_and_no_validation(host_repository):
    repo, agent = host_repository
    runner = FakeBuildRunner(
        agent, returncode=-signal.SIGKILL, timed_out=True, tail="partial")
    runtime = _runtime(repo, agent, build_runner=runner)
    result = runtime.dispatch("build_recipe", {})
    assert not result.success and result.error_kind == "timeout"
    assert result.payload["tail"] == "partial"
    assert result.payload["timed_out"] is True
    assert runtime.validated_generation is None


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX process groups")
def test_real_build_timeout_terminates_group_forcibly_and_reaps(host_repository):
    repo, agent = host_repository
    deadline = SessionDeadline.from_timeout(0.2)
    runner = ControlledBuildRunner(
        repo, TrustedAgentDirectory(agent), deadline, termination_grace=0.1)
    real_popen = subprocess.Popen
    processes = []
    script = (
        "import signal,time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "print('partial-before-timeout', flush=True); "
        "time.sleep(10)"
    )

    def launch_helper(command, **kwargs):
        process = real_popen([sys.executable, "-c", script], **kwargs)
        processes.append(process)
        return process

    started = time.monotonic()
    with patch(
        "cve_agent.openai_host_tools.subprocess.Popen",
        side_effect=launch_helper,
    ):
        result = runner.run("recipe")
    assert time.monotonic() - started < 3
    assert result.timed_out is True
    assert result.returncode == -signal.SIGKILL
    assert "partial-before-timeout" in result.tail
    assert processes[0].poll() is not None
    assert "partial-before-timeout" in (agent / BUILD_LOG_NAME).read_text()


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX process groups")
def test_build_timeout_kills_group_after_leader_exits(host_repository):
    repo, agent = host_repository
    deadline = SessionDeadline.from_timeout(0.2)
    runner = ControlledBuildRunner(
        repo, TrustedAgentDirectory(agent), deadline, termination_grace=0.1)
    real_popen = subprocess.Popen
    child_script = (
        "import signal,time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "print('descendant-alive', flush=True); "
        "time.sleep(3)"
    )
    leader_script = (
        "import subprocess,sys; "
        f"subprocess.Popen([sys.executable, '-c', {child_script!r}])"
    )

    def launch_helper(command, **kwargs):
        return real_popen([sys.executable, "-c", leader_script], **kwargs)

    started = time.monotonic()
    with patch(
        "cve_agent.openai_host_tools.subprocess.Popen",
        side_effect=launch_helper,
    ):
        result = runner.run("recipe")
    assert time.monotonic() - started < 1.5
    assert result.timed_out is True
    assert "descendant-alive" in result.tail


def test_interactive_build_approval_once(host_repository):
    repo, agent = host_repository
    approval = FakeApproval(ApprovalDecision.APPROVE_ONCE)
    runner = FakeBuildRunner(agent)
    runtime = _runtime(
        repo, agent, build_runner=runner, interactive=True,
        approval_provider=approval)
    result = runtime.dispatch("build_recipe", {})
    assert result.success and runner.calls == ["recipe"]
    assert approval.requests[0].summary == "devtool build recipe"


def test_interactive_denial_is_structured_and_prevents_side_effect(host_repository):
    repo, agent = host_repository
    approval = FakeApproval(ApprovalDecision.DENY)
    runner = FakeBuildRunner(agent)
    runtime = _runtime(
        repo, agent, build_runner=runner, interactive=True,
        approval_provider=approval)
    result = runtime.dispatch("build_recipe", {})
    assert not result.success and result.error_kind == "approval"
    assert runner.calls == []


def test_interactive_commit_denial_is_structured_and_does_not_stage(host_repository):
    repo, agent = host_repository
    before = _git(repo, "rev-parse", "HEAD").stdout.strip()
    (repo / "a.c").write_text("repair\n", encoding="utf-8")
    approval = FakeApproval(ApprovalDecision.DENY)
    runtime = _runtime(
        repo, agent, interactive=True, approval_provider=approval)
    result = runtime.dispatch("git_commit", {
        "paths": ["a.c"], "message": "repair"})
    serialized = result.to_dict()
    assert not result.success and serialized["error_kind"] == "approval"
    assert serialized["mutated"] is False
    assert approval.requests[0].category == "git_mutation"
    assert "a.c" in approval.requests[0].summary
    assert _git(repo, "rev-parse", "HEAD").stdout.strip() == before
    assert _git(repo, "diff", "--cached", "--name-only").stdout == ""


def test_interactive_large_patch_approval_and_denial_are_bounded(host_repository):
    repo, agent = host_repository
    target = repo / "a.c"
    old = target.read_text(encoding="utf-8")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    arguments = {
        "path": "a.c", "expected_sha256": digest,
        "hunks": [{"old_text": old, "replacement": "patched\n"}],
    }
    denied_approval = FakeApproval(ApprovalDecision.DENY)
    denied_runtime = _runtime(
        repo, agent, interactive=True, approval_provider=denied_approval)
    denied = denied_runtime.dispatch("apply_patch_hunks", arguments)
    assert not denied.success and denied.error_kind == "approval"
    assert target.read_text(encoding="utf-8") == old
    request = denied_approval.requests[0]
    assert request.operation == "apply_patch_hunks"
    assert digest in request.summary
    assert "@@ bounded-hunk 1 @@" in request.summary
    assert len(request.summary) <= 512

    approved = FakeApproval(ApprovalDecision.APPROVE_ONCE)
    approved_runtime = _runtime(
        repo, agent, interactive=True, approval_provider=approved)
    result = approved_runtime.dispatch("apply_patch_hunks", arguments)
    assert result.success
    assert target.read_text(encoding="utf-8") == "patched\n"


def test_interactive_amend_denial_is_structured_and_does_not_stage(host_repository):
    repo, agent = host_repository
    (repo / "a.c").write_text("selected fix\n", encoding="utf-8")
    _git(repo, "add", "--", "a.c")
    _git(repo, "commit", "-m", "selected fix")
    before = _git(repo, "rev-parse", "HEAD").stdout.strip()
    (repo / "a.c").write_text("repair\n", encoding="utf-8")
    approval = FakeApproval(ApprovalDecision.DENY)
    runtime = _runtime(
        repo, agent, interactive=True, approval_provider=approval)
    result = runtime.dispatch("git_amend", {
        "paths": ["a.c"], "message_mode": "no_edit"})
    assert not result.success and result.error_kind == "approval"
    assert approval.requests[0].category == "git_mutation"
    assert _git(repo, "rev-parse", "HEAD").stdout.strip() == before
    assert _git(repo, "diff", "--cached", "--name-only").stdout == ""


def test_approve_class_suppresses_later_prompts(host_repository):
    repo, agent = host_repository
    approval = FakeApproval(ApprovalDecision.APPROVE_CLASS)
    runner = FakeBuildRunner(agent)
    runtime = _runtime(
        repo, agent, build_runner=runner, interactive=True,
        approval_provider=approval)
    assert runtime.dispatch("build_recipe", {}).success
    assert runtime.dispatch("build_recipe", {}).success
    assert len(approval.requests) == 1
    assert runner.calls == ["recipe", "recipe"]


def test_console_approval_fails_closed_for_non_tty():
    provider = ConsoleApprovalProvider(io.StringIO("y\n"), io.StringIO())
    decision = provider.request(None, 10)  # type: ignore[arg-type]
    assert decision is ApprovalDecision.DENY


def test_approval_timeout_is_distinct(host_repository):
    repo, agent = host_repository
    approval = FakeApproval(ApprovalDecision.TIMEOUT)
    runner = FakeBuildRunner(agent)
    runtime = _runtime(
        repo, agent, build_runner=runner, interactive=True,
        approval_provider=approval)
    result = runtime.dispatch("build_recipe", {})
    assert not result.success and result.error_kind == "timeout"
    assert runner.calls == []


def test_read_only_tool_does_not_prompt(host_repository):
    repo, agent = host_repository
    approval = FakeApproval()
    runtime = _runtime(
        repo, agent, interactive=True, approval_provider=approval)
    result = runtime.dispatch("read_file", {"path": "a.c"})
    assert result.success
    assert approval.requests == []


def test_file_approval_summary_uses_trusted_stats_not_content(host_repository):
    repo, agent = host_repository
    approval = FakeApproval(ApprovalDecision.APPROVE_ONCE)
    runtime = _runtime(
        repo, agent, interactive=True, approval_provider=approval)
    secret = "do-not-display-content"
    result = runtime.dispatch("write_file", {
        "path": "a.c", "content": secret, "mode": "replace_only"})
    assert result.success
    shown = approval.requests[0].summary
    assert "a.c" in shown and f"{len(secret)} bytes" in shown
    assert secret not in shown


def test_approval_summary_escapes_terminal_control_characters(host_repository):
    repo, agent = host_repository
    unusual_path = "odd\x1b[31m.c"
    (repo / unusual_path).write_text("base\n", encoding="utf-8")
    approval = FakeApproval(ApprovalDecision.APPROVE_ONCE)
    runtime = _runtime(
        repo, agent, allowed={unusual_path}, interactive=True,
        approval_provider=approval)
    result = runtime.dispatch("write_file", {
        "path": unusual_path, "content": "changed\n", "mode": "replace_only"})
    assert result.success
    assert "\x1b" not in approval.requests[0].summary
    assert "\\u001b" in approval.requests[0].summary


def test_build_is_invalidated_by_later_file_mutation(host_repository):
    repo, agent = host_repository
    runtime = _runtime(repo, agent)
    assert runtime.dispatch("build_recipe", {}).success
    assert runtime.dispatch("write_file", {
        "path": "a.c", "content": "changed\n", "mode": "replace_only"}).success
    result = runtime.dispatch("finish", {
        "status": "done", "reason": "complete", "summary": "built"})
    assert not result.success
    assert "predates" in result.payload["error"]


def test_build_is_invalidated_by_later_large_patch_hunk(host_repository):
    repo, agent = host_repository
    target = repo / "a.c"
    runtime = _runtime(repo, agent)
    assert runtime.dispatch("build_recipe", {}).success
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    patched = runtime.dispatch("apply_patch_hunks", {
        "path": "a.c", "expected_sha256": digest,
        "hunks": [{"old_text": "base\n", "replacement": "fixed\n"}],
    })
    assert patched.success
    result = runtime.dispatch("finish", {
        "status": "done", "reason": "complete", "summary": "stale"})
    assert not result.success
    assert "predates" in result.payload["error"]


def test_staging_already_built_content_does_not_invalidate_build(host_repository):
    repo, agent = host_repository
    runtime = _runtime(repo, agent)
    assert runtime.dispatch("write_file", {
        "path": "a.c", "content": "changed\n", "mode": "replace_only"}).success
    built = runtime.dispatch("build_recipe", {})
    assert built.success
    generation = runtime.mutation_generation
    assert runtime.dispatch("git_stage", {"paths": ["a.c"]}).success
    assert runtime.mutation_generation == generation
    assert runtime.validated_generation == generation


def test_amend_after_successful_build_records_built_source_without_staling_it(
        host_repository):
    repo, agent = host_repository
    branch = _git(repo, "branch", "--show-current").stdout.strip()
    _git(repo, "switch", "-q", "-c", "source")
    (repo / "a.c").write_text("upstream\n", encoding="utf-8")
    _git(repo, "add", "--", "a.c")
    _git(repo, "commit", "-m", "upstream")
    source = _git(repo, "rev-parse", "HEAD").stdout.strip()
    _git(repo, "switch", "-q", branch)

    runtime = _runtime(repo, agent)
    picked = runtime.dispatch("git_cherry_pick_start", {"revision": source})
    assert picked.success and picked.payload["conflicted"] is False
    edited = runtime.dispatch("write_file", {
        "path": "a.c", "content": "portable upstream\n", "mode": "replace_only"})
    assert edited.success
    built = runtime.dispatch("build_recipe", {})
    generation = runtime.mutation_generation
    assert built.success and runtime.validated_generation == generation
    amended = runtime.dispatch("git_amend", {
        "paths": ["a.c"], "message_mode": "no_edit"})
    assert amended.success and amended.mutated
    transition = amended.payload["trusted_transition"]
    assert transition["old_head"] != transition["new_head"]
    assert transition["operation"] == "amend"
    assert all(transition["invariants"].values())
    assert runtime.trusted_git_state.trusted_head == transition["new_head"]
    assert runtime.trusted_git_state.last_host_git_operation == "amend"
    assert runtime.trusted_git_state.transition_count == 2
    assert runtime.mutation_generation == generation
    assert runtime.validated_generation == generation
    assert runtime.trusted_git_state.built_generation == generation
    finished = runtime.dispatch("finish", {
        "status": "done", "reason": "built repair committed",
        "summary": "portable fix"})
    assert finished.success and finished.terminal
    assert _git(repo, "status", "--porcelain").stdout == ""
    assert _git(repo, "show", "HEAD:a.c").stdout == "portable upstream\n"


def test_edit_amend_build_finish_succeeds(host_repository):
    repo, agent = host_repository
    (repo / "a.c").write_text("selected fix\n", encoding="utf-8")
    _git(repo, "add", "--", "a.c")
    _git(repo, "commit", "-m", "selected fix")
    runtime = _runtime(repo, agent)
    assert runtime.dispatch("write_file", {
        "path": "a.c", "content": "repaired fix\n", "mode": "replace_only",
    }).success
    assert runtime.dispatch("git_amend", {
        "paths": ["a.c"], "message_mode": "no_edit"}).success
    assert runtime.dispatch("build_recipe", {}).success
    finished = runtime.dispatch("finish", {
        "status": "done", "reason": "verified", "summary": "amended repair"})
    assert finished.success
    assert _git(repo, "show", "HEAD:a.c").stdout == "repaired fix\n"
    assert _git(repo, "status", "--porcelain").stdout == ""


def test_build_edit_amend_finish_is_rejected_as_stale(host_repository):
    repo, agent = host_repository
    (repo / "a.c").write_text("selected fix\n", encoding="utf-8")
    _git(repo, "add", "--", "a.c")
    _git(repo, "commit", "-m", "selected fix")
    runtime = _runtime(repo, agent)
    assert runtime.dispatch("build_recipe", {}).success
    assert runtime.dispatch("write_file", {
        "path": "a.c", "content": "later repair\n", "mode": "replace_only",
    }).success
    assert runtime.dispatch("git_amend", {
        "paths": ["a.c"], "message_mode": "no_edit"}).success
    finished = runtime.dispatch("finish", {
        "status": "done", "reason": "claim", "summary": "stale"})
    assert not finished.success
    assert "predates" in finished.payload["error"]


def test_followup_commit_after_successful_build_does_not_stale_validation(
        host_repository):
    repo, agent = host_repository
    runtime = _runtime(repo, agent)
    edited = runtime.dispatch("write_file", {
        "path": "a.c", "content": "follow-up repair\n", "mode": "replace_only"})
    assert edited.success
    built = runtime.dispatch("build_recipe", {})
    generation = runtime.mutation_generation
    assert built.success and runtime.validated_generation == generation
    committed = runtime.dispatch("git_commit", {
        "paths": ["a.c"], "message": "record follow-up repair"})
    assert committed.success and runtime.mutation_generation == generation
    finished = runtime.dispatch("finish", {
        "status": "done", "reason": "built follow-up committed",
        "summary": "follow-up fix"})
    assert finished.success and finished.terminal
    assert _git(repo, "show", "HEAD:a.c").stdout == "follow-up repair\n"
    assert _git(repo, "status", "--porcelain").stdout == ""


def test_done_accepted_after_current_generation_build(host_repository):
    repo, agent = host_repository
    runtime = _runtime(repo, agent)
    assert runtime.dispatch("build_recipe", {}).success
    result = runtime.dispatch("finish", {
        "status": "done", "reason": "verification complete",
        "summary": "recipe builds"})
    assert result.success and result.terminal
    assert runtime.terminal_status == "done"
    assert runtime.session_result().resolved is True


def test_done_removes_stale_conclusion_instead_of_trusting_it(host_repository):
    repo, agent = host_repository
    (agent / "conclusion.json").write_text(
        '{"not_applicable":true,"reason":"model claim"}\n', encoding="utf-8")
    runtime = _runtime(repo, agent)
    runtime.dispatch("build_recipe", {})
    result = runtime.dispatch("finish", {
        "status": "done", "reason": "host verified", "summary": "clean"})
    assert result.success
    assert not (agent / "conclusion.json").exists()


def test_runtime_initialization_removes_stale_conclusion(host_repository):
    repo, agent = host_repository
    conclusion = agent / "conclusion.json"
    conclusion.write_text(
        '{"not_applicable":true,"reason":"stale claim"}\n', encoding="utf-8")
    _runtime(repo, agent)
    assert not conclusion.exists()


def test_done_rejected_without_successful_build(host_repository):
    repo, agent = host_repository
    runtime = _runtime(repo, agent)
    result = runtime.dispatch("finish", {
        "status": "done", "reason": "claim", "summary": "claim"})
    assert not result.success and result.error_kind == "policy"
    assert "no successful" in result.payload["error"]


def test_done_rejected_after_failed_build(host_repository):
    repo, agent = host_repository
    runtime = _runtime(
        repo, agent, build_runner=FakeBuildRunner(agent, returncode=1))
    assert not runtime.dispatch("build_recipe", {}).success
    result = runtime.dispatch("finish", {
        "status": "done", "reason": "claim", "summary": "claim"})
    assert not result.success and result.error_kind == "policy"
    assert "no successful" in result.payload["error"]


def test_done_rejected_for_active_operation(host_repository):
    repo, agent = host_repository
    runtime = _runtime(repo, agent)
    runtime.dispatch("build_recipe", {})
    (repo / ".git" / "CHERRY_PICK_HEAD").write_text("deadbeef\n", encoding="utf-8")
    result = runtime.dispatch("finish", {
        "status": "done", "reason": "claim", "summary": "claim"})
    assert not result.success
    assert result.payload["operations"] == ["cherry_pick"]


def test_done_rejected_for_unmerged_index_without_operation(host_repository):
    repo, agent = host_repository
    runtime = _runtime(repo, agent)
    runtime.dispatch("build_recipe", {})
    base = _git(repo, "hash-object", "a.c").stdout.strip()
    ours = _git(repo, "hash-object", "-w", "--stdin", input_text="ours\n").stdout.strip()
    theirs = _git(repo, "hash-object", "-w", "--stdin", input_text="theirs\n").stdout.strip()
    index_info = (
        f"100644 {base} 1\ta.c\n"
        f"100644 {ours} 2\ta.c\n"
        f"100644 {theirs} 3\ta.c\n"
    )
    _git(repo, "update-index", "--index-info", input_text=index_info)
    result = runtime.dispatch("finish", {
        "status": "done", "reason": "claim", "summary": "claim"})
    assert not result.success
    assert result.payload["paths"] == ["a.c"]


def test_done_rejected_for_out_of_scope_committed_path(host_repository):
    repo, agent = host_repository
    runtime = _runtime(repo, agent)
    (repo / "outside.c").write_text("outside\n", encoding="utf-8")
    _git(repo, "add", "--", "outside.c")
    _git(repo, "commit", "-m", "outside")
    runtime.dispatch("build_recipe", {})
    result = runtime.dispatch("finish", {
        "status": "done", "reason": "claim", "summary": "claim"})
    assert not result.success
    assert "not produced by a typed trusted Git operation" in result.payload["error"]


def test_done_rejected_for_staged_or_unstaged_state(host_repository):
    repo, agent = host_repository
    runtime = _runtime(repo, agent)
    (repo / "a.c").write_text("changed\n", encoding="utf-8")
    _git(repo, "add", "--", "a.c")
    runtime.dispatch("build_recipe", {})
    result = runtime.dispatch("finish", {
        "status": "done", "reason": "claim", "summary": "claim"})
    assert not result.success
    assert result.payload["staged"] == ["a.c"]


def test_expired_deadline_rejects_new_work_without_fresh_budget(host_repository):
    repo, agent = host_repository
    clock = FakeClock()
    deadline = SessionDeadline.from_timeout(5, clock)
    runner = FakeBuildRunner(agent)
    runtime = _runtime(repo, agent, build_runner=runner, deadline=deadline)
    clock.advance(6)
    build = runtime.dispatch("build_recipe", {})
    finish = runtime.dispatch("finish", {
        "status": "done", "reason": "claim", "summary": "claim"})
    assert build.error_kind == "timeout" and finish.error_kind == "timeout"
    assert runner.calls == []


@pytest.mark.parametrize(
    ("status_value", "key"),
    [("not_applicable", "not_applicable"), ("needs_human", "needs_human")],
)
def test_non_code_finish_writes_trusted_orchestrator_shape(
        host_repository, status_value, key):
    repo, agent = host_repository
    runtime = _runtime(repo, agent)
    result = runtime.dispatch("finish", {
        "status": status_value, "reason": "source feature is absent"})
    assert result.success and result.terminal
    path = agent / "conclusion.json"
    assert json.loads(path.read_text()) == {key: True, "reason": "source feature is absent"}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with patch("cve_agent.orchestrator.get_agent_dir", return_value=agent):
        if status_value == "not_applicable":
            assert _read_conclusion(repo) == "source feature is absent"
            assert _read_escalation(repo) is None
        else:
            escalation = _read_escalation(repo)
            assert escalation is not None
            assert escalation.reason == "source feature is absent"
            assert _read_conclusion(repo) is None


def test_non_code_finish_requires_baseline_head_and_clean_source(host_repository):
    repo, agent = host_repository
    runtime = _runtime(repo, agent)
    (repo / "a.c").write_text("changed\n", encoding="utf-8")
    dirty = runtime.dispatch("finish", {
        "status": "needs_human", "reason": "cannot continue"})
    assert not dirty.success
    (repo / "a.c").write_text("base\n", encoding="utf-8")
    restored = runtime.dispatch("finish", {
        "status": "needs_human", "reason": "cannot continue"})
    assert restored.success


def test_non_code_finish_rejects_committed_head_change(host_repository):
    repo, agent = host_repository
    runtime = _runtime(repo, agent)
    (repo / "a.c").write_text("changed\n", encoding="utf-8")
    _git(repo, "add", "--", "a.c")
    _git(repo, "commit", "-m", "change")
    result = runtime.dispatch("finish", {
        "status": "not_applicable", "reason": "claim"})
    assert not result.success
    assert "baseline HEAD" in result.payload["error"]


@pytest.mark.parametrize("tool", ["write_file", "delete_file"])
def test_generic_file_tools_cannot_mutate_conclusion(host_repository, tool):
    repo, agent = host_repository
    (repo / "conclusion.json").write_text("old\n", encoding="utf-8")
    runtime = _runtime(repo, agent, allowed={"conclusion.json"})
    arguments = {"path": "conclusion.json"}
    if tool == "write_file":
        arguments.update({"content": "model claim", "mode": "replace_only"})
    result = runtime.dispatch(tool, arguments)
    assert not result.success and result.error_kind == "policy"


def test_conclusion_symlink_is_refused(host_repository, tmp_path):
    repo, agent = host_repository
    outside = tmp_path / "outside.json"
    outside.write_text("safe\n", encoding="utf-8")
    (agent / "conclusion.json").symlink_to(outside)
    with pytest.raises(ToolPolicyError, match="conclusion path must not be a symlink"):
        _runtime(repo, agent)
    assert outside.read_text() == "safe\n"


def test_conclusion_hardlink_is_refused_without_removing_target(
        host_repository, tmp_path):
    repo, agent = host_repository
    outside = tmp_path / "outside.json"
    outside.write_text("safe\n", encoding="utf-8")
    os.link(outside, agent / "conclusion.json")
    with pytest.raises(ToolPolicyError, match="regular file"):
        _runtime(repo, agent)
    assert outside.read_text() == "safe\n"


def test_conclusion_parent_replacement_is_refused(host_repository, tmp_path):
    repo, agent = host_repository
    runtime = _runtime(repo, agent)
    original = agent.with_name("recipe-original")
    agent.rename(original)
    outside = tmp_path / "outside-agent"
    outside.mkdir()
    agent.symlink_to(outside, target_is_directory=True)
    result = runtime.dispatch("finish", {
        "status": "needs_human", "reason": "blocked"})
    assert not result.success and result.error_kind == "policy"
    assert not (outside / "conclusion.json").exists()


def test_atomic_conclusion_failure_cleans_temporary_file(host_repository):
    repo, agent = host_repository

    def fail(_path):
        raise OSError("simulated replace race")

    runtime = _runtime(repo, agent, before_conclusion_replace=fail)
    result = runtime.dispatch("finish", {
        "status": "not_applicable", "reason": "absent"})
    assert not result.success and result.error_kind == "operation"
    assert not list(agent.glob(".cve-conclusion-*"))
    assert not (agent / "conclusion.json").exists()


def test_approval_waits_share_decreasing_deadline(host_repository):
    repo, agent = host_repository
    clock = FakeClock()
    deadline = SessionDeadline.from_timeout(10, clock)
    approval = FakeApproval(
        ApprovalDecision.APPROVE_ONCE,
        ApprovalDecision.APPROVE_ONCE,
    )
    runtime = _runtime(
        repo, agent, allowed={"a.c", "b.c"}, interactive=True,
        approval_provider=approval, deadline=deadline)
    clock.advance(1)
    runtime.dispatch("write_file", {
        "path": "a.c", "content": "a\n", "mode": "replace_only"})
    clock.advance(2)
    runtime.dispatch("write_file", {
        "path": "b.c", "content": "b\n", "mode": "replace_only"})
    assert approval.timeouts == [9, 7]


def test_terminal_outcome_also_requires_interactive_approval(host_repository):
    repo, agent = host_repository
    approval = FakeApproval(ApprovalDecision.DENY)
    runtime = _runtime(
        repo, agent, interactive=True, approval_provider=approval)
    result = runtime.dispatch("finish", {
        "status": "needs_human", "reason": "blocked"})
    assert not result.success and result.error_kind == "approval"
    assert not (agent / "conclusion.json").exists()


def test_interactive_approval_emits_trusted_audit_events(host_repository):
    repo, agent = host_repository
    approval = FakeApproval(ApprovalDecision.APPROVE_ONCE)
    events = []

    def record(kind, data):
        events.append((kind, dict(data)))

    runtime = _runtime(
        repo, agent, interactive=True, approval_provider=approval,
        event_sink=record)
    result = runtime.dispatch("finish", {
        "status": "needs_human", "reason": "blocked"})
    assert result.success
    assert [kind for kind, _ in events] == [
        "approval_request", "approval_result"]
    assert events[0][1]["category"] == "terminal"
    assert events[1][1]["decision"] == "approve_once"


def test_noninteractive_mode_is_explicitly_trusted(host_repository):
    repo, agent = host_repository
    approval = FakeApproval()
    runtime = _runtime(
        repo, agent, interactive=False, approval_provider=approval)
    result = runtime.dispatch("finish", {
        "status": "needs_human", "reason": "blocked"})
    assert result.success
    assert approval.requests == []


def test_terminal_text_is_bounded_plain_text(host_repository):
    repo, agent = host_repository
    runtime = _runtime(repo, agent)
    control = runtime.dispatch("finish", {
        "status": "needs_human", "reason": "bad\x01text"})
    oversized = runtime.dispatch("finish", {
        "status": "needs_human", "reason": "é" * 2048})
    assert control.error_kind == "validation"
    assert oversized.error_kind == "validation"


def test_recipe_is_host_derived_and_validated(host_repository):
    repo, agent = host_repository
    runner = FakeBuildRunner(agent)
    runtime = _runtime(repo, agent, build_runner=runner)
    runtime.dispatch("build_recipe", {})
    assert runner.calls == [repo.name]


@pytest.mark.parametrize("recipe", ["-leading", "../bad", "bad/name", "bad\nname", ""])
def test_unsafe_recipe_names_are_rejected_before_build(host_repository, recipe):
    repo, agent = host_repository
    runner = FakeBuildRunner(agent)
    with pytest.raises(ValueError):
        OpenAIHostToolRuntime(
            repo, {"a.c"}, "model", 30, agent,
            recipe=recipe, build_runner=runner)
    assert runner.calls == []


def test_calls_after_terminal_are_rejected(host_repository):
    repo, agent = host_repository
    runtime = _runtime(repo, agent)
    runtime.dispatch("finish", {
        "status": "needs_human", "reason": "blocked"})
    later = runtime.dispatch("git_status", {})
    assert not later.success and later.error_kind == "policy"
