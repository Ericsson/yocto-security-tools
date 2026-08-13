# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Socket-to-Git integration coverage for the native OpenAI backend."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

import pytest

from cve_agent import get_agent_dir
from cve_agent.openai_backend import OpenAICompatibleBackend, OpenAIConfig
from cve_agent.openai_client import (
    OpenAIAuthenticationError,
    OpenAIChatCompletionsClient,
    OpenAIConnectionError,
    OpenAIMalformedJSONError,
    OpenAINonRetryableHTTPError,
    OpenAINotFoundError,
    OpenAIProtocolError,
    OpenAIRequestTimeoutError,
    OpenAIResponseSizeError,
    OpenAIRetryableServerError,
    OpenAIRetryPolicy,
)
from cve_agent.openai_deadline import SessionDeadline
from cve_agent.openai_host_tools import (
    BUILD_LOG_NAME,
    ApprovalDecision,
    BuildCommandResult,
    OpenAIHostToolRuntime,
)
from cve_agent.openai_loop import JSONLTranscript, TranscriptError
from cve_agent.orchestrator import _read_conclusion, _read_escalation
from cve_agent.session import guarded_session

from .openai_test_server import (
    ScriptedHTTPResponse,
    ScriptedOpenAIServer,
    assistant_response,
    tool_call,
)


def _git(repo: Path, *arguments: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
        env={
            **os.environ,
            "GIT_EDITOR": "true",
            "GIT_SEQUENCE_EDITOR": "true",
            "GIT_TERMINAL_PROMPT": "0",
        },
    )
    if check and result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)
    return result.stdout.strip()


@dataclass(frozen=True)
class RealWorkspace:
    repo: Path
    agent: Path
    context: Path
    target: Path
    neighbor: Path
    upstream: str
    baseline: str


@pytest.fixture
def real_workspace(tmp_path: Path) -> RealWorkspace:
    """Create divergent history that produces one deterministic conflict."""
    repo = tmp_path / "build" / "workspace" / "sources" / "recipe"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.name", "Native Integration")
    _git(repo, "config", "user.email", "native-integration@example.com")
    target = repo / "recipe.c"
    neighbor = repo / "neighbor.txt"
    target.write_text("value = base;\n", encoding="utf-8")
    neighbor.write_text("must remain unchanged\n", encoding="utf-8")
    _git(repo, "add", "--", target.name, neighbor.name)
    _git(repo, "commit", "-m", "base")
    baseline = _git(repo, "rev-parse", "HEAD")
    _git(repo, "tag", "original-version", baseline)

    _git(repo, "switch", "-q", "-c", "upstream")
    target.write_text("value = upstream;\n", encoding="utf-8")
    _git(repo, "commit", "-am", "upstream security fix")
    upstream = _git(repo, "rev-parse", "HEAD")

    _git(repo, "switch", "-q", "main")
    target.write_text("value = downstream;\n", encoding="utf-8")
    _git(repo, "commit", "-am", "downstream adaptation")
    agent = get_agent_dir(repo)
    context = agent / "context.md"
    context.write_text(
        "Resolve the upstream security change in recipe.c and build it.\n",
        encoding="utf-8",
    )
    return RealWorkspace(repo, agent, context, target, neighbor, upstream, baseline)


class RecordingBuildRunner:
    def __init__(
        self, workspace: RealWorkspace, *, returncode: int = 0, timed_out: bool = False
    ) -> None:
        self.workspace = workspace
        self.returncode = returncode
        self.timed_out = timed_out
        self.calls: list[dict[str, object]] = []

    def run(self, recipe: str) -> BuildCommandResult:
        log = self.workspace.agent / BUILD_LOG_NAME
        log.write_text("deterministic build output\n", encoding="utf-8")
        self.calls.append(
            {
                "recipe": recipe,
                "content": self.workspace.target.read_text(encoding="utf-8"),
                "head": _git(self.workspace.repo, "rev-parse", "HEAD"),
            }
        )
        return BuildCommandResult(
            returncode=self.returncode,
            duration=0.01,
            timed_out=self.timed_out,
            tail="deterministic build output",
            truncated=False,
            total_output_bytes=27,
            log_path=log,
        )


class ScriptedApproval:
    def __init__(self, *decisions: ApprovalDecision) -> None:
        self.decisions = list(decisions)
        self.requests = []

    def request(self, request, timeout: float) -> ApprovalDecision:
        self.requests.append((request, timeout))
        return self.decisions.pop(0)


def _request_has_tool_results(*identifiers: str):
    def check(body: dict[str, object]) -> None:
        messages = body["messages"]
        assert isinstance(messages, list)
        results = [message for message in messages if message.get("role") == "tool"]
        assert [message["tool_call_id"] for message in results[-len(identifiers) :]] == list(
            identifiers
        )
        for message in results[-len(identifiers) :]:
            decoded = json.loads(message["content"])
            assert set(decoded) >= {"success", "mutated", "terminal", "generation"}

    return check


def _request_contract(body: dict[str, object]) -> None:
    assert set(body) == {"model", "messages", "stream", "max_tokens", "tools", "tool_choice"}
    assert body["model"] == "socket-model"
    assert body["stream"] is False
    assert body["tool_choice"] == "auto"
    tools = body["tools"]
    assert isinstance(tools, list)
    names = {tool["function"]["name"] for tool in tools}
    assert {"read_file", "replace_in_file", "git_stage", "build_recipe", "finish"} <= names
    assert all(tool["type"] == "function" for tool in tools)
    assert all(tool["function"]["parameters"]["additionalProperties"] is False for tool in tools)


def _backend(
    server: ScriptedOpenAIServer,
    workspace: RealWorkspace,
    runner: RecordingBuildRunner,
    *,
    approval=None,
    before_replace=None,
    max_steps: int = 20,
    max_tool_calls: int = 100,
) -> tuple[OpenAICompatibleBackend, dict[str, object]]:
    holder: dict[str, object] = {}

    def runtime_factory(*args, **kwargs):
        kwargs["build_runner"] = runner
        if approval is not None:
            kwargs["approval_provider"] = approval
        if before_replace is not None:
            kwargs["before_replace"] = before_replace
        runtime = OpenAIHostToolRuntime(*args, **kwargs)
        holder["runtime"] = runtime
        return runtime

    backend = OpenAICompatibleBackend(runtime_factory=runtime_factory)
    backend.configure(
        {
            "model": "socket-model",
            "openai_base_url": server.base_url,
            "openai_max_steps": max_steps,
            "openai_max_tool_calls": max_tool_calls,
            "openai_connect_timeout": 2,
            "openai_request_timeout": 2,
        },
        os.environ,
    )
    return backend, holder


def _guarded(
    workspace: RealWorkspace,
    backend: OpenAICompatibleBackend,
    *,
    interactive: bool = False,
):
    with patch("cve_agent.session.get_backend", return_value=backend):
        return guarded_session(
            workspace.context,
            workspace.repo,
            workspace.upstream,
            {"hashes": [workspace.upstream]},
            model="socket-model",
            timeout=20,
            cve_id="CVE-2099-0001",
            interactive=interactive,
            backend_name="openai",
        )


def test_socket_guarded_manual_edit_build_finish_and_request_sequence(
    real_workspace: RealWorkspace,
) -> None:
    """Exercise HTTP, loop, tools, Git, build, transcript, and outer guard."""
    workspace = real_workspace
    _git(workspace.repo, "cherry-pick", workspace.upstream, check=False)
    conflict = workspace.target.read_text(encoding="utf-8")
    assert "<<<<<<< HEAD" in conflict
    resolved = "value = secure-downstream;\n"
    neighbor_before = workspace.neighbor.read_bytes()
    runner = RecordingBuildRunner(workspace)

    actions = [
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call("context", "read_file", {"path": str(workspace.context)}),
                tool_call("status", "git_status", {}),
                tool_call(
                    "diff",
                    "git_diff",
                    {
                        "mode": "working",
                        "paths": [workspace.target.name],
                    },
                ),
                tool_call("target", "read_file", {"path": workspace.target.name}),
                content="I will inspect the trusted context and conflict.",
            ),
            check=_request_contract,
        ),
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call(
                    "replace",
                    "replace_in_file",
                    {
                        "path": workspace.target.name,
                        "old_text": conflict,
                        "new_text": resolved,
                        "expected_count": 1,
                    },
                ),
            ),
            check=_request_has_tool_results("context", "status", "diff", "target"),
        ),
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call("stage", "git_stage", {"paths": [workspace.target.name]}),
                tool_call(
                    "continue",
                    "git_cherry_pick_continue",
                    {
                        "resolution_note": "Adapted the fix to the downstream value layout.",
                    },
                ),
            ),
            check=_request_has_tool_results("replace"),
        ),
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call("build", "build_recipe", {}),
            ),
            check=_request_has_tool_results("stage", "continue"),
        ),
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call(
                    "finish",
                    "finish",
                    {
                        "status": "done",
                        "reason": "security fix committed and build passed",
                        "summary": "adapted upstream fix",
                    },
                ),
            ),
            check=_request_has_tool_results("build"),
        ),
    ]

    with ScriptedOpenAIServer(actions) as server:
        backend, holder = _backend(server, workspace, runner)
        result = _guarded(workspace, backend)
        requests = list(server.requests)

    assert result.resolved and result.transcript_path is not None
    assert len(requests) == 5
    assert all(request.method == "POST" for request in requests)
    assert all(request.path == "/v1/chat/completions" for request in requests)
    assert all(request.content_type == "application/json" for request in requests)
    assert all(request.body_bytes < 1024 * 1024 for request in requests)
    assert runner.calls == [
        {
            "recipe": "recipe",
            "content": resolved,
            "head": _git(workspace.repo, "rev-parse", "HEAD"),
        }
    ]
    assert workspace.target.read_text(encoding="utf-8") == resolved
    assert workspace.neighbor.read_bytes() == neighbor_before
    message = _git(workspace.repo, "log", "-1", "--format=%B")
    assert "Backport-resolution:" in message
    assert "Assisted-by: openai:socket-model" in message
    assert not (workspace.repo / ".git" / "hooks" / "pre-commit").exists()
    assert not (workspace.repo / ".git" / "hooks" / "cve-agent-allowed-files").exists()
    audit = workspace.agent / "recipe-CVE-2099-0001-ai-changes.log"
    assert audit.is_file()
    events = [
        json.loads(line) for line in result.transcript_path.read_text(encoding="utf-8").splitlines()
    ]
    assert events[-1]["event"] == "session_end"
    assert events[-1]["resolved"] is True
    runtime = holder["runtime"]
    assert isinstance(runtime, OpenAIHostToolRuntime)
    assert runtime.terminal_status == "done"
    requested_names = [
        call["function"]["name"]
        for request in requests
        for message in request.body["messages"]
        if message.get("role") == "assistant"
        for call in message.get("tool_calls", [])
    ]
    assert "shell" not in requested_names


def test_socket_cherry_pick_conflict_resolution_has_trusted_provenance(
    real_workspace: RealWorkspace,
) -> None:
    workspace = real_workspace
    runner = RecordingBuildRunner(workspace)
    final_content = "value = conflict-adapted;\n"
    actions = [
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call("context", "read_file", {"path": str(workspace.context)}),
                tool_call("history", "git_show", {"revision": workspace.upstream}),
                tool_call(
                    "start",
                    "git_cherry_pick_start",
                    {
                        "revision": workspace.upstream,
                    },
                ),
            )
        ),
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call("unmerged", "git_unmerged_files", {}),
                tool_call(
                    "restore",
                    "git_restore_conflict",
                    {
                        "path": workspace.target.name,
                        "side": "theirs",
                    },
                ),
                tool_call(
                    "adapt",
                    "replace_in_file",
                    {
                        "path": workspace.target.name,
                        "old_text": "value = upstream;\n",
                        "new_text": final_content,
                        "expected_count": 1,
                    },
                ),
            ),
            check=_request_has_tool_results("context", "history", "start"),
        ),
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call("stage", "git_stage", {"paths": [workspace.target.name]}),
                tool_call(
                    "continue",
                    "git_cherry_pick_continue",
                    {
                        "resolution_note": "Kept the downstream API spelling.",
                    },
                ),
            )
        ),
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call("verify", "git_show", {"revision": "HEAD"}),
                tool_call("build", "build_recipe", {}),
            )
        ),
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call(
                    "finish",
                    "finish",
                    {
                        "status": "done",
                        "reason": "conflict resolved and verified",
                    },
                ),
            )
        ),
    ]

    with ScriptedOpenAIServer(actions) as server:
        backend, _ = _backend(server, workspace, runner)
        result = backend.run_session(
            f"Read {workspace.context}",
            workspace.repo,
            {workspace.target.name},
            "socket-model",
            20,
            False,
        )

    assert result.resolved
    assert workspace.target.read_text(encoding="utf-8") == final_content
    assert _git(workspace.repo, "status", "--porcelain") == ""
    message = _git(workspace.repo, "log", "-1", "--format=%B")
    assert "(cherry picked from commit" in message
    assert "Backport-resolution: Kept the downstream API spelling." in message
    assert "Assisted-by: openai:socket-model" in message
    all_calls = [
        call["function"]["name"]
        for request in server.requests
        for message in request.body["messages"]
        if message.get("role") == "assistant"
        for call in message.get("tool_calls", [])
    ]
    assert not ({"shell", "git_reset", "git_add_all"} & set(all_calls))


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        ("not_applicable", "the affected feature is disabled"),
        ("needs_human", "the prerequisite is outside this session scope"),
    ],
)
def test_socket_transient_edit_restored_before_trusted_noncode_outcome(
    real_workspace: RealWorkspace,
    status: str,
    reason: str,
) -> None:
    workspace = real_workspace
    original = workspace.target.read_text(encoding="utf-8")
    runner = RecordingBuildRunner(workspace)
    actions = [
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call("inspect", "read_file", {"path": workspace.target.name}),
                tool_call(
                    "attempt",
                    "replace_in_file",
                    {
                        "path": workspace.target.name,
                        "old_text": original,
                        "new_text": "transient model attempt\n",
                        "expected_count": 1,
                    },
                ),
            )
        ),
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call(
                    "restore",
                    "replace_in_file",
                    {
                        "path": workspace.target.name,
                        "old_text": "transient model attempt\n",
                        "new_text": original,
                        "expected_count": 1,
                    },
                ),
            )
        ),
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call("finish", "finish", {"status": status, "reason": reason}),
            )
        ),
    ]
    with ScriptedOpenAIServer(actions) as server:
        backend, _ = _backend(server, workspace, runner)
        result = backend.run_session(
            "inspect and conclude",
            workspace.repo,
            {workspace.target.name},
            "socket-model",
            20,
            False,
        )

    conclusion = workspace.agent / "conclusion.json"
    assert result.resolved and conclusion.is_file()
    assert stat.S_IMODE(conclusion.stat().st_mode) == 0o600
    assert workspace.target.read_text(encoding="utf-8") == original
    assert _git(workspace.repo, "status", "--porcelain") == ""
    with patch("cve_agent.orchestrator.get_agent_dir", return_value=workspace.agent):
        if status == "not_applicable":
            assert _read_conclusion(workspace.repo) == reason
            assert _read_escalation(workspace.repo) is None
        else:
            escalation = _read_escalation(workspace.repo)
            assert escalation is not None
            assert escalation.reason == reason
            assert _read_conclusion(workspace.repo) is None


def test_socket_interactive_denial_recovery_and_approve_class(
    real_workspace: RealWorkspace,
) -> None:
    workspace = real_workspace
    original = workspace.target.read_text(encoding="utf-8")
    runner = RecordingBuildRunner(workspace)
    approver = ScriptedApproval(
        ApprovalDecision.DENY,
        ApprovalDecision.APPROVE_CLASS,
        ApprovalDecision.APPROVE_ONCE,
    )
    actions = [
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call(
                    "denied",
                    "replace_in_file",
                    {
                        "path": workspace.target.name,
                        "old_text": original,
                        "new_text": "first\n",
                        "expected_count": 1,
                    },
                ),
            )
        ),
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call(
                    "corrected",
                    "replace_in_file",
                    {
                        "path": workspace.target.name,
                        "old_text": original,
                        "new_text": "second\n",
                        "expected_count": 1,
                    },
                ),
                tool_call(
                    "same_class",
                    "replace_in_file",
                    {
                        "path": workspace.target.name,
                        "old_text": "second\n",
                        "new_text": original,
                        "expected_count": 1,
                    },
                ),
            ),
            check=_request_has_tool_results("denied"),
        ),
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call(
                    "finish",
                    "finish",
                    {
                        "status": "needs_human",
                        "reason": "operator review requested",
                    },
                ),
            )
        ),
    ]
    with ScriptedOpenAIServer(actions) as server:
        backend, _ = _backend(server, workspace, runner, approval=approver)
        result = backend.run_session(
            "interactive recovery",
            workspace.repo,
            {workspace.target.name},
            "socket-model",
            20,
            True,
        )
        second_request = server.requests[1].body

    assert result.resolved
    denial = json.loads(second_request["messages"][-1]["content"])
    assert denial["success"] is False
    assert denial["policy_category"] == "approval"
    assert [item[0].category for item in approver.requests] == [
        "file_mutation",
        "file_mutation",
        "terminal",
    ]


def _direct_client(
    server: ScriptedOpenAIServer,
    *,
    attempts: int = 1,
    request_timeout: int = 2,
    secret: str | None = None,
) -> OpenAIChatCompletionsClient:
    environment = {"SOCKET_TEST_KEY": secret} if secret is not None else {}
    options = {
        "model": "socket-model",
        "openai_base_url": server.base_url,
        "openai_connect_timeout": 2,
        "openai_request_timeout": request_timeout,
    }
    if secret is not None:
        options["openai_api_key_env"] = "SOCKET_TEST_KEY"
    config = OpenAIConfig.from_sources(options, environment)
    return OpenAIChatCompletionsClient(
        config,
        SessionDeadline.from_timeout(10),
        retry_policy=OpenAIRetryPolicy(max_attempts=attempts, initial_backoff=0, max_delay=0),
        environ=environment,
    )


_EMPTY_MESSAGES = [{"role": "user", "content": "respond with one tool call"}]


@pytest.mark.parametrize(
    ("status", "error_type"),
    [
        (401, OpenAIAuthenticationError),
        (404, OpenAINotFoundError),
        (500, OpenAINonRetryableHTTPError),
        (502, OpenAIRetryableServerError),
        (503, OpenAIRetryableServerError),
        (504, OpenAIRetryableServerError),
    ],
)
def test_real_http_status_mapping(status: int, error_type: type[Exception]) -> None:
    with ScriptedOpenAIServer(
        [
            ScriptedHTTPResponse(status=status, json_body={"error": {"message": "safe"}}),
        ]
    ) as server:
        client = _direct_client(server)
        with pytest.raises(error_type):
            client.complete(_EMPTY_MESSAGES, [])
        assert server.request_count == 1


def test_real_http_429_and_gateway_retry_are_bounded() -> None:
    success = assistant_response(content="portable response")
    with ScriptedOpenAIServer(
        [
            ScriptedHTTPResponse(status=429, json_body={"error": "busy"}),
            ScriptedHTTPResponse(status=503, json_body={"error": "busy"}),
            ScriptedHTTPResponse(json_body=success),
        ]
    ) as server:
        response = _direct_client(server, attempts=3).complete(_EMPTY_MESSAGES, [])
        assert response.content == "portable response"
        assert server.request_count == 3


@pytest.mark.parametrize(
    ("response", "error_type"),
    [
        (ScriptedHTTPResponse(close_connection=True), OpenAIConnectionError),
        (ScriptedHTTPResponse(raw_body=b"not-json"), OpenAIMalformedJSONError),
        (ScriptedHTTPResponse(raw_body=b"\xff\xfe"), OpenAIMalformedJSONError),
        (
            ScriptedHTTPResponse(raw_body=b"{}", headers={"Content-Length": str(1024 * 1024 + 1)}),
            OpenAIResponseSizeError,
        ),
        (
            ScriptedHTTPResponse(
                raw_body=json.dumps(assistant_response(content="partial")).encode(),
                partial_bytes=8,
            ),
            OpenAIConnectionError,
        ),
    ],
)
def test_real_http_transport_and_body_failures(
    response: ScriptedHTTPResponse,
    error_type: type[Exception],
) -> None:
    with ScriptedOpenAIServer([response]) as server:
        with pytest.raises(error_type):
            _direct_client(server).complete(_EMPTY_MESSAGES, [])


def test_real_http_delayed_response_obeys_timeout() -> None:
    with ScriptedOpenAIServer(
        [
            ScriptedHTTPResponse(json_body=assistant_response(content="too late"), delay=1.2),
        ]
    ) as server:
        with pytest.raises(OpenAIRequestTimeoutError):
            _direct_client(server, request_timeout=1).complete(_EMPTY_MESSAGES, [])


def test_socket_protocol_rejections_recover_to_trusted_finish(
    real_workspace: RealWorkspace,
) -> None:
    """Malformed args, unknown tools, replay, and unsafe batches stay typed."""
    workspace = real_workspace
    runner = RecordingBuildRunner(workspace)
    actions = [
        ScriptedHTTPResponse(json_body=assistant_response(content="I will inspect first")),
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call("bad-json", "read_file", "{"),
                tool_call("unknown", "run_shell", {}),
            )
        ),
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call("inspect", "read_file", {"path": workspace.target.name}),
            )
        ),
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call("inspect", "git_status", {}),
            )
        ),
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call(
                    "early",
                    "finish",
                    {
                        "status": "needs_human",
                        "reason": "must be rejected as a batch",
                    },
                ),
                tool_call("later", "read_file", {"path": workspace.target.name}),
            )
        ),
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call(
                    "premature",
                    "finish",
                    {
                        "status": "done",
                        "reason": "missing build and commit",
                    },
                ),
            )
        ),
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call(
                    "terminal",
                    "finish",
                    {
                        "status": "needs_human",
                        "reason": "protocol recovery complete",
                    },
                ),
            )
        ),
    ]
    with ScriptedOpenAIServer(actions) as server:
        backend, _ = _backend(server, workspace, runner)
        result = backend.run_session(
            "exercise recovery", workspace.repo, {workspace.target.name}, "socket-model", 20, False
        )
        requests = list(server.requests)

    assert result.resolved
    assert requests[1].body["messages"][-1]["role"] == "user"
    duplicate_result = json.loads(requests[4].body["messages"][-1]["content"])
    assert duplicate_result["policy_category"] == "validation"
    unsafe_results = requests[5].body["messages"][-2:]
    assert [message["tool_call_id"] for message in unsafe_results] == ["early", "later"]
    assert all(json.loads(message["content"])["success"] is False for message in unsafe_results)
    premature = json.loads(requests[6].body["messages"][-1]["content"])
    assert premature["success"] is False
    assert premature["policy_category"] == "policy"


def test_socket_second_text_only_stop_is_unresolved(real_workspace: RealWorkspace) -> None:
    actions = [
        ScriptedHTTPResponse(json_body=assistant_response(content="first prose stop")),
        ScriptedHTTPResponse(json_body=assistant_response(content="second prose stop")),
    ]
    runner = RecordingBuildRunner(real_workspace)
    with ScriptedOpenAIServer(actions) as server:
        backend, _ = _backend(server, real_workspace, runner)
        result = backend.run_session(
            "use tools",
            real_workspace.repo,
            {real_workspace.target.name},
            "socket-model",
            20,
            False,
        )
    assert not result.resolved
    assert "stopped twice" in result.failure_reason


def test_socket_client_error_after_mutation_runs_outer_cleanup_and_redacts_secret(
    real_workspace: RealWorkspace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = real_workspace
    original = workspace.target.read_text(encoding="utf-8")
    secret = "sk-socket-integration-secret"
    monkeypatch.setenv("SOCKET_TEST_SECRET", secret)
    runner = RecordingBuildRunner(workspace)
    actions = [
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call(
                    "mutation",
                    "replace_in_file",
                    {
                        "path": workspace.target.name,
                        "old_text": original,
                        "new_text": "authorized mutation before error\n",
                        "expected_count": 1,
                    },
                ),
            )
        ),
        ScriptedHTTPResponse(
            status=500,
            raw_body=(f'{{"error":"Bearer {secret} {secret}"}}').encode(),
        ),
    ]
    with ScriptedOpenAIServer(actions) as server:
        backend, _ = _backend(server, workspace, runner)
        backend.configure(
            {
                "model": "socket-model",
                "openai_base_url": server.base_url,
                "openai_api_key_env": "SOCKET_TEST_SECRET",
                "openai_connect_timeout": 2,
                "openai_request_timeout": 2,
            },
            os.environ,
        )
        with patch(
            "cve_agent.session.revert_unauthorized_changes",
            wraps=(
                __import__(
                    "cve_agent.session", fromlist=["revert_unauthorized_changes"]
                ).revert_unauthorized_changes
            ),
        ) as cleanup:
            result = _guarded(workspace, backend)
        requests = list(server.requests)

    assert not result.resolved and result.transcript_path is not None
    assert cleanup.call_count == 1
    assert all(request.authorization_present for request in requests)
    assert secret not in repr(requests)
    assert secret not in result.failure_reason
    assert secret not in result.transcript_path.read_text(encoding="utf-8")
    build_log = workspace.agent / BUILD_LOG_NAME
    if build_log.exists():
        assert secret not in build_log.read_text(encoding="utf-8")
    assert (workspace.agent / "recipe-CVE-2099-0001-ai-changes.log").exists()


def test_server_fixture_detects_tool_result_order_mismatch() -> None:
    """The server-side request oracle reports reordered tool results safely."""
    messages = [
        {"role": "user", "content": "test ordering"},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                tool_call("first", "git_status", {}),
                tool_call("second", "git_status", {}),
            ],
        },
        {"role": "tool", "tool_call_id": "second", "content": "{}"},
        {"role": "tool", "tool_call_id": "first", "content": "{}"},
    ]
    with pytest.raises(AssertionError, match="request check failed"):
        with ScriptedOpenAIServer(
            [
                ScriptedHTTPResponse(
                    json_body=assistant_response(content="observed"),
                    check=_request_has_tool_results("first", "second"),
                )
            ]
        ) as server:
            _direct_client(server).complete(messages, [])


def test_socket_model_turn_and_tool_call_limits_are_independent(
    real_workspace: RealWorkspace,
) -> None:
    runner = RecordingBuildRunner(real_workspace)
    with ScriptedOpenAIServer(
        [
            ScriptedHTTPResponse(
                json_body=assistant_response(
                    tool_call("one", "read_file", {"path": real_workspace.target.name})
                )
            )
        ]
    ) as server:
        backend, _ = _backend(server, real_workspace, runner, max_steps=1)
        turn_result = backend.run_session(
            "bounded turn",
            real_workspace.repo,
            {real_workspace.target.name},
            "socket-model",
            20,
            False,
        )
    assert not turn_result.resolved
    assert "max-steps" in turn_result.failure_reason

    with ScriptedOpenAIServer(
        [
            ScriptedHTTPResponse(
                json_body=assistant_response(
                    tool_call("one", "git_status", {}),
                    tool_call("two", "git_status", {}),
                )
            )
        ]
    ) as server:
        backend, _ = _backend(server, real_workspace, runner, max_tool_calls=1)
        tool_result = backend.run_session(
            "bounded tools",
            real_workspace.repo,
            {real_workspace.target.name},
            "socket-model",
            20,
            False,
        )
    assert not tool_result.resolved
    assert "max-tool-calls" in tool_result.failure_reason


def test_socket_unexpected_argument_is_rejected_then_recovered(
    real_workspace: RealWorkspace,
) -> None:
    runner = RecordingBuildRunner(real_workspace)
    actions = [
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call(
                    "extra",
                    "read_file",
                    {"path": real_workspace.target.name, "provider_extension": True},
                )
            )
        ),
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call(
                    "finish",
                    "finish",
                    {"status": "needs_human", "reason": "invalid request corrected"},
                )
            ),
            check=_request_has_tool_results("extra"),
        ),
    ]
    with ScriptedOpenAIServer(actions) as server:
        backend, _ = _backend(server, real_workspace, runner)
        result = backend.run_session(
            "closed schemas",
            real_workspace.repo,
            {real_workspace.target.name},
            "socket-model",
            20,
            False,
        )
        error = json.loads(server.requests[1].body["messages"][-1]["content"])
    assert result.resolved
    assert error["success"] is False
    assert error["policy_category"] == "validation"


def test_real_http_rejects_enormous_and_deep_tool_arguments() -> None:
    enormous = assistant_response(tool_call("large", "read_file", {"path": "x" * (256 * 1024 + 1)}))
    deep: dict[str, object] = {"path": "recipe.c"}
    for _ in range(40):
        deep = {"nested": deep}
    deep_call = tool_call("deep", "read_file", {})
    function = deep_call["function"]
    assert isinstance(function, dict)
    function["arguments"] = deep
    deeply_nested = assistant_response(deep_call)

    for response in (enormous, deeply_nested):
        with ScriptedOpenAIServer([ScriptedHTTPResponse(json_body=response)]) as server:
            with pytest.raises(OpenAIProtocolError):
                _direct_client(server).complete(_EMPTY_MESSAGES, [])


@pytest.mark.parametrize(("returncode", "timed_out"), [(1, False), (-9, True)])
def test_socket_build_failure_and_timeout_are_structured_and_recoverable(
    real_workspace: RealWorkspace,
    returncode: int,
    timed_out: bool,
) -> None:
    runner = RecordingBuildRunner(real_workspace, returncode=returncode, timed_out=timed_out)
    actions = [
        ScriptedHTTPResponse(json_body=assistant_response(tool_call("build", "build_recipe", {}))),
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call(
                    "finish",
                    "finish",
                    {"status": "needs_human", "reason": "build needs investigation"},
                )
            ),
            check=_request_has_tool_results("build"),
        ),
    ]
    with ScriptedOpenAIServer(actions) as server:
        backend, _ = _backend(server, real_workspace, runner)
        result = backend.run_session(
            "build once",
            real_workspace.repo,
            {real_workspace.target.name},
            "socket-model",
            20,
            False,
        )
        build_result = json.loads(server.requests[1].body["messages"][-1]["content"])
    assert result.resolved
    assert build_result["success"] is False
    assert build_result["policy_category"] == ("timeout" if timed_out else "operation")
    assert build_result["error"]["timed_out"] is timed_out


def test_socket_unauthorized_and_symlink_paths_are_refused(
    real_workspace: RealWorkspace,
) -> None:
    link = real_workspace.repo / "linked.c"
    link.symlink_to(real_workspace.target.name)
    _git(real_workspace.repo, "add", "--", link.name)
    _git(real_workspace.repo, "commit", "-m", "add fixture symlink")
    runner = RecordingBuildRunner(real_workspace)
    actions = [
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call(
                    "neighbor",
                    "replace_in_file",
                    {
                        "path": real_workspace.neighbor.name,
                        "old_text": "must remain unchanged\n",
                        "new_text": "unauthorized\n",
                        "expected_count": 1,
                    },
                ),
                tool_call("symlink", "read_file", {"path": link.name}),
            )
        ),
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call(
                    "finish",
                    "finish",
                    {"status": "needs_human", "reason": "path requests were refused"},
                )
            )
        ),
    ]
    with ScriptedOpenAIServer(actions) as server:
        backend, _ = _backend(server, real_workspace, runner)
        result = backend.run_session(
            "try scoped paths",
            real_workspace.repo,
            {real_workspace.target.name, link.name},
            "socket-model",
            20,
            False,
        )
        errors = [
            json.loads(message["content"]) for message in server.requests[1].body["messages"][-2:]
        ]
    assert result.resolved
    assert [error["success"] for error in errors] == [False, False], errors
    assert [error["policy_category"] for error in errors] == ["policy", "policy"]


def test_socket_out_of_scope_cherry_pick_is_refused_before_mutation(
    real_workspace: RealWorkspace,
) -> None:
    workspace = real_workspace
    original_head = _git(workspace.repo, "rev-parse", "HEAD")
    _git(workspace.repo, "switch", "-q", "-c", "out-of-scope")
    workspace.neighbor.write_text("unauthorized upstream change\n", encoding="utf-8")
    _git(workspace.repo, "commit", "-am", "out of scope change")
    revision = _git(workspace.repo, "rev-parse", "HEAD")
    _git(workspace.repo, "switch", "-q", "main")
    runner = RecordingBuildRunner(workspace)
    actions = [
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call("start", "git_cherry_pick_start", {"revision": revision})
            )
        ),
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call(
                    "finish",
                    "finish",
                    {"status": "needs_human", "reason": "commit reaches neighbor.txt"},
                )
            )
        ),
    ]
    with ScriptedOpenAIServer(actions) as server:
        backend, _ = _backend(server, workspace, runner)
        result = backend.run_session(
            "preflight commit",
            workspace.repo,
            {workspace.target.name},
            "socket-model",
            20,
            False,
        )
        refusal = json.loads(server.requests[1].body["messages"][-1]["content"])
    assert result.resolved
    assert _git(workspace.repo, "rev-parse", "HEAD") == original_head
    assert refusal["success"] is False
    assert refusal["policy_category"] == "policy"
    assert refusal["error"]["rejected_paths"] == [workspace.neighbor.name]


def test_transcript_creation_failure_prevents_socket_contact(
    real_workspace: RealWorkspace,
) -> None:
    def fail_transcript(*args, **kwargs):
        raise OSError("transcript storage unavailable")

    with ScriptedOpenAIServer() as server:
        backend = OpenAICompatibleBackend(transcript_factory=fail_transcript)
        backend.configure({"model": "socket-model", "openai_base_url": server.base_url}, os.environ)
        result = backend.run_session(
            "must audit",
            real_workspace.repo,
            {real_workspace.target.name},
            "socket-model",
            20,
            False,
        )
        assert server.request_count == 0
    assert not result.resolved
    assert result.transcript_path is None
    assert "mandatory native transcript" in result.failure_reason.lower()


def test_terminal_transcript_failure_removes_conclusion_artifact(
    real_workspace: RealWorkspace,
) -> None:
    actions = [
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call(
                    "finish",
                    "finish",
                    {"status": "needs_human", "reason": "operator review required"},
                )
            )
        )
    ]
    runner = RecordingBuildRunner(real_workspace)

    def transcript_factory(*args, **kwargs):
        transcript = JSONLTranscript.create(*args, **kwargs)
        original_write = transcript.write

        def fail_terminal(kind, **data):
            if kind == "terminal_result":
                raise TranscriptError("simulated terminal audit failure")
            original_write(kind, **data)

        transcript.write = fail_terminal  # type: ignore[method-assign]
        return transcript

    def runtime_factory(*args, **kwargs):
        kwargs["build_runner"] = runner
        return OpenAIHostToolRuntime(*args, **kwargs)

    with ScriptedOpenAIServer(actions) as server:
        backend = OpenAICompatibleBackend(
            runtime_factory=runtime_factory,
            transcript_factory=transcript_factory,
        )
        backend.configure(
            {"model": "socket-model", "openai_base_url": server.base_url},
            os.environ,
        )
        result = backend.run_session(
            "terminal audit must persist",
            real_workspace.repo,
            {real_workspace.target.name},
            "socket-model",
            20,
            False,
        )
    assert not result.resolved
    assert "mandatory native transcript" in result.failure_reason.lower()
    assert not (real_workspace.agent / "conclusion.json").exists()


def test_endpoint_echoed_api_key_cannot_enter_tool_results_or_conclusion(
    real_workspace: RealWorkspace,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = "sk-distinctive-terminal-secret"
    monkeypatch.setenv("TERMINAL_TEST_KEY", secret)
    actions = [
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call(
                    "echoed",
                    "finish",
                    {
                        "status": "needs_human",
                        "reason": f"Bearer {secret} {secret}",
                    },
                )
            )
        ),
        ScriptedHTTPResponse(
            json_body=assistant_response(
                tool_call(
                    "safe",
                    "finish",
                    {"status": "needs_human", "reason": "operator review required"},
                )
            )
        ),
    ]
    runner = RecordingBuildRunner(real_workspace)

    def runtime_factory(*args, **kwargs):
        kwargs["build_runner"] = runner
        return OpenAIHostToolRuntime(*args, **kwargs)

    with ScriptedOpenAIServer(actions) as server:
        backend = OpenAICompatibleBackend(runtime_factory=runtime_factory)
        backend.configure(
            {
                "model": "socket-model",
                "openai_base_url": server.base_url,
                "openai_api_key_env": "TERMINAL_TEST_KEY",
            },
            os.environ,
        )
        result = backend.run_session(
            "protect credentials",
            real_workspace.repo,
            {real_workspace.target.name},
            "socket-model",
            20,
            False,
        )
        first_tool_result = server.requests[1].body["messages"][-1]["content"]
    assert result.resolved and result.transcript_path is not None
    conclusion = real_workspace.agent / "conclusion.json"
    assert secret not in first_tool_result
    assert secret not in conclusion.read_text(encoding="utf-8")
    assert secret not in result.transcript_path.read_text(encoding="utf-8")
    captured = capsys.readouterr()
    assert secret not in captured.out
    assert secret not in captured.err
