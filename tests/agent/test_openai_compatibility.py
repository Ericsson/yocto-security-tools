# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""User-facing Ollama, instruction, documentation, and CLI compatibility tests."""
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from cve_agent import read_shared_agent_instructions
from cve_agent.__main__ import _parse_args
from cve_agent.claude_backend import ClaudeBackend
from cve_agent.kiro_backend import KiroBackend
from cve_agent.openai_backend import (
    DEFAULT_OPENAI_BASE_URL,
    OpenAICompatibleBackend,
    OpenAIConfig,
    OpenAIConfigurationError,
)
from cve_agent.openai_client import OpenAIChatCompletionsClient
from cve_agent.openai_deadline import SessionDeadline

PROJECT_ROOT = Path(__file__).resolve().parents[2]
NATIVE_GUIDE = PROJECT_ROOT / "docs" / "openai-compatible-backend.md"
USER_GUIDES = (
    PROJECT_ROOT / "README.md",
    NATIVE_GUIDE,
)
OPENAI_OPTIONS = {
    "--openai-base-url",
    "--openai-api-key-env",
    "--openai-max-steps",
    "--openai-max-tool-calls",
    "--openai-max-output-tokens",
    "--openai-connect-timeout",
    "--openai-request-timeout",
    "--openai-allow-remote",
    "--openai-allow-insecure-remote-http",
}


class _Response:
    status_code = 200
    headers: dict[str, str] = {}

    def __init__(self, payload: dict[str, object]) -> None:
        self.body = json.dumps(payload).encode("utf-8")
        self.closed = False

    def iter_content(self, chunk_size: int, decode_unicode: bool = False):
        yield self.body

    def close(self) -> None:
        self.closed = True


class _Transport:
    def __init__(self, response: _Response) -> None:
        self.response = response
        self.calls: list[tuple[str, dict[str, object]]] = []

    def post(self, url: str, **kwargs: object) -> _Response:
        self.calls.append((url, kwargs))
        return self.response


def _capture_help(monkeypatch, capsys) -> str:
    monkeypatch.setattr(sys, "argv", ["cve-agent", "--help"])
    with pytest.raises(SystemExit) as exc_info:
        _parse_args()
    assert exc_info.value.code == 0
    return capsys.readouterr().out


def test_cli_help_lists_backend_group_and_every_native_option_without_network(
        monkeypatch, capsys):
    def refuse_network(*args, **kwargs):
        raise AssertionError("help must not contact an endpoint")

    monkeypatch.setattr("socket.create_connection", refuse_network)
    help_text = _capture_help(monkeypatch, capsys)
    assert "AI backend: kiro, claude, or openai" in help_text
    assert "OpenAI-compatible backend:" in help_text
    parsed_options = set(re.findall(r"--[a-z][a-z0-9-]+", help_text))
    assert parsed_options >= OPENAI_OPTIONS
    assert "--openai-api-key" not in parsed_options


def test_documented_configuration_precedence_exactly_matches_code():
    environ = {
        "CVE_AGENT_OPENAI_MODEL": "private-model",
        "CVE_AGENT_OPENAI_BASE_URL": "http://localhost:12000/v1",
        "OPENAI_BASE_URL": "http://localhost:13000/v1",
        "CVE_AGENT_OPENAI_API_KEY_ENV": "PRIVATE_KEY",
        "CVE_AGENT_OPENAI_MAX_STEPS": "21",
        "CVE_AGENT_OPENAI_MAX_TOOL_CALLS": "201",
        "CVE_AGENT_OPENAI_MAX_OUTPUT_TOKENS": "9001",
        "CVE_AGENT_OPENAI_CONNECT_TIMEOUT": "11",
        "CVE_AGENT_OPENAI_REQUEST_TIMEOUT": "121",
        "CVE_AGENT_OPENAI_ALLOW_REMOTE": "false",
        "CVE_AGENT_OPENAI_ALLOW_INSECURE_REMOTE_HTTP": "false",
        "CLI_KEY": "test-only-key",
        "PRIVATE_KEY": "test-only-private-key",
    }
    config = OpenAIConfig.from_sources({
        "model": "cli-model",
        "openai_base_url": "https://models.example/v1",
        "openai_api_key_env": "CLI_KEY",
        "openai_max_steps": 7,
        "openai_max_tool_calls": 70,
        "openai_max_output_tokens": 4096,
        "openai_connect_timeout": 4,
        "openai_request_timeout": 90,
        "openai_allow_remote_endpoint": True,
        "openai_allow_insecure_remote_http": False,
    }, environ)
    assert config == OpenAIConfig(
        base_url="https://models.example/v1",
        model="cli-model",
        api_key_env="CLI_KEY",
        max_steps=7,
        max_tool_calls=70,
        max_output_tokens=4096,
        connect_timeout=4,
        request_timeout=90,
        allow_remote_endpoint=True,
        allow_insecure_remote_http=False,
    )

    private = OpenAIConfig.from_sources({"model": None}, environ)
    assert private.model == "private-model"
    assert private.base_url == "http://localhost:12000/v1"
    assert private.api_key_env == "PRIVATE_KEY"
    assert private.max_steps == 21
    assert private.max_tool_calls == 201
    assert private.max_output_tokens == 9001
    assert private.connect_timeout == 11
    assert private.request_timeout == 121

    standard = OpenAIConfig.from_sources(
        {"model": "model"}, {"OPENAI_BASE_URL": "http://localhost:15000/v1"})
    assert standard.base_url == "http://localhost:15000/v1"
    assert OpenAIConfig.from_sources({"model": "model"}, {}).base_url == (
        DEFAULT_OPENAI_BASE_URL)

    remote_from_environment = OpenAIConfig.from_sources({
        "model": "model",
        "openai_base_url": "http://models.example/v1",
    }, {
        "CVE_AGENT_OPENAI_ALLOW_REMOTE": "true",
        "CVE_AGENT_OPENAI_ALLOW_INSECURE_REMOTE_HTTP": "true",
    })
    assert remote_from_environment.allow_remote_endpoint is True
    assert remote_from_environment.allow_insecure_remote_http is True


def test_local_ollama_configuration_does_not_require_api_key():
    config = OpenAIConfig.from_sources({
        "model": "operator-selected-tool-model",
        "openai_base_url": "http://127.0.0.1:11434/v1",
    }, {})
    assert config.api_key_env == "OPENAI_API_KEY"
    assert config.base_url == DEFAULT_OPENAI_BASE_URL


def test_remote_security_errors_are_actionable_and_secret_free():
    secret = "test-secret-must-never-appear"
    with pytest.raises(OpenAIConfigurationError) as remote_error:
        OpenAIConfig.from_sources({
            "model": "model",
            "openai_base_url": "https://models.example/v1",
            "openai_api_key_env": "MODEL_KEY",
        }, {"MODEL_KEY": secret})
    assert "--openai-allow-remote" in str(remote_error.value)
    assert "CVE_AGENT_OPENAI_ALLOW_REMOTE" in str(remote_error.value)
    assert secret not in str(remote_error.value)

    with pytest.raises(OpenAIConfigurationError) as insecure_error:
        OpenAIConfig.from_sources({
            "model": "model",
            "openai_base_url": "http://models.example/v1",
            "openai_api_key_env": "MODEL_KEY",
            "openai_allow_remote_endpoint": True,
        }, {"MODEL_KEY": secret})
    assert "--openai-allow-insecure-remote-http" in str(insecure_error.value)
    assert "CVE_AGENT_OPENAI_ALLOW_INSECURE_REMOTE_HTTP" in str(insecure_error.value)
    assert secret not in str(insecure_error.value)


def test_backend_instruction_assembly_has_one_matching_tool_preamble():
    shared = read_shared_agent_instructions()
    assert "backend preamble" in shared
    assert "semantic workflow example" in shared
    assert "fs_read" not in shared
    assert "execute_bash" not in shared

    native = OpenAICompatibleBackend().assembled_instructions()
    assert native.count("Only the advertised native typed tools exist") == 1
    assert "`read_file`" in native
    assert "`build_recipe`" in native
    assert "`git_commit`" in native
    assert "`git_amend`" in native
    assert "`finish`" in native
    assert "There is no shell" in native
    assert "execute_bash" not in native
    assert "`Bash`" not in native

    kiro = KiroBackend().assembled_instructions()
    assert kiro.count("`fs_read`") == 1
    assert kiro.count("`execute_bash`") == 1
    assert "devtool build" in kiro
    assert "established `<agent_dir>/conclusion.json`" in kiro

    claude = ClaudeBackend().assembled_instructions()
    assert claude.count("`Bash`") == 1
    assert "`Read`" in claude
    assert "fs_read" not in claude
    assert "devtool build" in claude


def test_documented_options_exist_and_bash_blocks_are_valid(monkeypatch, capsys):
    help_text = _capture_help(monkeypatch, capsys)
    parser_options = set(re.findall(r"--[a-z][a-z0-9-]+", help_text))

    for guide in USER_GUIDES:
        content = guide.read_text(encoding="utf-8")
        for index, block in enumerate(
                re.findall(r"```bash\n(.*?)\n```", content, re.DOTALL)):
            checked = subprocess.run(
                ["bash", "-n"], input=block, text=True,
                capture_output=True, check=False)
            assert checked.returncode == 0, (
                f"invalid bash block {index} in {guide}: {checked.stderr}")

    documented_options = set(re.findall(
        r"--[a-z][a-z0-9-]+", NATIVE_GUIDE.read_text(encoding="utf-8")))
    assert documented_options <= parser_options
    assert documented_options >= OPENAI_OPTIONS


def test_minimal_ollama_shaped_chat_completion_is_accepted():
    response = _Response({
        "id": "chatcmpl-ollama-test",
        "object": "chat.completion",
        "model": "operator-selected-model",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": None,
                "tool_calls": [{
                    "id": "call_ollama_1",
                    "type": "function",
                    "function": {
                        "name": "git_status",
                        "arguments": {},
                    },
                }],
            },
            "finish_reason": "tool_calls",
        }],
    })
    transport = _Transport(response)
    config = OpenAIConfig.from_sources({"model": "operator-selected-model"}, {})
    client = OpenAIChatCompletionsClient(
        config, SessionDeadline.from_timeout(30), transport=transport, environ={})
    result = client.complete(
        [{"role": "user", "content": "Inspect status."}],
        [{
            "type": "function",
            "function": {
                "name": "git_status",
                "description": "Inspect status.",
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            },
        }],
    )

    assert result.tool_calls[0].id == "call_ollama_1"
    assert result.tool_calls[0].name == "git_status"
    assert result.tool_calls[0].arguments == "{}"
    assert result.tool_calls[0].arguments_were_object is True
    assert response.closed is True
