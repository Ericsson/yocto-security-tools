# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for the stage-one native OpenAI-compatible backend contract."""
import dataclasses
import os
import socket
import subprocess
import sys
from argparse import Namespace
from pathlib import Path

import pytest

import cve_agent
from cve_agent import CveResult, ResultStatus
from cve_agent.__main__ import _configure_backend, _parse_args, main
from cve_agent.backend import AIBackend, SessionResult, available_backends, get_backend
from cve_agent.claude_backend import ClaudeBackend
from cve_agent.kiro_backend import KiroBackend
from cve_agent.openai_backend import (
    DEFAULT_OPENAI_BASE_URL,
    MAX_OUTPUT_TOKENS_LIMIT,
    MAX_STEPS_LIMIT,
    MAX_TOOL_CALLS_LIMIT,
    OpenAICompatibleBackend,
    OpenAIConfig,
    OpenAIConfigurationError,
)


@pytest.fixture(autouse=True)
def _clear_openai_environment(monkeypatch):
    """Keep developer credentials and endpoint settings out of unit tests."""
    for name in list(os.environ):
        if name.startswith("CVE_AGENT_OPENAI_") or name.startswith("OPENAI_"):
            monkeypatch.delenv(name, raising=False)


def _options(**overrides):
    options = {"model": "test-model"}
    options.update(overrides)
    return options


def test_builtin_registration_preserves_existing_backends():
    assert {"kiro", "claude", "openai"} <= set(available_backends())
    assert isinstance(get_backend("kiro"), KiroBackend)
    assert isinstance(get_backend("claude"), ClaudeBackend)
    assert isinstance(get_backend("openai"), OpenAICompatibleBackend)


def test_module_imports_without_openai_sdk_or_network_access():
    project_root = Path(cve_agent.__file__).resolve().parent.parent
    code = (
        "import socket, sys; "
        "sys.modules['openai'] = None; "
        "socket.create_connection = lambda *a, **k: "
        "(_ for _ in ()).throw(AssertionError('network access')); "
        "import cve_agent.openai_backend"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True,
        check=False, cwd=project_root)
    assert result.returncode == 0, result.stderr


def test_is_available_does_not_probe_endpoint(monkeypatch):
    def fail_network(*args, **kwargs):
        raise AssertionError("network access")

    monkeypatch.setattr(socket, "create_connection", fail_network)
    assert OpenAICompatibleBackend().is_available() is True


def test_native_tool_preamble_requires_host_verified_finish():
    preamble = OpenAICompatibleBackend().tool_preamble()
    assert "`finish`" in preamble
    assert "never create, edit, or delete `conclusion.json`" in preamble
    assert "host alone verifies terminal state" in preamble
    assert "There is no shell" in preamble
    assert "matching tool result" in preamble
    assert "`git_commit`" in preamble
    assert "`git_amend`" in preamble
    assert "message_mode=no_edit" in preamble


def test_parser_accepts_openai_options(monkeypatch):
    monkeypatch.setattr(sys, "argv", [
        "cve-agent", "--cve-id", "CVE-2025-0001",
        "--cve-info", "/tmp/cve.json", "--backend", "openai",
        "--model", "qwen3", "--openai-base-url", "http://localhost:11434/v1",
        "--openai-api-key-env", "OLLAMA_API_KEY", "--openai-max-steps", "7",
        "--openai-max-tool-calls", "30", "--openai-max-output-tokens", "4096",
        "--openai-connect-timeout", "4", "--openai-request-timeout", "90",
        "--openai-allow-remote", "--openai-allow-insecure-remote-http",
    ])
    args = _parse_args()
    assert args.backend == "openai"
    assert args.model == "qwen3"
    assert args.openai_api_key_env == "OLLAMA_API_KEY"
    assert args.openai_max_steps == 7
    assert args.openai_allow_remote_endpoint is True
    assert args.openai_allow_insecure_remote_http is True


def test_help_is_network_free_and_has_no_secret_argument(monkeypatch, capsys):
    def fail_network(*args, **kwargs):
        raise AssertionError("network access")

    monkeypatch.setattr(socket, "create_connection", fail_network)
    monkeypatch.setattr(sys, "argv", ["cve-agent", "--help"])
    with pytest.raises(SystemExit) as exc_info:
        _parse_args()
    assert exc_info.value.code == 0
    help_text = capsys.readouterr().out
    assert "--backend" in help_text
    assert "--openai-base-url" in help_text
    assert "--openai-api-key-env" in help_text
    assert "openai-<profile>" in help_text
    assert "CVE_AGENT_OPENAI_CONFIG_DIR" in help_text
    assert "--openai-api-key " not in help_text


def test_model_defaults_are_separate():
    assert get_backend("kiro").resolve_model(None, {}) == "claude-sonnet-5"
    assert get_backend("claude").resolve_model(None, {}) == "claude-sonnet-5"
    with pytest.raises(OpenAIConfigurationError, match="--model"):
        get_backend("openai").resolve_model(None, {})
    assert get_backend("openai").resolve_model(
        None, {"CVE_AGENT_OPENAI_MODEL": "local-model"}) == "local-model"


@pytest.mark.parametrize("model", ["line\nbreak", "control\x01name", "x" * 257])
def test_model_identity_must_be_one_bounded_printable_line(model):
    with pytest.raises(OpenAIConfigurationError, match="bounded printable line"):
        OpenAIConfig.from_sources(_options(model=model), {})


def test_configure_backend_resolves_existing_and_openai_models():
    existing = Namespace(backend="kiro", model=None)
    _configure_backend(existing)
    assert existing.model == "claude-sonnet-5"

    openai = Namespace(backend="openai", model="native-model")
    _configure_backend(openai)
    assert openai.model == "native-model"
    assert get_backend("openai").config.model == "native-model"


def test_cli_environment_and_default_precedence():
    environ = {
        "CVE_AGENT_OPENAI_MODEL": "private-model",
        "CVE_AGENT_OPENAI_BASE_URL": "http://localhost:12000/v1",
        "OPENAI_BASE_URL": "http://localhost:13000/v1",
        "CVE_AGENT_OPENAI_MAX_STEPS": "11",
    }
    config = OpenAIConfig.from_sources(
        _options(model="cli-model", openai_base_url="http://localhost:14000/v1",
                 openai_max_steps=5), environ)
    assert config.model == "cli-model"
    assert config.base_url == "http://localhost:14000/v1"
    assert config.max_steps == 5

    private = OpenAIConfig.from_sources({"model": None}, environ)
    assert private.model == "private-model"
    assert private.base_url == "http://localhost:12000/v1"
    assert private.max_steps == 11

    standard = OpenAIConfig.from_sources(
        _options(), {"OPENAI_BASE_URL": "http://localhost:15000/v1"})
    assert standard.base_url == "http://localhost:15000/v1"

    defaults = OpenAIConfig.from_sources(_options(), {})
    assert defaults.base_url == DEFAULT_OPENAI_BASE_URL


def test_standard_openai_model_does_not_leak_in_as_a_default():
    with pytest.raises(OpenAIConfigurationError, match="CVE_AGENT_OPENAI_MODEL"):
        OpenAIConfig.from_sources(
            {"model": None}, {"OPENAI_MODEL": "unexpected-default"})


@pytest.mark.parametrize("url,normalized", [
    ("http://localhost:11434/v1/", "http://localhost:11434/v1"),
    ("http://127.99.1.2:11434/v1", "http://127.99.1.2:11434/v1"),
    ("https://[::1]:11434/custom/v1/", "https://[::1]:11434/custom/v1"),
])
def test_valid_loopback_urls(url, normalized):
    config = OpenAIConfig.from_sources(_options(openai_base_url=url), {})
    assert config.base_url == normalized
    assert config.chat_completions_url == f"{normalized}/chat/completions"


@pytest.mark.parametrize("url,match", [
    ("http://user:password@localhost:11434/v1", "credentials"),
    ("http://localhost:11434/v1?debug=1", "query string"),
    ("http://localhost:11434/v1#section", "fragment"),
    ("ftp://localhost/v1", "scheme"),
    ("http://localhost:not-a-port/v1", "malformed"),
    ("http://localhost:65536/v1", "malformed"),
    ("http:///v1", "hostname"),
    ("http://localhost:11434/v1/chat/completions", "API root"),
])
def test_rejects_surprising_url_forms(url, match):
    with pytest.raises(OpenAIConfigurationError, match=match):
        OpenAIConfig.from_sources(_options(openai_base_url=url), {})


def test_remote_endpoint_requires_explicit_opt_in():
    with pytest.raises(OpenAIConfigurationError, match="--openai-allow-remote"):
        OpenAIConfig.from_sources(
            _options(openai_base_url="https://api.example.test/v1"), {})

    config = OpenAIConfig.from_sources(
        _options(openai_base_url="https://api.example.test/v1",
                 openai_allow_remote_endpoint=True), {})
    assert config.allow_remote_endpoint is True


def test_insecure_remote_http_requires_separate_opt_in():
    options = _options(
        openai_base_url="http://api.example.test/v1",
        openai_allow_remote_endpoint=True,
    )
    with pytest.raises(OpenAIConfigurationError,
                       match="--openai-allow-insecure-remote-http"):
        OpenAIConfig.from_sources(options, {})

    options["openai_allow_insecure_remote_http"] = True
    config = OpenAIConfig.from_sources(options, {})
    assert config.allow_insecure_remote_http is True


@pytest.mark.parametrize("name", ["API-KEY", "9API_KEY", "API KEY", ""])
def test_api_key_environment_name_validation(name):
    with pytest.raises(OpenAIConfigurationError, match="valid identifier"):
        OpenAIConfig.from_sources(
            _options(openai_api_key_env=name), {name: "not-logged"})


def test_explicit_api_key_environment_must_exist():
    with pytest.raises(OpenAIConfigurationError, match="MY_OPENAI_KEY.*not set"):
        OpenAIConfig.from_sources(
            _options(openai_api_key_env="MY_OPENAI_KEY"), {})

    config = OpenAIConfig.from_sources(
        _options(openai_api_key_env="MY_OPENAI_KEY"),
        {"MY_OPENAI_KEY": "secret-value"})
    assert config.api_key_env == "MY_OPENAI_KEY"


@pytest.mark.parametrize("field,upper", [
    ("openai_max_steps", MAX_STEPS_LIMIT),
    ("openai_max_tool_calls", MAX_TOOL_CALLS_LIMIT),
    ("openai_max_output_tokens", MAX_OUTPUT_TOKENS_LIMIT),
])
@pytest.mark.parametrize("value_kind", ["zero", "negative", "too_large"])
def test_positive_and_upper_bounds(field, upper, value_kind):
    values = {"zero": 0, "negative": -1, "too_large": upper + 1}
    with pytest.raises(OpenAIConfigurationError, match="between 1 and"):
        OpenAIConfig.from_sources(_options(**{field: values[value_kind]}), {})


def test_api_key_value_is_absent_from_errors_and_logs(caplog):
    secret = "sk-do-not-disclose-123"
    with pytest.raises(OpenAIConfigurationError) as exc_info:
        OpenAIConfig.from_sources(
            _options(openai_api_key_env="MY_KEY",
                     openai_base_url="https://remote.example/v1"),
            {"MY_KEY": secret})
    assert secret not in str(exc_info.value)
    assert secret not in caplog.text


def test_configuration_is_immutable():
    config = OpenAIConfig.from_sources(_options(), {})
    with pytest.raises(dataclasses.FrozenInstanceError):
        config.model = "changed"  # type: ignore[misc]


def test_direct_config_construction_cannot_bypass_validation():
    values = dataclasses.asdict(OpenAIConfig.from_sources(_options(), {}))
    values["base_url"] = "http://user:secret@localhost:11434/v1"
    with pytest.raises(OpenAIConfigurationError, match="credentials"):
        OpenAIConfig(**values)

    values = dataclasses.asdict(OpenAIConfig.from_sources(_options(), {}))
    values["max_steps"] = 0
    with pytest.raises(OpenAIConfigurationError, match="between 1"):
        OpenAIConfig(**values)


def test_minimal_third_party_backend_needs_no_configuration_override():
    class ThirdPartyBackend(AIBackend):
        name = "third-party"

        def is_available(self):
            return True

        def run_session(self, prompt, workspace_path, allowed_files,
                        model, timeout, interactive):
            return SessionResult(resolved=True, duration=0.0)

    backend = ThirdPartyBackend()
    assert backend.configure({}, {}) is None
    assert backend.resolve_model(None, {}) == "claude-sonnet-5"


def test_setup_is_local_and_session_initialization_failure_is_unresolved(tmp_path):
    backend = OpenAICompatibleBackend()
    backend.configure(_options(), {})
    assert backend.setup() is None
    result = backend.run_session(
        "prompt", tmp_path, set(), "test-model", 60, False)
    assert result.resolved is False
    assert result.transcript_path is not None


def test_cli_missing_openai_model_fails_before_processing(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", [
        "cve-agent", "--cve-id", "CVE-2025-0001",
        "--cve-info", "/tmp/cve.json", "--backend", "openai",
    ])
    monkeypatch.delenv("CVE_AGENT_OPENAI_MODEL", raising=False)
    called = False

    def process(*args, **kwargs):
        nonlocal called
        called = True
        return CveResult("CVE-2025-0001", ResultStatus.SUCCESS)

    monkeypatch.setattr("cve_agent.__main__.process_single_cve", process)
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == cve_agent.EXIT_AGENT_ERROR
    error = capsys.readouterr().err
    assert "--model MODEL" in error
    assert "CVE_AGENT_OPENAI_MODEL" in error
    assert called is False


def test_cli_configuration_error_does_not_print_api_key(monkeypatch, capsys):
    secret = "sk-cli-secret-value"
    monkeypatch.setenv("MY_OPENAI_KEY", secret)
    monkeypatch.setattr(sys, "argv", [
        "cve-agent", "--cve-id", "CVE-2025-0001",
        "--cve-info", "/tmp/cve.json", "--backend", "openai",
        "--model", "model", "--openai-api-key-env", "MY_OPENAI_KEY",
        "--openai-base-url", "https://remote.example/v1",
    ])
    with pytest.raises(SystemExit):
        main()
    captured = capsys.readouterr()
    assert secret not in captured.out
    assert secret not in captured.err


def test_valid_cli_configuration_proceeds_to_processing(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", [
        "cve-agent", "--cve-id", "CVE-2025-0001",
        "--cve-info", "/tmp/cve.json", "--backend", "openai",
        "--model", "local-model",
    ])
    called = False

    def process_cve(*args, **kwargs):
        nonlocal called
        called = True
        return CveResult("CVE-2025-0001", ResultStatus.SUCCESS)

    monkeypatch.setattr("cve_agent.__main__.process_single_cve", process_cve)
    main()
    captured = capsys.readouterr()
    assert "CVE-2025-0001: WORKFLOW_COMPLETED_UNVERIFIED" in captured.out
    assert captured.err == ""
    assert called is True
