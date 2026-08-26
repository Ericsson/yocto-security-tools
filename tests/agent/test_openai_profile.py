# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for named native OpenAI profile selection and strict loading."""
import socket
from argparse import Namespace
from pathlib import Path

import pytest

from cve_agent.__main__ import _configure_backend
from cve_agent.backend import (
    BackendConfigurationError,
    resolve_backend_selector,
)
from cve_agent.openai_backend import OpenAICompatibleBackend, OpenAIConfigurationError
from cve_agent.openai_profile import (
    MAX_PROFILE_BYTES,
    OpenAIProfileError,
    default_openai_config_dir,
    load_openai_profile,
    resolve_openai_profile_path,
)

BASE_PROFILE = """\
[openai]
base_url = http://localhost:11434/v1
model = profile-model
max_steps = 30
max_tool_calls = 150
max_consecutive_no_progress = 4
max_output_tokens = 4096
connect_timeout = 9
request_timeout = 300
allow_remote_endpoint = false
allow_insecure_remote_http = false

[chat]
temperature = 0.0
top_p = 0.95
reasoning_effort = none
"""


def _write_profile(directory: Path, name: str = "test", text: str = BASE_PROFILE) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"openai-{name}.cfg"
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)
    return path


def _options(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {"backend_profile": "test", "model": None}
    values.update(overrides)
    return values


def test_selector_canonicalizes_openai_profiles_and_preserves_plugins():
    assert resolve_backend_selector("openai").profile is None
    selection = resolve_backend_selector("openai-qwen-coder-next-l40s")
    assert selection.selector == "openai-qwen-coder-next-l40s"
    assert selection.backend == "openai"
    assert selection.profile == "qwen-coder-next-l40s"
    assert resolve_backend_selector("kiro").backend == "kiro"
    assert resolve_backend_selector("claude").backend == "claude"
    assert resolve_backend_selector("test-plugin").backend == "test-plugin"


@pytest.mark.parametrize("selector", [
    "openai-", "openai-UPPER", "openai-../x", "openai-a..b", "openai-a/b",
    "openai-a\\b", "openai-a b", "openai-\x00", "openai-módel",
    "openai-" + "a" * 65,
])
def test_invalid_reserved_selector_is_rejected(selector):
    with pytest.raises(BackendConfigurationError, match="profile names"):
        resolve_backend_selector(selector)


def test_default_path_is_derived_from_module_not_cwd(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert default_openai_config_dir().name == "etc"
    assert resolve_openai_profile_path("abc", {}).name == "openai-abc.cfg"
    assert resolve_openai_profile_path("abc", {}).parent == default_openai_config_dir()


def test_config_dir_override_must_be_absolute():
    with pytest.raises(OpenAIProfileError, match="absolute"):
        resolve_openai_profile_path(
            "test", {"CVE_AGENT_OPENAI_CONFIG_DIR": "relative/config"})


def test_profile_supplies_required_model_and_all_portable_values(tmp_path):
    directory = tmp_path / "profiles"
    path = _write_profile(directory)
    environ = {"CVE_AGENT_OPENAI_CONFIG_DIR": str(directory)}
    profile = load_openai_profile("test", environ)
    backend = OpenAICompatibleBackend()
    backend.configure(_options(), environ)

    assert profile.path == path
    assert len(profile.sha256) == 64
    assert backend.config.model == "profile-model"
    assert backend.config.base_url == "http://localhost:11434/v1"
    assert backend.config.max_steps == 30
    assert backend.config.max_tool_calls == 150
    assert backend.config.max_consecutive_no_progress == 4
    assert backend.config.max_output_tokens == 4096
    assert backend.config.connect_timeout == 9
    assert backend.config.request_timeout == 300
    assert backend.config.allow_remote_endpoint is False
    assert backend.config.allow_insecure_remote_http is False
    assert backend.config.temperature == 0.0
    assert backend.config.top_p == 0.95
    assert backend.config.reasoning_effort == "none"


def test_profile_loads_explicit_capabilities_probe_and_fallback(tmp_path):
    directory = tmp_path / "profiles"
    _write_profile(directory, text=BASE_PROFILE + """
[capabilities]
chat_completions_path = api/v1/chat/completions
supports_tools = true
supports_parallel_tool_calls = false
supports_tool_choice = false
output_token_field = max_completion_tokens
reasoning_request_field = reasoning_effort
reasoning_response_field = reasoning_content
requires_reasoning_replay = true
supports_response_usage = false
supports_request_ids = true
max_request_bytes = 32768
max_response_bytes = 65536

[probe]
enabled = true

[fallback]
selector = openai-secondary
allow_timeout = true
allow_rate_limit = false
preserve_mutations = false
min_remaining_seconds = 12
""")
    _write_profile(directory, "secondary")

    profile = load_openai_profile(
        "test", {"CVE_AGENT_OPENAI_CONFIG_DIR": str(directory)})

    assert profile.capabilities.chat_completions_path == "api/v1/chat/completions"
    assert profile.capabilities.supports_parallel_tool_calls is False
    assert profile.capabilities.output_token_field == "max_completion_tokens"
    assert profile.capabilities.requires_reasoning_replay is True
    assert profile.probe.enabled is True
    assert profile.fallback is not None
    assert profile.fallback.profile == "secondary"
    assert profile.fallback.allow_timeout is True
    assert profile.fallback.allow_rate_limit is False
    assert profile.fallback.preserve_mutations is False
    assert profile.fallback.min_remaining_seconds == 12


@pytest.mark.parametrize(("section", "match"), [
    ("[capabilities]\noutput_token_field = vendor_tokens\n", "output_token_field"),
    ("[capabilities]\nsupports_tools = false\n", "tool"),
    ("[capabilities]\nrequires_reasoning_replay = true\n", "reasoning replay"),
    ("[capabilities]\nmax_response_bytes = 9999999\n", "max_response_bytes"),
    ("[probe]\nenabled = maybe\n", "strict boolean"),
    ("[fallback]\nselector = claude\n", "openai-<profile>"),
    ("[fallback]\nselector = openai-test\n", "differ"),
    ("[fallback]\nselector = openai-secondary\nallow_timeout = maybe\n",
     "strict boolean"),
    ("[fallback]\nselector = openai-secondary\nmin_remaining_seconds = 0\n",
     "between"),
])
def test_provider_sections_reject_unsupported_values(tmp_path, section, match):
    directory = tmp_path / "profiles"
    _write_profile(directory, text=BASE_PROFILE + section)

    with pytest.raises(OpenAIProfileError, match=match):
        load_openai_profile(
            "test", {"CVE_AGENT_OPENAI_CONFIG_DIR": str(directory)})


def test_backend_rejects_nested_fallback_profiles(tmp_path):
    directory = tmp_path / "profiles"
    fallback = "\n[fallback]\nselector = openai-secondary\n"
    _write_profile(directory, "test", BASE_PROFILE + fallback)
    _write_profile(
        directory, "secondary", BASE_PROFILE.replace("profile-model", "secondary-model")
        + "\n[fallback]\nselector = openai-third\n")
    _write_profile(directory, "third")

    with pytest.raises(OpenAIConfigurationError, match="nested"):
        OpenAICompatibleBackend().configure(
            _options(), {"CVE_AGENT_OPENAI_CONFIG_DIR": str(directory)})


def test_profile_is_read_once_and_setup_remains_network_free(
    monkeypatch, tmp_path,
):
    directory = tmp_path / "profiles"
    _write_profile(directory)
    environ = {"CVE_AGENT_OPENAI_CONFIG_DIR": str(directory)}
    from cve_agent import openai_profile

    original = openai_profile._read_profile_file
    reads = []

    def counted_read(path):
        reads.append(path)
        return original(path)

    monkeypatch.setattr(openai_profile, "_read_profile_file", counted_read)
    monkeypatch.setattr(
        socket, "create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("network access")),
    )
    backend = OpenAICompatibleBackend()
    backend.configure(_options(), environ)
    backend.setup()
    assert len(reads) == 1


def test_profile_precedence_cli_then_profile_then_environment(tmp_path):
    directory = tmp_path / "profiles"
    _write_profile(directory)
    environ = {
        "CVE_AGENT_OPENAI_CONFIG_DIR": str(directory),
        "CVE_AGENT_OPENAI_MODEL": "env-model",
        "CVE_AGENT_OPENAI_BASE_URL": "http://localhost:9999/v1",
        "CVE_AGENT_OPENAI_MAX_STEPS": "3",
        "CVE_AGENT_OPENAI_MAX_CONSECUTIVE_NO_PROGRESS": "2",
        "CVE_AGENT_OPENAI_TEMPERATURE": "1.5",
        "CVE_AGENT_OPENAI_TOP_P": "0.2",
        "CVE_AGENT_OPENAI_REASONING_EFFORT": "high",
    }
    backend = OpenAICompatibleBackend()
    backend.configure(_options(), environ)
    assert backend.config.model == "profile-model"
    assert backend.config.max_steps == 30
    assert backend.config.max_consecutive_no_progress == 4
    assert backend.config.temperature == 0.0
    assert backend.config.top_p == 0.95
    assert backend.config.reasoning_effort == "none"

    backend.configure(_options(
        model="cli-model",
        openai_base_url="http://localhost:7777/v1",
        openai_max_steps=2,
        openai_max_tool_calls=4,
        openai_max_consecutive_no_progress=5,
        openai_max_output_tokens=512,
        openai_connect_timeout=2,
        openai_request_timeout=8,
        openai_allow_remote_endpoint=False,
        openai_allow_insecure_remote_http=False,
        openai_temperature=0.0,
        openai_top_p=0.5,
        openai_reasoning_effort="low",
    ), environ)
    config = backend.config
    assert config.model == "cli-model"
    assert config.base_url == "http://localhost:7777/v1"
    assert config.max_steps == 2
    assert config.max_tool_calls == 4
    assert config.max_consecutive_no_progress == 5
    assert config.max_output_tokens == 512
    assert config.connect_timeout == 2
    assert config.request_timeout == 8
    assert config.allow_remote_endpoint is False
    assert config.allow_insecure_remote_http is False
    assert config.temperature == 0.0
    assert config.top_p == 0.5
    assert config.reasoning_effort == "low"


def test_cli_configuration_canonicalizes_before_backend_lookup(monkeypatch, tmp_path):
    directory = tmp_path / "profiles"
    _write_profile(directory, "named")
    monkeypatch.setenv("CVE_AGENT_OPENAI_CONFIG_DIR", str(directory))
    args = Namespace(backend="openai-named", model=None)
    backend = _configure_backend(args)
    assert backend.name == "openai"
    assert args.backend == "openai"
    assert args.backend_selector == "openai-named"
    assert args.backend_profile == "named"
    assert args.model == "profile-model"


def test_missing_profile_never_falls_back_to_plain_openai(tmp_path):
    with pytest.raises(OpenAIProfileError, match="not found"):
        OpenAICompatibleBackend().configure(
            _options(), {"CVE_AGENT_OPENAI_CONFIG_DIR": str(tmp_path)})


def test_symlink_oversized_world_writable_and_malformed_utf8_are_rejected(tmp_path):
    directory = tmp_path / "profiles"
    target = _write_profile(directory, "target")
    (directory / "openai-link.cfg").symlink_to(target)
    with pytest.raises(OpenAIProfileError, match="not found"):
        load_openai_profile("link", {"CVE_AGENT_OPENAI_CONFIG_DIR": str(directory)})

    oversized = directory / "openai-large.cfg"
    oversized.write_bytes(b"#" * (MAX_PROFILE_BYTES + 1))
    oversized.chmod(0o600)
    with pytest.raises(OpenAIProfileError, match="64 KiB"):
        load_openai_profile("large", {"CVE_AGENT_OPENAI_CONFIG_DIR": str(directory)})

    unsafe = _write_profile(directory, "unsafe")
    unsafe.chmod(0o602)
    with pytest.raises(OpenAIProfileError, match="world-writable"):
        load_openai_profile("unsafe", {"CVE_AGENT_OPENAI_CONFIG_DIR": str(directory)})

    malformed = directory / "openai-badutf.cfg"
    malformed.write_bytes(b"[openai]\nmodel=bad\xff\n")
    malformed.chmod(0o600)
    with pytest.raises(OpenAIProfileError, match="UTF-8"):
        load_openai_profile("badutf", {"CVE_AGENT_OPENAI_CONFIG_DIR": str(directory)})


@pytest.mark.parametrize(("text", "match"), [
    ("[openai]\nmodel=a\nmodel=b\n", "DuplicateOptionError"),
    ("[openai]\nmodel=a\n[openai]\nmodel=b\n", "DuplicateSectionError"),
    ("[DEFAULT]\nfoo=bar\n[openai]\nmodel=a\n", "DEFAULT"),
    ("[DEFAULT]\n[openai]\nmodel=a\n", "DEFAULT"),
    ("[unknown]\nfoo=bar\n[openai]\nmodel=a\n", "unknown.*section"),
    ("[openai]\nmodel=a\nunknown=true\n", "unknown key"),
    ("[openai]\nmodel=a\napi_key=secret\n", "secret-bearing"),
    ("[openai\nmodel=a\n", "malformed"),
])
def test_strict_ini_schema_rejects_ambiguous_or_unknown_input(tmp_path, text, match):
    directory = tmp_path / "profiles"
    _write_profile(directory, text=text)
    with pytest.raises(OpenAIProfileError, match=match):
        load_openai_profile("test", {"CVE_AGENT_OPENAI_CONFIG_DIR": str(directory)})


def test_api_key_env_is_indirect_and_required_without_leaking_secret(tmp_path):
    directory = tmp_path / "profiles"
    _write_profile(directory, text=BASE_PROFILE.replace(
        "model = profile-model", "model = profile-model\napi_key_env = SITE_OPENAI_KEY"))
    environ = {"CVE_AGENT_OPENAI_CONFIG_DIR": str(directory)}
    with pytest.raises(OpenAIConfigurationError, match="SITE_OPENAI_KEY.*not set"):
        OpenAICompatibleBackend().configure(_options(), environ)
    secret = "profile-secret-value"
    backend = OpenAICompatibleBackend()
    backend.configure(_options(), {**environ, "SITE_OPENAI_KEY": secret})
    assert backend.config.api_key_env == "SITE_OPENAI_KEY"
    assert secret not in repr(backend.config)


@pytest.mark.parametrize(("section", "value", "match"), [
    ("chat", "temperature = nan", "temperature"),
    ("chat", "temperature = 2.1", "temperature"),
    ("chat", "top_p = 0", "top_p"),
    ("chat", "reasoning_effort = extreme", "reasoning_effort"),
])
def test_malformed_portable_chat_values_fail_during_profile_loading(
    tmp_path, section, value, match,
):
    directory = tmp_path / "profiles"
    text = f"[openai]\nmodel = profile-model\n\n[{section}]\n{value}\n"
    _write_profile(directory, text=text)
    with pytest.raises(OpenAIProfileError, match=match):
        load_openai_profile("test", {"CVE_AGENT_OPENAI_CONFIG_DIR": str(directory)})


@pytest.mark.parametrize(("line", "match"), [
    ("num_ctx = 0", "num_ctx"),
    ("num_ctx = 1048577", "num_ctx"),
    ("num_ctx = 4096\npreload = perhaps", "strict boolean"),
    ("num_ctx = 4096\nkeep_alive = forever", "keep_alive"),
    ("num_ctx = 4096\nOLLAMA_NUM_PARALLEL = 4", "unknown key"),
])
def test_ollama_profile_values_and_server_settings_are_strict(tmp_path, line, match):
    directory = tmp_path / "profiles"
    text = (
        "[openai]\nmodel = target\n\n[ollama]\n"
        "source_model = source\ntarget_model = target\n" + line + "\n"
    )
    _write_profile(directory, text=text)
    with pytest.raises(OpenAIProfileError, match=match):
        load_openai_profile("test", {"CVE_AGENT_OPENAI_CONFIG_DIR": str(directory)})


def test_remote_plain_http_profile_still_requires_both_opt_ins(tmp_path):
    directory = tmp_path / "profiles"
    remote = BASE_PROFILE.replace(
        "http://localhost:11434/v1", "http://models.example.test:11434/v1")
    _write_profile(directory, text=remote)
    environ = {"CVE_AGENT_OPENAI_CONFIG_DIR": str(directory)}
    with pytest.raises(OpenAIConfigurationError, match="allow-remote"):
        OpenAICompatibleBackend().configure(_options(), environ)

    one_opt_in = remote.replace(
        "allow_remote_endpoint = false", "allow_remote_endpoint = true")
    _write_profile(directory, text=one_opt_in)
    with pytest.raises(OpenAIConfigurationError, match="allow-insecure-remote-http"):
        OpenAICompatibleBackend().configure(_options(), environ)


def test_explicit_false_cli_boolean_is_not_treated_as_missing(tmp_path):
    directory = tmp_path / "profiles"
    remote = BASE_PROFILE.replace(
        "http://localhost:11434/v1", "https://models.example.test/v1").replace(
        "allow_remote_endpoint = false", "allow_remote_endpoint = true")
    _write_profile(directory, text=remote)
    environ = {"CVE_AGENT_OPENAI_CONFIG_DIR": str(directory)}
    with pytest.raises(OpenAIConfigurationError, match="allow-remote"):
        OpenAICompatibleBackend().configure(
            _options(openai_allow_remote_endpoint=False), environ)


def test_no_profile_plain_openai_still_uses_environment_and_no_file(tmp_path):
    backend = OpenAICompatibleBackend()
    backend.configure({"model": None}, {"CVE_AGENT_OPENAI_MODEL": "env-model"})
    assert backend.config.model == "env-model"
    assert not (tmp_path / "openai-env-model.cfg").exists()
