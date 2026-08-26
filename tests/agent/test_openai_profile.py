# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for named native OpenAI profile selection and strict loading."""
from pathlib import Path

import pytest

from cve_agent.backend import (
    BackendConfigurationError,
    resolve_backend_selector,
)
from cve_agent.openai_backend import OpenAICompatibleBackend
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


def test_no_profile_plain_openai_still_uses_environment_and_no_file(tmp_path):
    backend = OpenAICompatibleBackend()
    backend.configure({"model": None}, {"CVE_AGENT_OPENAI_MODEL": "env-model"})
    assert backend.config.model == "env-model"
    assert not (tmp_path / "openai-env-model.cfg").exists()
