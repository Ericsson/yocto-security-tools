# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent.setup — agent verification and installation."""
import json
from unittest.mock import patch

import pytest

import cve_agent.setup as setup
from cve_agent.setup import (
    REQUIRED_AGENTS,
    check_kiro_cli,
    ensure_agents,
    get_missing_agents,
    install_agents,
    sync_agent_instructions,
    verify_agents_installed,
)


@pytest.fixture
def fake_dirs(tmp_path, monkeypatch):
    """Set up fake source, target, and stable-instructions directories.

    Mirrors the real project layout so install_agents()'s prompt rewriting
    matches production behavior, and patches PACKAGED_AGENT_INSTRUCTIONS /
    STABLE_AGENT_INSTRUCTIONS so sync_agent_instructions() stays confined to
    tmp_path instead of touching the real packaged file or data_dir().
    """
    project_root = tmp_path / "project_root"
    source = project_root / "cve_agent" / "agents"
    target = tmp_path / "target"
    stable_dir = tmp_path / "stable_data_dir"
    source.mkdir(parents=True)
    target.mkdir()
    packaged_instructions = project_root / "cve_agent" / "AGENT_INSTRUCTIONS.md"
    packaged_instructions.write_text("instructions")
    stable_instructions = stable_dir / "AGENT_INSTRUCTIONS.md"

    # Create source agent JSONs with a file:// prompt URI
    for name in REQUIRED_AGENTS:
        (source / f"{name}.json").write_text(
            f'{{"name": "{name}", "prompt": "file://cve_agent/AGENT_INSTRUCTIONS.md"}}')

    monkeypatch.setattr("cve_agent.setup.AGENT_SOURCE_DIR", source)
    monkeypatch.setattr("cve_agent.setup.KIRO_AGENTS_DIR", target)
    monkeypatch.setattr("cve_agent.setup.PACKAGED_AGENT_INSTRUCTIONS", packaged_instructions)
    monkeypatch.setattr("cve_agent.setup.STABLE_AGENT_INSTRUCTIONS", stable_instructions)
    return source, target


def test_get_missing_agents_all_missing(fake_dirs):
    _, _ = fake_dirs
    missing = get_missing_agents()
    assert set(missing) == set(REQUIRED_AGENTS)


def test_get_missing_agents_none_missing(fake_dirs):
    source, target = fake_dirs
    for name in REQUIRED_AGENTS:
        (target / f"{name}.json").symlink_to(source / f"{name}.json")
    assert get_missing_agents() == []


def test_get_missing_agents_detects_stale_prompt_path(fake_dirs, tmp_path):
    """An installed agent whose prompt file:// URI no longer resolves (e.g.
    the project was relocated after install) must be treated as missing so
    it gets reinstalled with a corrected path, reproducing the bug where a
    stale install was silently treated as already present."""
    source, target = fake_dirs
    stale_prompt = tmp_path / "old-location" / "AGENT_INSTRUCTIONS.md"
    assert not stale_prompt.exists()

    for name in REQUIRED_AGENTS:
        (target / f"{name}.json").write_text(
            f'{{"name": "{name}", "prompt": "file://{stale_prompt}"}}')

    # Bug: file exists on disk, so a pure existence check would miss this.
    for name in REQUIRED_AGENTS:
        assert (target / f"{name}.json").exists()

    missing = get_missing_agents()
    assert set(missing) == set(REQUIRED_AGENTS)


def test_get_missing_agents_valid_prompt_path_not_missing(fake_dirs, tmp_path):
    """An installed agent whose prompt file:// URI resolves to a real file
    must not be reported as missing."""
    source, target = fake_dirs
    real_prompt = tmp_path / "AGENT_INSTRUCTIONS.md"
    real_prompt.write_text("instructions")

    for name in REQUIRED_AGENTS:
        (target / f"{name}.json").write_text(
            f'{{"name": "{name}", "prompt": "file://{real_prompt}"}}')

    assert get_missing_agents() == []


def test_get_missing_agents_malformed_json_treated_as_missing(fake_dirs):
    """Malformed JSON in an installed agent file must not crash detection
    and should be treated as missing (safe default)."""
    source, target = fake_dirs
    for name in REQUIRED_AGENTS:
        (target / f"{name}.json").write_text("{not valid json")

    missing = get_missing_agents()
    assert set(missing) == set(REQUIRED_AGENTS)


def test_ensure_agents_reinstalls_stale_prompt_path(fake_dirs, tmp_path, monkeypatch):
    """Regression test: ensure_agents() must reinstall (not silently accept)
    an agent whose prompt path is stale, fixing it non-interactively."""
    source, target = fake_dirs
    stale_prompt = tmp_path / "old-location" / "AGENT_INSTRUCTIONS.md"
    for name in REQUIRED_AGENTS:
        (target / f"{name}.json").write_text(
            f'{{"name": "{name}", "prompt": "file://{stale_prompt}"}}')

    monkeypatch.setattr("cve_agent.setup.check_kiro_cli", lambda: True)
    ensure_agents(interactive=False)

    assert verify_agents_installed() is True
    for name in REQUIRED_AGENTS:
        data = json.loads((target / f"{name}.json").read_text())
        assert data['prompt'].startswith('file:///')
        assert data['prompt'] == f"file://{setup.STABLE_AGENT_INSTRUCTIONS}"
        assert str(stale_prompt) not in data['prompt']


def test_verify_agents_installed_false(fake_dirs):
    assert verify_agents_installed() is False


def test_verify_agents_installed_true(fake_dirs):
    source, target = fake_dirs
    for name in REQUIRED_AGENTS:
        (target / f"{name}.json").symlink_to(source / f"{name}.json")
    assert verify_agents_installed() is True


def test_install_agents_creates_symlinks(fake_dirs):
    source, target = fake_dirs
    result = install_agents(list(REQUIRED_AGENTS))
    assert result is True
    for name in REQUIRED_AGENTS:
        installed = target / f"{name}.json"
        assert installed.exists()
        assert not installed.is_symlink()
        data = json.loads(installed.read_text())
        assert data['name'] == name
        assert data['prompt'].startswith('file:///')
        assert data['prompt'] == f"file://{setup.STABLE_AGENT_INSTRUCTIONS}"


def test_install_agents_missing_source(fake_dirs):
    source, _ = fake_dirs
    (source / f"{REQUIRED_AGENTS[0]}.json").unlink()
    result = install_agents([REQUIRED_AGENTS[0]])
    assert result is False


def test_install_agents_creates_target_dir(tmp_path, monkeypatch):
    source = tmp_path / "source"
    target = tmp_path / "nonexistent" / "agents"
    packaged_instructions = tmp_path / "packaged" / "AGENT_INSTRUCTIONS.md"
    stable_instructions = tmp_path / "stable_data_dir" / "AGENT_INSTRUCTIONS.md"
    source.mkdir()
    packaged_instructions.parent.mkdir()
    packaged_instructions.write_text("instructions")
    (source / f"{REQUIRED_AGENTS[0]}.json").write_text(
        '{"prompt": "file://cve_agent/AGENT_INSTRUCTIONS.md"}')

    monkeypatch.setattr("cve_agent.setup.AGENT_SOURCE_DIR", source)
    monkeypatch.setattr("cve_agent.setup.KIRO_AGENTS_DIR", target)
    monkeypatch.setattr("cve_agent.setup.PACKAGED_AGENT_INSTRUCTIONS", packaged_instructions)
    monkeypatch.setattr("cve_agent.setup.STABLE_AGENT_INSTRUCTIONS", stable_instructions)

    result = install_agents([REQUIRED_AGENTS[0]])
    assert result is True
    assert target.exists()

    data = json.loads((target / f"{REQUIRED_AGENTS[0]}.json").read_text())
    assert data['prompt'] == f"file://{stable_instructions}"
    assert stable_instructions.is_file()


def test_check_kiro_cli_found():
    with patch("shutil.which", return_value="/usr/bin/kiro-cli"):
        assert check_kiro_cli() is True


def test_check_kiro_cli_not_found():
    with patch("shutil.which", return_value=None):
        assert check_kiro_cli() is False


def test_sync_agent_instructions_copies_to_stable_path(fake_dirs):
    result = sync_agent_instructions()
    assert result == setup.STABLE_AGENT_INSTRUCTIONS
    assert setup.STABLE_AGENT_INSTRUCTIONS.is_file()
    assert setup.STABLE_AGENT_INSTRUCTIONS.read_text() == "instructions"


def test_sync_agent_instructions_overwrites_existing_stable_copy(fake_dirs):
    setup.STABLE_AGENT_INSTRUCTIONS.parent.mkdir(parents=True, exist_ok=True)
    setup.STABLE_AGENT_INSTRUCTIONS.write_text("old content")

    sync_agent_instructions()

    assert setup.STABLE_AGENT_INSTRUCTIONS.read_text() == "instructions"


def test_sync_agent_instructions_propagates_content_upgrades(fake_dirs):
    """A newer packaged AGENT_INSTRUCTIONS.md must overwrite the stable copy
    on re-sync, so content upgrades reach the kiro agent's prompt."""
    sync_agent_instructions()
    assert setup.STABLE_AGENT_INSTRUCTIONS.read_text() == "instructions"

    setup.PACKAGED_AGENT_INSTRUCTIONS.write_text("updated instructions v2")
    sync_agent_instructions()

    assert setup.STABLE_AGENT_INSTRUCTIONS.read_text() == "updated instructions v2"


def test_sync_agent_instructions_missing_packaged_file_raises(fake_dirs):
    setup.PACKAGED_AGENT_INSTRUCTIONS.unlink()
    with pytest.raises(FileNotFoundError):
        sync_agent_instructions()


def test_sync_agent_instructions_stable_path_independent_of_package_location(
        fake_dirs, tmp_path, monkeypatch):
    """Simulate the packaged file moving to a different location entirely
    (e.g. project relocated, or reinstalled into a different venv). Once
    synced, the stable copy and its content remain unaffected — this is the
    property that decouples the kiro agent's prompt from source location."""
    sync_agent_instructions()
    original_stable_mtime_content = setup.STABLE_AGENT_INSTRUCTIONS.read_text()

    # "Move" the package: point PACKAGED_AGENT_INSTRUCTIONS somewhere else.
    new_location = tmp_path / "new_package_location" / "AGENT_INSTRUCTIONS.md"
    new_location.parent.mkdir(parents=True)
    new_location.write_text(original_stable_mtime_content)
    monkeypatch.setattr("cve_agent.setup.PACKAGED_AGENT_INSTRUCTIONS", new_location)

    # STABLE_AGENT_INSTRUCTIONS path itself never changes and still resolves.
    assert setup.STABLE_AGENT_INSTRUCTIONS.is_file()
    assert setup.STABLE_AGENT_INSTRUCTIONS.read_text() == original_stable_mtime_content


def test_ensure_agents_syncs_instructions_even_when_already_installed(fake_dirs, monkeypatch):
    """ensure_agents() must re-sync AGENT_INSTRUCTIONS.md even when no agent
    JSON needs reinstalling, so packaged content upgrades still propagate."""
    source, target = fake_dirs
    for name in REQUIRED_AGENTS:
        (target / f"{name}.json").write_text(
            f'{{"name": "{name}", "prompt": "file://{setup.STABLE_AGENT_INSTRUCTIONS}"}}')
    setup.STABLE_AGENT_INSTRUCTIONS.parent.mkdir(parents=True, exist_ok=True)
    setup.STABLE_AGENT_INSTRUCTIONS.write_text("stale content")

    monkeypatch.setattr("cve_agent.setup.check_kiro_cli", lambda: True)
    assert verify_agents_installed() is True  # nothing to reinstall

    ensure_agents(interactive=False)

    assert setup.STABLE_AGENT_INSTRUCTIONS.read_text() == "instructions"


def test_ensure_agents_exits_when_packaged_instructions_missing(fake_dirs, monkeypatch):
    setup.PACKAGED_AGENT_INSTRUCTIONS.unlink()
    monkeypatch.setattr("cve_agent.setup.check_kiro_cli", lambda: True)
    with pytest.raises(SystemExit):
        ensure_agents(interactive=False)


def test_ensure_agents_exits_without_kiro_cli(monkeypatch):
    monkeypatch.setattr("cve_agent.setup.check_kiro_cli", lambda: False)
    with pytest.raises(SystemExit):
        ensure_agents()


def test_ensure_agents_noop_when_installed(fake_dirs, monkeypatch):
    source, target = fake_dirs
    for name in REQUIRED_AGENTS:
        (target / f"{name}.json").symlink_to(source / f"{name}.json")
    monkeypatch.setattr("cve_agent.setup.check_kiro_cli", lambda: True)
    ensure_agents()


def test_ensure_agents_auto_installs_non_interactive(fake_dirs, monkeypatch):
    monkeypatch.setattr("cve_agent.setup.check_kiro_cli", lambda: True)
    ensure_agents(interactive=False)
    assert verify_agents_installed() is True


def test_ensure_agents_prompts_and_installs(fake_dirs, monkeypatch):
    monkeypatch.setattr("cve_agent.setup.check_kiro_cli", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "y")
    ensure_agents(interactive=True)
    assert verify_agents_installed() is True


def test_ensure_agents_prompts_and_declines(fake_dirs, monkeypatch):
    monkeypatch.setattr("cve_agent.setup.check_kiro_cli", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "n")
    with pytest.raises(SystemExit):
        ensure_agents(interactive=True)
