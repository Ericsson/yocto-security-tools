# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent — data classes, config, and helpers."""
from pathlib import Path
from unittest.mock import patch

from cve_agent import (
    EXIT_NOT_APPLICABLE,
    RECOVERABLE_EXITS,
    UNRECOVERABLE_EXITS,
    AgentConfig,
    ResultStatus,
    get_agent_dir,
    resolve_agent_instructions,
)


def test_agent_config_defaults():
    cfg = AgentConfig(cve_id="CVE-2025-0001", cve_info_path=Path("/tmp/cve.json"))
    assert cfg.trust_mode is False
    assert cfg.max_retries == 3
    assert cfg.skip_ptest is False
    assert cfg.clean is False
    assert cfg.mirror_dir is None
    assert cfg.meta_layer is None


def test_result_status_values():
    assert ResultStatus.SUCCESS.value == "success"
    assert ResultStatus.CONFLICT_RESOLVED.value == "conflict_resolved"
    assert ResultStatus.FAILED.value == "failed"
    assert ResultStatus.ESCALATED.value == "escalated"
    assert ResultStatus.SKIPPED.value == "skipped"


def test_get_agent_dir(tmp_path):
    ws = tmp_path / "build" / "workspace" / "sources" / "busybox"
    ws.mkdir(parents=True)
    agent_dir = get_agent_dir(ws)
    assert agent_dir == tmp_path / "build" / "workspace" / "cve_agent" / "busybox"
    assert agent_dir.exists()


def test_exit_code_sets():
    assert 1 in RECOVERABLE_EXITS   # CONFLICT
    assert 3 in RECOVERABLE_EXITS   # PTEST_ERROR
    assert 4 in RECOVERABLE_EXITS   # BUILD_ERROR
    assert 2 in UNRECOVERABLE_EXITS  # CHECKOUT_ERROR
    assert 5 in UNRECOVERABLE_EXITS  # PATCH_ERROR
    assert RECOVERABLE_EXITS.isdisjoint(UNRECOVERABLE_EXITS)


def test_exit_not_applicable_in_unrecoverable():
    assert EXIT_NOT_APPLICABLE in UNRECOVERABLE_EXITS
    assert EXIT_NOT_APPLICABLE not in RECOVERABLE_EXITS


def test_resolve_agent_instructions_prefers_stable_copy(tmp_path):
    stable = tmp_path / "stable" / "AGENT_INSTRUCTIONS.md"
    packaged = tmp_path / "packaged" / "AGENT_INSTRUCTIONS.md"
    stable.parent.mkdir()
    packaged.parent.mkdir()
    stable.write_text("stable")
    packaged.write_text("packaged")

    with patch("cve_agent.setup.STABLE_AGENT_INSTRUCTIONS", stable), \
         patch("cve_agent.setup.PACKAGED_AGENT_INSTRUCTIONS", packaged):
        assert resolve_agent_instructions() == stable


def test_resolve_agent_instructions_falls_back_to_packaged(tmp_path):
    stable = tmp_path / "stable" / "AGENT_INSTRUCTIONS.md"  # never created
    packaged = tmp_path / "packaged" / "AGENT_INSTRUCTIONS.md"
    packaged.parent.mkdir()
    packaged.write_text("packaged")

    with patch("cve_agent.setup.STABLE_AGENT_INSTRUCTIONS", stable), \
         patch("cve_agent.setup.PACKAGED_AGENT_INSTRUCTIONS", packaged):
        assert resolve_agent_instructions() == packaged
