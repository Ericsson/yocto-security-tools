# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent.context — context building helpers."""
from unittest.mock import patch as mock_patch

from cve_agent.context import _build_phase_instructions


def test_build_phase_instructions_file_exists(tmp_path):
    instructions = tmp_path / "AGENT_INSTRUCTIONS.md"
    instructions.write_text("# Instructions\nDo the thing.")
    with mock_patch("cve_agent.context.resolve_agent_instructions", return_value=instructions):
        result = _build_phase_instructions()
    assert "Do the thing" in result


def test_build_phase_instructions_missing(tmp_path):
    missing = tmp_path / "nonexistent.md"
    with mock_patch("cve_agent.context.resolve_agent_instructions", return_value=missing):
        result = _build_phase_instructions()
    assert "AGENT_INSTRUCTIONS.md" in result
