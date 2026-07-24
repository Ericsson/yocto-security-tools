# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent.context — context building helpers."""
from pathlib import Path
from unittest.mock import patch as mock_patch

from cve_agent import EXIT_CONFLICT, EXIT_SUCCESS
from cve_agent.context import _build_phase_instructions, _gather_interdiff, build_context


def test_build_phase_instructions_file_exists(tmp_path):
    """When the instructions file exists, a short pointer is returned —
    not the full file content, which already reaches the model via the
    system prompt (see cve_agent.kiro_backend / cve_agent.claude_backend)."""
    instructions = tmp_path / "AGENT_INSTRUCTIONS.md"
    instructions.write_text("# Instructions\nDo the thing.")
    with mock_patch("cve_agent.context.resolve_agent_instructions", return_value=instructions):
        result = _build_phase_instructions()
    assert "Do the thing" not in result
    assert "AGENT_INSTRUCTIONS.md" in result


def test_build_phase_instructions_missing(tmp_path):
    missing = tmp_path / "nonexistent.md"
    with mock_patch("cve_agent.context.resolve_agent_instructions", return_value=missing):
        result = _build_phase_instructions()
    assert "AGENT_INSTRUCTIONS.md" in result


class TestGatherInterdiff:
    @mock_patch("cve_agent.context.generate_interdiff", return_value="-old\n+new\n")
    @mock_patch("cve_agent.context.run_git_stdout", return_value="diff text")
    @mock_patch("cve_agent.context.get_upstream_sha", return_value="abc123456789")
    def test_returns_section_when_available(self, mock_sha, mock_git, mock_interdiff):
        result = _gather_interdiff(Path("/ws"), {})
        assert "Interdiff (upstream" in result
        assert "-old\n+new\n" in result

    @mock_patch("cve_agent.context.generate_interdiff", return_value=None)
    @mock_patch("cve_agent.context.run_git_stdout", return_value="diff text")
    @mock_patch("cve_agent.context.get_upstream_sha", return_value="abc123456789")
    def test_returns_empty_when_interdiff_unavailable(self, mock_sha, mock_git, mock_interdiff):
        result = _gather_interdiff(Path("/ws"), {})
        assert result == ""

    @mock_patch("cve_agent.context.generate_interdiff")
    @mock_patch("cve_agent.context.get_upstream_sha", return_value="unknown")
    def test_returns_empty_when_no_upstream_sha(self, mock_sha, mock_interdiff):
        result = _gather_interdiff(Path("/ws"), {})
        assert result == ""
        mock_interdiff.assert_not_called()


class TestBuildContextInterdiffWiring:
    @mock_patch("cve_agent.context._gather_interdiff", return_value="## Interdiff (upstream → backport)\n\ndelta")
    @mock_patch("cve_agent.context._gather_knowledge", return_value="")
    @mock_patch("cve_agent.context._gather_context_for_exit_code", return_value="ctx")
    @mock_patch("cve_agent.context._build_phase_instructions", return_value="instr")
    @mock_patch("cve_agent.context._build_header", return_value="header")
    def test_interdiff_section_included_for_non_conflict_phase(
            self, mock_header, mock_instr, mock_ctx, mock_knowledge, mock_interdiff, tmp_path):
        with mock_patch("cve_agent.context.get_agent_dir", return_value=tmp_path):
            context_file = build_context(
                tmp_path, EXIT_SUCCESS, "CVE-2025-0001", {'name': 'busybox'}
            )
        content = context_file.read_text(encoding='utf-8')
        assert "Interdiff (upstream" in content
        mock_interdiff.assert_called_once()

    @mock_patch("cve_agent.context._gather_interdiff", return_value="## Interdiff (upstream → backport)\n\ndelta")
    @mock_patch("cve_agent.context._gather_knowledge", return_value="")
    @mock_patch("cve_agent.context._gather_context_for_exit_code", return_value="ctx")
    @mock_patch("cve_agent.context._build_phase_instructions", return_value="instr")
    @mock_patch("cve_agent.context._build_header", return_value="header")
    def test_interdiff_skipped_for_conflict_phase(
            self, mock_header, mock_instr, mock_ctx, mock_knowledge, mock_interdiff, tmp_path):
        with mock_patch("cve_agent.context.get_agent_dir", return_value=tmp_path):
            context_file = build_context(
                tmp_path, EXIT_CONFLICT, "CVE-2025-0001", {'name': 'busybox'}
            )
        content = context_file.read_text(encoding='utf-8')
        assert "Interdiff (upstream" not in content
        mock_interdiff.assert_not_called()

    @mock_patch("cve_agent.context._gather_interdiff", return_value="")
    @mock_patch("cve_agent.context._gather_knowledge", return_value="")
    @mock_patch("cve_agent.context._gather_context_for_exit_code", return_value="ctx")
    @mock_patch("cve_agent.context._build_phase_instructions", return_value="instr")
    @mock_patch("cve_agent.context._build_header", return_value="header")
    def test_no_section_when_interdiff_empty(
            self, mock_header, mock_instr, mock_ctx, mock_knowledge, mock_interdiff, tmp_path):
        with mock_patch("cve_agent.context.get_agent_dir", return_value=tmp_path):
            context_file = build_context(
                tmp_path, EXIT_SUCCESS, "CVE-2025-0001", {'name': 'busybox'}
            )
        content = context_file.read_text(encoding='utf-8')
        assert "Interdiff (upstream" not in content
