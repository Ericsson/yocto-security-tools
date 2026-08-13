# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent.context — context building helpers."""
from pathlib import Path
from unittest.mock import patch as mock_patch

from cve_agent import EXIT_BUILD_ERROR, EXIT_CONFLICT, EXIT_PTEST_ERROR, EXIT_SUCCESS
from cve_agent.context import _build_phase_instructions, _gather_interdiff, build_context


def test_build_phase_instructions_conflict():
    """Conflict phase embeds ONLY the conflict fragment (§2 + patterns)."""
    result = _build_phase_instructions(EXIT_CONFLICT)
    assert "## Instructions" in result
    assert "Resolve Conflicts" in result
    assert "Common Conflict Patterns" in result
    # Other phases' workflow must not leak into a conflict session.
    assert "Fix Build Errors" not in result
    assert "Fix Test Failures" not in result
    # Fragments carry no SPDX/license header (prompt files are streamed to
    # the model — a header would just pollute the context).
    assert "SPDX-License-Identifier" not in result


def test_build_phase_instructions_build():
    """Build phase embeds ONLY the build fragment (§3)."""
    result = _build_phase_instructions(EXIT_BUILD_ERROR)
    assert "Fix Build Errors" in result
    assert "cleansstate" in result
    assert "Resolve Conflicts" not in result
    assert "Fix Test Failures" not in result


def test_build_phase_instructions_ptest():
    """Ptest phase embeds ONLY the ptest fragment (§4)."""
    result = _build_phase_instructions(EXIT_PTEST_ERROR)
    assert "Fix Test Failures" in result
    assert "Never hand-edit" in result
    assert "Resolve Conflicts" not in result
    assert "Fix Build Errors" not in result


def test_build_phase_instructions_analysis_has_no_fragment():
    """Exit 0 (analysis) needs no fragment — the core Analyse step covers it."""
    assert _build_phase_instructions(EXIT_SUCCESS) == ""


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
