# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for preserving upstream commit message during backport resolution.

Verifies that amend_commit_with_summary restores the original upstream
commit message when the AI replaced it with backport notes.
"""
from pathlib import Path
from unittest.mock import patch

from cve_agent.review import _dedupe_agent_notes, amend_commit_with_summary

UPSTREAM_SHA = "97acf3dfda80c91c3a8c9f2372546301d4a1a7a8"
UPSTREAM_SUBJECT = (
    "transport.c: Additional boundary checks for packet length (#2052)"
)
UPSTREAM_BODY = (
    "Add upper-bound check on packet_length against\n"
    "LIBSSH2_PACKET_MAXPAYLOAD to prevent OOB write.\n"
    "\n"
    "Closes #2050"
)


class TestPreserveOriginalCommitMessage:
    """Bug: AI replaces original upstream message with backport notes."""

    @patch("subprocess.run")
    @patch("cve_agent.review.run_git_stdout")
    def test_restores_original_when_ai_replaced_message(
        self, mock_git, mock_run
    ):
        """When the AI wrote 'Conflicts Resolved:' as the message body
        (replacing the original), amend_commit_with_summary should restore
        the original upstream subject+body and append backport notes after."""
        # Simulate AI having replaced the message entirely
        ai_replaced_msg = (
            "transport.c: Additional boundary checks for packet length (#2052)\n"
            "\n"
            "Conflicts Resolved:\n"
            "\n"
            "src/transport.c (1 conflict):\n"
            "- Upstream uses ssh2_ntohu32(); stable uses _libssh2_ntohu32().\n"
            "\n"
            "Assisted-by: kiro:claude-sonnet-4.6\n"
        )

        def git_side_effect(args, cwd):
            if '--format=%B' in args:
                return ai_replaced_msg
            if '--format=%s' in args and UPSTREAM_SHA in args:
                return UPSTREAM_SUBJECT
            if '--format=%b' in args and UPSTREAM_SHA in args:
                return UPSTREAM_BODY
            return ""

        mock_git.side_effect = git_side_effect
        mock_run.return_value = type("R", (), {"returncode": 0})()

        amend_commit_with_summary(
            Path("/ws"), UPSTREAM_SHA, "Changes from upstream commit 97acf3dfda80:\n  - src/transport.c: adapted from upstream"
        )

        mock_run.assert_called_once()
        final_msg = mock_run.call_args[0][0][-1]

        # Original subject must be present
        assert UPSTREAM_SUBJECT in final_msg
        # Original body must be restored
        assert "LIBSSH2_PACKET_MAXPAYLOAD" in final_msg
        assert "Closes #2050" in final_msg
        # Kiro notes must still be present
        assert "Conflicts Resolved:" in final_msg
        # Summary must be appended
        assert "Changes from upstream commit" in final_msg

    @patch("subprocess.run")
    @patch("cve_agent.review.run_git_stdout")
    def test_no_restore_when_original_preserved(self, mock_git, mock_run):
        """When the AI correctly appended notes after the original message,
        amend_commit_with_summary should just append the summary."""
        # AI properly preserved the original and appended
        preserved_msg = (
            "transport.c: Additional boundary checks for packet length (#2052)\n"
            "\n"
            "Add upper-bound check on packet_length against\n"
            "LIBSSH2_PACKET_MAXPAYLOAD to prevent OOB write.\n"
            "\n"
            "Closes #2050\n"
            "\n"
            "Conflicts Resolved:\n"
            "\n"
            "src/transport.c (1 conflict):\n"
            "- Upstream uses ssh2_ntohu32(); stable uses _libssh2_ntohu32().\n"
            "\n"
            "Assisted-by: kiro:claude-sonnet-4.6\n"
        )

        def git_side_effect(args, cwd):
            if '--format=%B' in args:
                return preserved_msg
            if '--format=%s' in args and UPSTREAM_SHA in args:
                return UPSTREAM_SUBJECT
            if '--format=%b' in args and UPSTREAM_SHA in args:
                return UPSTREAM_BODY
            return ""

        mock_git.side_effect = git_side_effect
        mock_run.return_value = type("R", (), {"returncode": 0})()

        amend_commit_with_summary(
            Path("/ws"), UPSTREAM_SHA, "Changes from upstream commit 97acf3dfda80:\n  - src/transport.c: adapted"
        )

        mock_run.assert_called_once()
        final_msg = mock_run.call_args[0][0][-1]

        # Original body preserved
        assert "Closes #2050" in final_msg
        # Kiro notes preserved
        assert "Conflicts Resolved:" in final_msg
        # Summary appended
        assert "Changes from upstream commit" in final_msg

    @patch("subprocess.run")
    @patch("cve_agent.review.run_git_stdout")
    def test_body_only_replaced_no_subject_match(self, mock_git, mock_run):
        """When the AI wrote a completely different subject line (edge case),
        the original should be restored from upstream SHA."""
        ai_msg = (
            "Conflicts Resolved:\n"
            "\n"
            "src/transport.c (1 conflict):\n"
            "- Adapted API call.\n"
        )

        def git_side_effect(args, cwd):
            if '--format=%B' in args:
                return ai_msg
            if '--format=%s' in args and UPSTREAM_SHA in args:
                return UPSTREAM_SUBJECT
            if '--format=%b' in args and UPSTREAM_SHA in args:
                return UPSTREAM_BODY
            return ""

        mock_git.side_effect = git_side_effect
        mock_run.return_value = type("R", (), {"returncode": 0})()

        amend_commit_with_summary(Path("/ws"), UPSTREAM_SHA, "summary")

        mock_run.assert_called_once()
        final_msg = mock_run.call_args[0][0][-1]

        # Original subject restored
        assert UPSTREAM_SUBJECT in final_msg
        # Original body restored
        assert "Closes #2050" in final_msg
        # AI notes kept
        assert "Conflicts Resolved:" in final_msg


class TestDedupeDuplicateNoteBlocks:
    """Bug: repeated AI resolution attempts duplicate the agent note block.

    When the resolution loop runs the AI backend more than once for the
    same CVE (e.g. a conflict is resolved, then a later ptest/build
    failure triggers another AI session), the backend may append a
    fresh ``Conflicts Resolved:`` / ``Assisted-by:`` block on top of the
    one already present from an earlier attempt instead of updating it
    in place, producing duplicated justification text in the final
    commit message.
    """

    def test_dedupe_removes_earlier_duplicate_blocks(self):
        """_dedupe_agent_notes keeps only the last note block."""
        msg = (
            UPSTREAM_SUBJECT + "\n\n" + UPSTREAM_BODY + "\n\n"
            "Conflicts Resolved:\n\n"
            "src/transport.c (1 conflict):\n"
            "- resolution details from attempt 1\n\n"
            "Assisted-by: kiro:claude-sonnet-5\n\n"
            "Conflicts Resolved:\n\n"
            "src/transport.c (1 conflict):\n"
            "- resolution details from attempt 2\n\n"
            "Assisted-by: kiro:claude-sonnet-5\n"
        )

        deduped = _dedupe_agent_notes(msg)

        assert deduped.count("Conflicts Resolved:") == 1
        assert deduped.count("Assisted-by:") == 1
        assert "attempt 1" not in deduped
        assert "attempt 2" in deduped
        assert UPSTREAM_SUBJECT in deduped
        assert "LIBSSH2_PACKET_MAXPAYLOAD" in deduped

    def test_dedupe_noop_when_single_block(self):
        """_dedupe_agent_notes leaves a single note block untouched."""
        msg = (
            UPSTREAM_SUBJECT + "\n\n" + UPSTREAM_BODY + "\n\n"
            "Conflicts Resolved:\n\n"
            "src/transport.c (1 conflict):\n"
            "- resolution details\n\n"
            "Assisted-by: kiro:claude-sonnet-5\n"
        )

        assert _dedupe_agent_notes(msg) == msg

    @patch("subprocess.run")
    @patch("cve_agent.review.run_git_stdout")
    def test_amend_commit_dedupes_before_appending_summary(
        self, mock_git, mock_run
    ):
        """End-to-end: amend_commit_with_summary strips duplicate note
        blocks left by repeated AI resolution attempts before appending
        the change summary."""
        duplicated_msg = (
            UPSTREAM_SUBJECT + "\n\n" + UPSTREAM_BODY + "\n\n"
            "Conflicts Resolved:\n\n"
            "libarchive/archive_read_support_format_rar5.c (1 conflict):\n"
            "- resolution details from attempt 1\n\n"
            "Assisted-by: kiro:claude-sonnet-5\n\n"
            "Conflicts Resolved:\n\n"
            "libarchive/archive_read_support_format_rar5.c (1 conflict):\n"
            "- resolution details from attempt 2\n\n"
            "Assisted-by: kiro:claude-sonnet-5\n"
        )

        def git_side_effect(args, cwd):
            if '--format=%B' in args:
                return duplicated_msg
            if '--format=%s' in args and UPSTREAM_SHA in args:
                return UPSTREAM_SUBJECT
            if '--format=%b' in args and UPSTREAM_SHA in args:
                return UPSTREAM_BODY
            return ""

        mock_git.side_effect = git_side_effect
        mock_run.return_value = type("R", (), {"returncode": 0})()

        amend_commit_with_summary(
            Path("/ws"), UPSTREAM_SHA,
            "Changes from upstream commit 97acf3dfda80:\n"
            "  - libarchive/archive_read_support_format_rar5.c: adapted"
        )

        mock_run.assert_called_once()
        final_msg = mock_run.call_args[0][0][-1]

        assert final_msg.count("Conflicts Resolved:") == 1
        assert final_msg.count("Assisted-by:") == 1
        assert "attempt 1" not in final_msg
        assert "attempt 2" in final_msg
        assert "Changes from upstream commit" in final_msg
