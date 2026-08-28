# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for the orchestrator's post-session commit-note budget gate."""
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cve_agent import AgentConfig, ResultStatus
from cve_agent.commit_notes import MAX_WORDS_SOFT
from cve_agent.orchestrator import (
    _MAX_NOTE_REJECTS,
    _AttemptOutcome,
    _make_result,
    _resolution_loop,
    _run_single_resolution_attempt,
    validate_commit_notes,
)
from cve_agent.session import SessionResult

COMPLIANT_MSG = (
    "Fix a use-after-free\n\n"
    "Conflicts Resolved:\n\n"
    "a.c (1 conflict):\n"
    "- Adapted foo_v2() to the stable foo_v1() signature.\n"
)

HARD_MSG = (
    "Fix a use-after-free\n\n"
    "Conflicts Resolved:\n\n"
    "a.c (1 conflict):\n"
    + '\n'.join('- ' + ' '.join(f'w{i}' for i in range(25)) for _ in range(2))
    + '\n'
)

SOFT_MSG = (
    "Fix a use-after-free\n\n"
    "Conflicts Resolved:\n\n"
    "a.c (1 conflict):\n"
    "- " + ' '.join(f'w{i}' for i in range(MAX_WORDS_SOFT + 4)) + '\n'
)


def _cfg(**kwargs):
    defaults = dict(cve_id="CVE-2025-0001", cve_info_path=Path("/tmp/c.json"))
    defaults.update(kwargs)
    return AgentConfig(**defaults)


def _git_stub(commit_msg):
    """Fake run_git_stdout: HEAD message on demand, a stable SHA otherwise."""
    def fake(args, *a, **kw):
        if args[:2] == ['log', '-1']:
            return commit_msg
        return "abc123"
    return fake


# --- validate_commit_notes ---

class TestValidateCommitNotes:
    def test_clean_message_has_no_violations(self):
        with patch("cve_agent.orchestrator.run_git_stdout",
                   _git_stub(COMPLIANT_MSG)):
            assert validate_commit_notes(Path("/ws")) == []

    def test_over_budget_message_is_reported(self):
        with patch("cve_agent.orchestrator.run_git_stdout",
                   _git_stub(HARD_MSG)):
            violations = validate_commit_notes(Path("/ws"))
        assert [v.filename for v in violations] == ['a.c']


# --- the gate inside a resolution attempt ---

@pytest.fixture
def attempt_env(tmp_path):
    """Patch everything a resolution attempt needs, keeping the gate real."""
    ws = tmp_path / "ws"
    ws.mkdir()
    agent_dir = tmp_path / "agent"
    agent_dir.mkdir()

    with patch("cve_agent.orchestrator.compute_allowed_files",
               return_value={"a.c"}), \
         patch("cve_agent.orchestrator.build_context",
               return_value=Path("/ctx")), \
         patch("cve_agent.orchestrator.get_upstream_sha", return_value="abc"), \
         patch("cve_agent.orchestrator.guarded_session",
               return_value=SessionResult(resolved=True, duration=1.0)), \
         patch("cve_agent.orchestrator._read_conclusion", return_value=None), \
         patch("cve_agent.orchestrator._read_escalation", return_value=None), \
         patch("cve_agent.orchestrator._clear_conclusion"), \
         patch("cve_agent.orchestrator.get_agent_dir",
               return_value=agent_dir), \
         patch("cve_agent.orchestrator._finalize_resolution",
               return_value=_AttemptOutcome()), \
         patch("cve_agent.orchestrator.request_approval",
               return_value=("approved", "")) as approval:
        yield ws, agent_dir, approval


def _attempt(ws, commit_msg, note_rejects=0):
    with patch("cve_agent.orchestrator.run_git_stdout", _git_stub(commit_msg)):
        return _run_single_resolution_attempt(
            _cfg(), ws, 1, {}, MagicMock(), 1, time.monotonic(), note_rejects)


class TestNoteBudgetGate:
    def test_hard_violation_bounces_with_feedback(self, attempt_env):
        ws, agent_dir, approval = attempt_env
        outcome = _attempt(ws, HARD_MSG)
        assert outcome.note_rejected is True
        assert outcome.result is None
        approval.assert_not_called()
        feedback = (agent_dir / "human_feedback.txt").read_text()
        assert "REJECTED a.c" in feedback
        assert "Do not change" in feedback
        assert "--amend --no-edit" in feedback

    def test_bounce_preserves_existing_human_feedback(self, attempt_env):
        ws, agent_dir, _ = attempt_env
        (agent_dir / "human_feedback.txt").write_text("keep the memcpy bounds")
        _attempt(ws, HARD_MSG)
        feedback = (agent_dir / "human_feedback.txt").read_text()
        assert "keep the memcpy bounds" in feedback
        assert "REJECTED a.c" in feedback

    def test_clean_notes_reach_approval(self, attempt_env):
        ws, agent_dir, approval = attempt_env
        outcome = _attempt(ws, COMPLIANT_MSG)
        assert outcome.note_rejected is False
        approval.assert_called_once()
        assert not (agent_dir / "human_feedback.txt").exists()

    def test_soft_violation_reaches_approval(self, attempt_env, capsys):
        ws, agent_dir, approval = attempt_env
        outcome = _attempt(ws, SOFT_MSG)
        assert outcome.note_rejected is False
        approval.assert_called_once()
        assert not (agent_dir / "human_feedback.txt").exists()
        assert "WARNING" in capsys.readouterr().out

    def test_cap_reached_accepts_and_continues(self, attempt_env, capsys):
        ws, agent_dir, approval = attempt_env
        outcome = _attempt(ws, HARD_MSG, note_rejects=_MAX_NOTE_REJECTS)
        assert outcome.note_rejected is False
        approval.assert_called_once()
        assert not (agent_dir / "human_feedback.txt").exists()
        assert "still over budget" in capsys.readouterr().out

    def test_violation_is_recorded_in_the_audit_log(self, attempt_env):
        ws, agent_dir, _ = attempt_env
        _attempt(ws, HARD_MSG)
        log = agent_dir / f"{ws.name}-CVE-2025-0001-ai-changes.log"
        assert "Commit note budget" in log.read_text()


# --- the loop's bounce counter ---

class TestNoteRejectCounter:
    def test_loop_increments_the_counter_per_bounce(self, tmp_path):
        seen = []

        def fake_attempt(config, ws, step, cve_info, kb, attempt, start,
                         note_rejects=0):
            seen.append(note_rejects)
            if note_rejects >= _MAX_NOTE_REJECTS:
                return _AttemptOutcome(result=_make_result(
                    config.cve_id, ResultStatus.CONFLICT_RESOLVED, attempt,
                    start, "accepted with warning"))
            return _AttemptOutcome(note_rejected=True)

        with patch("cve_agent.orchestrator._run_single_resolution_attempt",
                   fake_attempt):
            result = _resolution_loop(_cfg(max_retries=1), tmp_path, 1, {}, None)

        # max_retries=1 must still allow both bounces: a prose bounce is not a
        # resolution attempt, so it must not burn the retry budget.
        assert seen == [0, 1, 2]
        assert result.status == ResultStatus.CONFLICT_RESOLVED

    def test_bounces_cannot_escalate_a_correct_backport(self, tmp_path):
        """An always-verbose AI must end at approval, never ESCALATED."""
        attempts = []

        def fake_attempt(config, ws, step, cve_info, kb, attempt, start,
                         note_rejects=0):
            attempts.append(note_rejects)
            if note_rejects >= _MAX_NOTE_REJECTS:
                return _AttemptOutcome(result=_make_result(
                    config.cve_id, ResultStatus.CONFLICT_RESOLVED, attempt,
                    start, "accepted with warning"))
            return _AttemptOutcome(note_rejected=True)

        with patch("cve_agent.orchestrator._run_single_resolution_attempt",
                   fake_attempt):
            result = _resolution_loop(_cfg(max_retries=3), tmp_path, 1, {}, None)

        assert result.status is not ResultStatus.ESCALATED
        assert len(attempts) == _MAX_NOTE_REJECTS + 1

    def test_max_total_attempts_still_bounds_bounces(self, tmp_path):
        """The global ceiling must still stop a pathological loop."""
        with patch("cve_agent.orchestrator._run_single_resolution_attempt",
                   return_value=_AttemptOutcome(note_rejected=True)):
            result = _resolution_loop(
                _cfg(max_retries=3, max_total_attempts=2), tmp_path, 1, {}, None)
        assert result.status is ResultStatus.ESCALATED
