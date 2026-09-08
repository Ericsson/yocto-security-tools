# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""State-based native-agent progress and budget policy tests."""
import json

import pytest

from cve_agent.openai_progress import (
    MAX_CONSECUTIVE_INSPECTIONS,
    MAX_STATE_SUMMARY_BYTES,
    ProgressTracker,
)
from cve_agent.openai_tools import ToolAudit, ToolResult


def _result(
    tool: str,
    *,
    generation: int = 0,
    success: bool = True,
    mutated: bool = False,
    terminal: bool = False,
    payload: dict[str, object] | None = None,
    error_kind: str | None = None,
) -> ToolResult:
    return ToolResult(
        success=success,
        payload=payload or {},
        mutated=mutated,
        terminal=terminal,
        error_kind=error_kind,
        audit=ToolAudit(
            tool, success, mutated, generation, error_kind=error_kind),
    )


def test_repeated_read_and_status_require_new_state_or_evidence():
    tracker = ProgressTracker()
    read = _result("read_file", payload={"content": "bounded"})
    assert tracker.observe(
        "read_file", '{"path":"a.c"}', read, dispatched=True).progressed
    assert not tracker.observe(
        "read_file", '{"path":"a.c"}', read, dispatched=True).progressed

    status = _result("git_status", payload={
        "staged": [], "unstaged": ["a.c"], "untracked": [],
        "deleted": [], "conflicted": ["a.c"],
    })
    assert tracker.observe("git_status", "{}", status, dispatched=True).progressed
    assert not tracker.observe("git_status", "{}", status, dispatched=True).progressed


def test_new_range_mutation_conflict_reduction_build_and_commit_progress():
    tracker = ProgressTracker()
    read = _result("read_file_range", payload={"content": "line"})
    assert tracker.observe(
        "read_file_range", '{"end_line":20,"path":"a.c","start_line":10}',
        read, dispatched=True).progressed
    assert tracker.observe(
        "read_file_range", '{"end_line":40,"path":"a.c","start_line":30}',
        read, dispatched=True).progressed

    edit = tracker.observe(
        "apply_patch_hunks", '{"path":"a.c"}',
        _result("apply_patch_hunks", generation=1, mutated=True),
        dispatched=True)
    assert edit.progressed and edit.kind == "mutation"

    first_status = _result("git_status", generation=1, payload={
        "staged": [], "unstaged": ["a.c", "b.c"], "untracked": [],
        "deleted": [], "conflicted": ["a.c", "b.c"],
    })
    second_status = _result("git_status", generation=1, payload={
        "staged": ["a.c"], "unstaged": ["b.c"], "untracked": [],
        "deleted": [], "conflicted": ["b.c"],
    })
    tracker.observe("git_status", "{}", first_status, dispatched=True)
    reduction = tracker.observe(
        "git_status", "{}", second_status, dispatched=True)
    assert reduction.kind == "conflict_reduction"

    build = _result("build_recipe", generation=1, payload={
        "exit_status": 0, "duration": 2.0, "log_path": "/one",
        "tail": "ok", "generation": 1,
    })
    assert tracker.observe("build_recipe", "{}", build, dispatched=True).progressed
    repeated_build = _result("build_recipe", generation=1, payload={
        "exit_status": 0, "duration": 9.0, "log_path": "/two",
        "tail": "ok", "generation": 1,
    })
    assert not tracker.observe(
        "build_recipe", "{}", repeated_build, dispatched=True).progressed

    commit = tracker.observe(
        "git_amend", '{"paths":["a.c"]}',
        _result("git_amend", generation=1, mutated=True), dispatched=True)
    assert commit.kind == "trusted_git_transition"


def test_state_summary_is_bounded_host_owned_and_secret_free():
    tracker = ProgressTracker()
    secret = "seeded-progress-secret"
    tracker.observe(
        "read_file", json.dumps({"path": secret}),
        _result("read_file", payload={"content": secret}), dispatched=True)
    summary = tracker.state_summary(
        mutation_generation=2,
        validated_generation=1,
        consecutive_nonprogress=1,
        turns_remaining=9,
        tool_calls_remaining=38,
        mutation_calls=2,
        build_calls=1,
        provider_retries=3,
        deadline_remaining=284.9,
    )
    assert secret not in summary
    assert "Current mutation generation: 2" in summary
    assert "Provider retries: 3" in summary
    assert "different action class" in summary
    assert len(summary.encode()) <= MAX_STATE_SUMMARY_BYTES


def test_non_json_progress_payload_fails_closed():
    tracker = ProgressTracker()
    with pytest.raises((TypeError, ValueError)):
        tracker.observe(
            "read_file", "{}",
            _result("read_file", payload={"bad": object()}), dispatched=True)


def _inspect(tracker: ProgressTracker, index: int):
    """Observe one novel inspection call, as a whitespace probe would."""
    return tracker.observe(
        "search_text", json.dumps({"query": f"probe-{index}"}),
        _result("search_text", payload={"match_count": 1, "probe": index}),
        dispatched=True)


def test_novel_inspection_stops_counting_as_progress_once_saturated():
    tracker = ProgressTracker()
    for index in range(MAX_CONSECUTIVE_INSPECTIONS):
        event = _inspect(tracker, index)
        assert event.progressed and event.kind == "inspection"
    assert tracker.consecutive_inspections == MAX_CONSECUTIVE_INSPECTIONS
    assert tracker.inspection_saturated is True

    saturated = _inspect(tracker, MAX_CONSECUTIVE_INSPECTIONS)
    assert saturated.progressed is False
    assert saturated.kind == "inspection_saturated"
    assert saturated.action_class == "inspect"


def test_saturated_state_summary_names_the_line_addressed_tools():
    tracker = ProgressTracker()
    for index in range(MAX_CONSECUTIVE_INSPECTIONS + 1):
        _inspect(tracker, index)

    summary = tracker.state_summary(
        mutation_generation=0,
        validated_generation=None,
        consecutive_nonprogress=0,
        turns_remaining=4,
        tool_calls_remaining=200,
        mutation_calls=0,
        build_calls=0,
        provider_retries=0,
        deadline_remaining=100.0,
    )

    assert "stop inspecting" in summary
    assert "git_conflict_regions" in summary
    assert "read_file_range" in summary
    assert "replace_lines" in summary
    assert f"Inspections since last change: {MAX_CONSECUTIVE_INSPECTIONS + 1}" in summary
    assert len(summary.encode()) <= MAX_STATE_SUMMARY_BYTES


@pytest.mark.parametrize("tool,result_kwargs", [
    ("replace_lines", {"generation": 1, "mutated": True}),
    ("build_recipe", {"payload": {"exit_status": 0, "generation": 0}}),
    ("finish", {"terminal": True}),
])
def test_progress_resets_the_inspection_budget(tool, result_kwargs):
    tracker = ProgressTracker()
    for index in range(MAX_CONSECUTIVE_INSPECTIONS):
        _inspect(tracker, index)
    assert tracker.inspection_saturated is True

    tracker.observe(tool, "{}", _result(tool, **result_kwargs), dispatched=True)

    assert tracker.consecutive_inspections == 0
    assert tracker.inspection_saturated is False
    assert _inspect(tracker, 99).progressed is True


def test_conflict_reduction_also_resets_the_inspection_budget():
    tracker = ProgressTracker()
    before = _result("git_status", payload={
        "staged": [], "unstaged": [], "untracked": [], "deleted": [],
        "conflicted": ["a.c", "b.c"],
    })
    after = _result("git_status", payload={
        "staged": [], "unstaged": [], "untracked": [], "deleted": [],
        "conflicted": ["b.c"],
    })
    tracker.observe("git_status", "{}", before, dispatched=True)
    for index in range(MAX_CONSECUTIVE_INSPECTIONS):
        _inspect(tracker, index)
    assert tracker.inspection_saturated is True

    reduction = tracker.observe("git_status", "{}", after, dispatched=True)

    assert reduction.kind == "conflict_reduction"
    assert tracker.consecutive_inspections == 0


def test_failed_and_undispatched_calls_do_not_spend_the_inspection_budget():
    tracker = ProgressTracker()
    failure = _result("search_text", success=False, error_kind="validation",
                      payload={"error": "single line"})
    tracker.observe("search_text", '{"query":"a\\nb"}', failure, dispatched=True)
    tracker.observe(
        "search_text", '{"query":"x"}', _result("search_text"), dispatched=False)

    assert tracker.consecutive_inspections == 0
