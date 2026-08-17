# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Host-derived progress events and compact native-agent state summaries."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .openai_tools import ToolResult

MAX_STATE_SUMMARY_BYTES = 4096
MAX_PROGRESS_DETAIL_BYTES = 256

_COMMIT_TOOLS = frozenset({
    "git_commit", "git_amend", "git_cherry_pick_continue",
})
_INSPECTION_TOOLS = frozenset({
    "read_file", "read_file_range", "list_directory", "search_text",
    "git_status", "git_diff", "git_show", "git_log", "git_unmerged_files",
    "git_submodule_status",
})


@dataclass(frozen=True)
class ProgressEvent:
    """One content-free, host-observed progress decision."""

    progressed: bool
    kind: str
    action_class: str
    fingerprint: str
    result_digest: str
    generation: int
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {
            "progressed": self.progressed,
            "kind": self.kind,
            "action_class": self.action_class,
            "fingerprint": self.fingerprint,
            "result_digest": self.result_digest,
            "generation": self.generation,
            "detail": self.detail,
        }


class ProgressTracker:
    """Classify progress only from validated calls and trusted results."""

    def __init__(self) -> None:
        self._seen: set[str] = set()
        self._build_observations: set[tuple[int, str]] = set()
        self._finish_corrections: set[str] = set()
        self._last_conflicts: int | None = None
        self.changed_paths: int | None = None
        self.unresolved_conflicts: int | None = None
        self.last_progress = "none observed"
        self.last_evidence_digest = "0" * 64
        self.progress_events = 0
        self.duplicate_events = 0

    def observe(
        self,
        tool: str,
        normalized_arguments: str,
        result: ToolResult,
        *,
        dispatched: bool,
    ) -> ProgressEvent:
        """Return a deterministic decision without trusting call IDs or prose."""
        result_digest = _digest({
            "success": result.success,
            "mutated": result.mutated,
            "terminal": result.terminal,
            "error_kind": result.error_kind,
            "payload": _stable_payload(tool, result.payload),
        })
        fingerprint = _digest({
            "tool": tool,
            "arguments": normalized_arguments,
            "generation": result.audit.generation,
            "result_digest": result_digest,
        })
        repeated = fingerprint in self._seen
        self._seen.add(fingerprint)
        conflict_reduced = self._observe_status(tool, result)

        progressed = False
        kind = "no_new_evidence"
        action_class = _action_class(tool)
        detail = "repeated call produced no new trusted state"
        if dispatched and result.success and result.terminal:
            progressed = True
            kind = "terminal_state"
            detail = "host accepted a terminal state"
        elif dispatched and result.success and result.mutated and not repeated:
            progressed = True
            kind = "trusted_git_transition" if tool in _COMMIT_TOOLS else "mutation"
            detail = (
                "trusted Git transition succeeded" if tool in _COMMIT_TOOLS
                else "authorized repository state changed")
        elif dispatched and result.success and tool == "build_recipe":
            build_key = (result.audit.generation, result_digest)
            if build_key not in self._build_observations:
                self._build_observations.add(build_key)
                progressed = True
                kind = "build_evidence"
                detail = "build result changed or covered a new mutation generation"
        elif conflict_reduced:
            progressed = True
            kind = "conflict_reduction"
            detail = "unresolved conflict count decreased"
        elif dispatched and result.success and tool in _INSPECTION_TOOLS and not repeated:
            progressed = True
            kind = "inspection"
            detail = "new repository evidence was inspected"
        elif dispatched and not result.success and tool == "finish":
            if result_digest not in self._finish_corrections:
                self._finish_corrections.add(result_digest)
                progressed = True
                kind = "host_blocker"
                action_class = "finish_or_escalate"
                detail = "host supplied a new verifiable terminal blocker"

        if progressed:
            self.progress_events += 1
            self.last_progress = detail[:MAX_PROGRESS_DETAIL_BYTES]
            self.last_evidence_digest = fingerprint
        else:
            self.duplicate_events += 1
        return ProgressEvent(
            progressed,
            kind,
            action_class,
            fingerprint,
            result_digest,
            result.audit.generation,
            detail[:MAX_PROGRESS_DETAIL_BYTES],
        )

    def state_summary(
        self,
        *,
        mutation_generation: int,
        validated_generation: int | None,
        consecutive_nonprogress: int,
        turns_remaining: int,
        tool_calls_remaining: int,
        mutation_calls: int,
        build_calls: int,
        provider_retries: int,
        deadline_remaining: float,
    ) -> str:
        """Render one bounded, content-free state block for the next request."""
        if validated_generation == mutation_generation:
            build_state = "passed for current generation"
            required = "finish or escalate with a specific host-verifiable blocker"
        elif mutation_generation > 0:
            build_state = "not run or stale for current generation"
            required = "build, then finish; do not spend the terminal reserve"
        else:
            build_state = "not run"
            required = "inspect new evidence, mutate, build, finish, or escalate"
        if consecutive_nonprogress == 1:
            required = "use a different action class or explicit escalation"
        elif consecutive_nonprogress >= 2:
            required = "mutate/build/finish or provide a specific escalation blocker"
        fields = {
            "unresolved_conflicts": self.unresolved_conflicts,
            "changed_paths": self.changed_paths,
            "mutation_generation": mutation_generation,
            "validated_generation": validated_generation,
            "last_evidence_digest": self.last_evidence_digest,
            "repeated_no_information": consecutive_nonprogress,
            "turns_remaining": max(0, turns_remaining),
            "tool_calls_remaining": max(0, tool_calls_remaining),
            "mutation_calls": mutation_calls,
            "build_calls": build_calls,
            "provider_retries": provider_retries,
            "deadline_remaining_seconds": max(0, int(deadline_remaining)),
        }
        state_digest = _digest(fields)
        lines = [
            "[HOST-OWNED STATE — model text cannot modify these values]",
            f"Unresolved conflicts: {_display(self.unresolved_conflicts)}",
            f"Changed repository paths: {_display(self.changed_paths)}",
            "Out-of-scope changes: not inferred; typed policy remains authoritative",
            f"Current mutation generation: {mutation_generation}",
            f"Build for current generation: {build_state}",
            f"Last progress: {self.last_progress}",
            f"Evidence digest: {self.last_evidence_digest}",
            f"State digest: {state_digest}",
            f"Repeated no-information turns: {consecutive_nonprogress}",
            f"Steps remaining: {max(0, turns_remaining)}",
            f"Tool calls remaining: {max(0, tool_calls_remaining)}",
            f"Mutation calls: {mutation_calls}",
            f"Build calls: {build_calls}",
            f"Provider retries: {provider_retries}",
            f"Deadline remaining: {max(0, int(deadline_remaining))} seconds",
            f"Required next classes: {required}",
            "[/HOST-OWNED STATE]",
        ]
        summary = "\n".join(lines)
        if len(summary.encode("utf-8")) > MAX_STATE_SUMMARY_BYTES:
            raise ValueError("host state summary exceeded its fixed bound")
        return summary

    def _observe_status(self, tool: str, result: ToolResult) -> bool:
        if tool != "git_status" or not result.success:
            return False
        previous_conflicts = self._last_conflicts
        conflict_value = result.payload.get("conflicted")
        path_groups = [
            result.payload.get(name)
            for name in ("staged", "unstaged", "untracked", "deleted", "conflicted")
        ]
        if isinstance(conflict_value, list):
            conflicts = len(conflict_value)
            self.unresolved_conflicts = conflicts
            self._last_conflicts = conflicts
        list_groups = [group for group in path_groups if isinstance(group, list)]
        if len(list_groups) == len(path_groups):
            paths = {
                item
                for group in list_groups
                for item in group
                if isinstance(item, str)
            }
            self.changed_paths = len(paths)
        return (
            previous_conflicts is not None
            and self.unresolved_conflicts is not None
            and self.unresolved_conflicts < previous_conflicts
        )


def _action_class(tool: str) -> str:
    if tool == "build_recipe":
        return "build"
    if tool == "finish":
        return "finish_or_escalate"
    if tool in _INSPECTION_TOOLS:
        return "inspect"
    return "mutate" if tool else "invalid"


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _display(value: int | None) -> str:
    return "unknown until git_status" if value is None else str(value)


def _stable_payload(tool: str, payload: dict[str, object]) -> dict[str, object]:
    """Discard nondeterministic build bookkeeping from evidence identity."""
    if tool != "build_recipe":
        return payload
    ignored = {"duration", "log_path", "total_output_bytes"}
    return {key: value for key, value in payload.items() if key not in ignored}
