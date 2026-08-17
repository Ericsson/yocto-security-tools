# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Trusted producer for the corrector-to-agent repository handoff."""
from __future__ import annotations

from pathlib import Path

from shared.handoff import (
    HANDOFF_SCHEMA_VERSION,
    HandoffError,
    RepositoryHandoff,
    capture_handoff_state,
    git_object,
    reference_change_paths,
    restore_tracked_paths,
    write_handoff,
)

from .state import WorkflowState
from .transfer import transfer_manifest_path, verified_transfer_paths


def handoff_path(state_dir: Path, recipe: str) -> Path:
    """Return the stable manifest path for a corrector workspace."""
    return state_dir / "handoffs" / f"{recipe}.json"


def emit_handoff(state: WorkflowState, state_dir: Path) -> RepositoryHandoff:
    """Classify repository state, narrowly clean generated paths, and emit."""
    workspace = state.workspace_path.resolve(strict=True)
    allowed, selected_parent = reference_change_paths(
        workspace, state.commit_hash, state.mainline_parent)
    generated = tuple(sorted(set(state.known_generated_paths) - set(allowed)))
    before = capture_handoff_state(workspace)
    generated_dirty = tuple(path for path in generated if path in before.tracked_paths)
    restore_tracked_paths(workspace, generated_dirty)
    captured = capture_handoff_state(workspace)
    transferred = verified_transfer_paths(
        transfer_manifest_path(workspace, state.recipe), captured.head)
    if transferred is not None:
        allowed = transferred

    declared = set(allowed) | set(captured.conflicted_paths)
    out_of_scope = tuple(sorted(set(captured.tracked_paths) - declared))
    manifest = RepositoryHandoff(
        schema_version=HANDOFF_SCHEMA_VERSION,
        cve=state.cve_id,
        workspace_root=str(workspace),
        baseline_head=git_object(workspace, "original-version^{commit}"),
        current_head=captured.head,
        baseline_tree=git_object(workspace, "original-version^{tree}"),
        current_tree=captured.tree,
        reference_commits=(git_object(workspace, f"{state.commit_hash}^{{commit}}"),),
        selected_commit=git_object(workspace, f"{state.commit_hash}^{{commit}}"),
        mainline_parent=state.mainline_parent,
        selected_parent=selected_parent,
        git_operation="cherry-pick",
        operation_state=captured.operation_state,
        conflicted_paths=captured.conflicted_paths,
        allowed_paths=allowed,
        known_generated_paths=generated,
        tracked_out_of_scope_paths=out_of_scope,
        index_fingerprint=captured.index_fingerprint,
        worktree_fingerprint=captured.worktree_fingerprint,
        critical_sha256="",
    ).with_digest()
    write_handoff(handoff_path(state_dir, state.recipe), manifest)
    if out_of_scope:
        sample = ", ".join(out_of_scope[:8])
        raise HandoffError(
            "HANDOFF_UNKNOWN_OUT_OF_SCOPE",
            f"tracked paths outside declared scope: {sample}",
        )
    return manifest
