# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Consumer-side validation of the corrector repository handoff."""
from __future__ import annotations

import contextvars
import json
import subprocess
from dataclasses import replace
from pathlib import Path

from shared import TEXT_ENCODING, TEXT_ERRORS, build_git_env
from shared.handoff import (
    HandoffError,
    RepositoryHandoff,
    capture_handoff_state,
    read_handoff,
    reference_change_paths,
    validate_handoff_state,
    write_handoff,
)

from .openai_tools import FileToolPathPolicy, ToolPolicyError, ToolValidationError

_VALIDATED_HANDOFF: contextvars.ContextVar[RepositoryHandoff | None] = (
    contextvars.ContextVar("cve_agent_validated_handoff", default=None)
)


def activate_validated_handoff(
    handoff: RepositoryHandoff | None,
) -> contextvars.Token[RepositoryHandoff | None]:
    """Bind validated handoff provenance to one provider session."""
    return _VALIDATED_HANDOFF.set(handoff)


def deactivate_validated_handoff(
    token: contextvars.Token[RepositoryHandoff | None],
) -> None:
    """Remove session-local handoff provenance."""
    _VALIDATED_HANDOFF.reset(token)


def current_validated_handoff() -> RepositoryHandoff | None:
    """Return the manifest established by full handoff validation."""
    return _VALIDATED_HANDOFF.get()


def current_validated_handoff_digest() -> str | None:
    """Return only provenance established by full handoff validation."""
    handoff = current_validated_handoff()
    return None if handoff is None else handoff.critical_sha256


def repository_handoff_path(workspace: Path) -> Path:
    """Derive the manifest beside corrector state, never from CWD."""
    return (workspace.parent.parent / "cve_corrector" / "handoffs"
            / f"{workspace.name}.json")


def transfer_manifest_path(workspace: Path) -> Path:
    return (workspace.parent.parent / "cve_corrector" / "transfers"
            / f"{workspace.name}.json")


def read_transfer_artifact(workspace: Path) -> dict[str, object] | None:
    """Read one bounded transfer manifest for durable artifact retention."""
    path = transfer_manifest_path(workspace)
    try:
        if path.stat().st_size > 1024 * 1024:
            return None
        value = json.loads(path.read_bytes().decode("utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) and value.get("schema_version") == 1 else None


def validate_repository_handoff(
    workspace: Path, cve_id: str, *, required: bool,
) -> RepositoryHandoff | None:
    """Parse, reauthorize, and bind the handoff to current repository state."""
    path = repository_handoff_path(workspace)
    if not path.is_file():
        if required:
            raise HandoffError("HANDOFF_MISSING", "corrector manifest is unavailable")
        return None
    manifest = read_handoff(path)
    if manifest.cve != cve_id:
        raise HandoffError("HANDOFF_CVE_MISMATCH", "manifest CVE changed")
    try:
        allowed = FileToolPathPolicy(workspace, manifest.allowed_paths).allowed_files
        generated = FileToolPathPolicy(
            workspace, manifest.known_generated_paths).allowed_files
    except (ValueError, ToolPolicyError, ToolValidationError) as error:
        raise HandoffError("HANDOFF_PATH_AUTHORIZATION", "unsafe manifest path") from error
    if len(allowed) != len(manifest.allowed_paths):
        raise HandoffError("HANDOFF_PATH_CONTRADICTION", "duplicate allowed path")
    if allowed & generated:
        raise HandoffError("HANDOFF_PATH_CONTRADICTION", "path roles overlap")
    if manifest.tracked_out_of_scope_paths:
        raise HandoffError(
            "HANDOFF_UNKNOWN_OUT_OF_SCOPE",
            "manifest declares tracked paths outside authorized scope",
        )
    expected_paths, expected_parent = reference_change_paths(
        workspace, manifest.selected_commit, manifest.mainline_parent)
    if expected_parent != manifest.selected_parent:
        raise HandoffError("HANDOFF_REFERENCE_DRIFT", "reference parent changed")
    expected_paths = tuple(sorted(
        set(expected_paths) | set(manifest.conflicted_paths)))
    if expected_paths != manifest.allowed_paths:
        transfer = read_transfer_artifact(workspace)
        transfer_paths = (transfer.get("final_changed_paths")
                          if transfer is not None else None)
        if (transfer is None or transfer.get("verification") != "verified"
                or transfer.get("target_final_head") != manifest.current_head
                or not isinstance(transfer_paths, list)
                or not all(isinstance(path, str) for path in transfer_paths)
                or tuple(transfer_paths) != manifest.allowed_paths):
            raise HandoffError("HANDOFF_REFERENCE_DRIFT", "reference operation changed")
    validate_handoff_state(manifest, workspace)
    return manifest


def refresh_repository_handoff(
    workspace: Path,
    manifest: RepositoryHandoff,
    allowed_paths: set[str],
    session_root_head: str | None = None,
) -> RepositoryHandoff:
    """Reissue a handoff for a narrowly audited provider retry state."""
    captured = capture_handoff_state(workspace)
    authorized = set(allowed_paths) | set(manifest.known_generated_paths)
    tracked_outside = sorted(set(captured.tracked_paths) - authorized)
    if tracked_outside:
        raise HandoffError(
            "HANDOFF_RETRY_SCOPE_DRIFT", "retry state has unauthorized tracked paths")
    result = subprocess.run(
        ["git", "--no-pager", "diff", "--name-only", "--no-renames", "-z",
         session_root_head or manifest.current_head, captured.head, "--"],
        cwd=workspace,
        env=build_git_env(),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        encoding=TEXT_ENCODING,
        errors=TEXT_ERRORS,
        check=False,
    )
    if result.returncode != 0 or len(result.stdout.encode("utf-8")) > 8 * 1024 * 1024:
        raise HandoffError("HANDOFF_RETRY_CAPTURE_FAILED", "retry commit scope unavailable")
    durable_paths = {path for path in result.stdout.split("\0") if path}
    if durable_paths - authorized:
        raise HandoffError(
            "HANDOFF_RETRY_SCOPE_DRIFT", "retry commits have unauthorized paths")
    refreshed = replace(
        manifest,
        current_head=captured.head,
        current_tree=captured.tree,
        operation_state=captured.operation_state,
        conflicted_paths=captured.conflicted_paths,
        tracked_out_of_scope_paths=(),
        index_fingerprint=captured.index_fingerprint,
        worktree_fingerprint=captured.worktree_fingerprint,
        critical_sha256="",
    ).with_digest()
    write_handoff(repository_handoff_path(workspace), refreshed)
    return refreshed
