# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Consumer-side validation of the corrector repository handoff."""
from __future__ import annotations

import contextvars
import json
from pathlib import Path

from shared.handoff import (
    HandoffError,
    RepositoryHandoff,
    read_handoff,
    reference_change_paths,
    validate_handoff_state,
)

from .openai_tools import FileToolPathPolicy, ToolPolicyError, ToolValidationError

_VALIDATED_HANDOFF_DIGEST: contextvars.ContextVar[str | None] = (
    contextvars.ContextVar("cve_agent_validated_handoff_digest", default=None)
)


def activate_validated_handoff(
    handoff: RepositoryHandoff | None,
) -> contextvars.Token[str | None]:
    """Bind validated handoff provenance to one provider session."""
    digest = None if handoff is None else handoff.critical_sha256
    return _VALIDATED_HANDOFF_DIGEST.set(digest)


def deactivate_validated_handoff(token: contextvars.Token[str | None]) -> None:
    """Remove session-local handoff provenance."""
    _VALIDATED_HANDOFF_DIGEST.reset(token)


def current_validated_handoff_digest() -> str | None:
    """Return only provenance established by full handoff validation."""
    return _VALIDATED_HANDOFF_DIGEST.get()


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
