# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Workflow state management for CVE corrector."""
import contextlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Exit codes (canonical definitions in shared/exit_codes.py)
from shared.exit_codes import (  # noqa: F401
    EXIT_ALREADY_APPLIED,
    EXIT_BUILD_ERROR,
    EXIT_BUILD_PREEXISTING,
    EXIT_CHECKOUT_ERROR,
    EXIT_CONFLICT,
    EXIT_DEVTOOL_ERROR,
    EXIT_GIT_ERROR,
    EXIT_IGNORED_BY_STATUS,
    EXIT_METADATA_ERROR,
    EXIT_NOT_APPLICABLE,
    EXIT_PATCH_ERROR,
    EXIT_PTEST_ERROR,
    EXIT_PTEST_PREEXISTING,
    EXIT_SUCCESS,
)


class WorkflowError(Exception):
    """Base exception for workflow errors with associated exit code."""

    exit_code: int = EXIT_METADATA_ERROR

    def __init__(self, message: str = ""):
        super().__init__(message)


class ConflictError(WorkflowError):
    """Cherry-pick conflict requiring manual resolution."""
    exit_code = EXIT_CONFLICT


class PtestError(WorkflowError):
    """Post-patch ptest failure."""
    exit_code = EXIT_PTEST_ERROR


class BuildError(WorkflowError):
    """Post-patch build failure."""
    exit_code = EXIT_BUILD_ERROR


class PatchError(WorkflowError):
    """Patch generation or application error."""
    exit_code = EXIT_PATCH_ERROR


class MetadataError(WorkflowError):
    """Metadata or configuration error."""
    exit_code = EXIT_METADATA_ERROR


class GitError(WorkflowError):
    """Git operation error."""
    exit_code = EXIT_GIT_ERROR


class DevtoolError(WorkflowError):
    """Devtool operation error."""
    exit_code = EXIT_DEVTOOL_ERROR


class PtestPreexistingError(WorkflowError):
    """Pre-patch ptest already failing."""
    exit_code = EXIT_PTEST_PREEXISTING


class BuildPreexistingError(WorkflowError):
    """Pre-patch build already failing."""
    exit_code = EXIT_BUILD_PREEXISTING


class AlreadyAppliedError(WorkflowError):
    """CVE fix already present in source tree."""
    exit_code = EXIT_ALREADY_APPLIED


class NotApplicableError(WorkflowError):
    """Vulnerable code not present in recipe version."""
    exit_code = EXIT_NOT_APPLICABLE


class IgnoredByStatusError(WorkflowError):
    """Recipe's existing CVE_STATUS marks this CVE as ignored/not-affected."""
    exit_code = EXIT_IGNORED_BY_STATUS


@dataclass
class WorkflowState:  # pylint: disable=too-many-instance-attributes
    """State object for CVE correction workflow."""
    workspace_path: Path
    cve_id: str
    recipe: str
    commit_hash: str
    hash_details: list
    meta_layer: Optional[Path]
    skip_build: bool
    skip_ptest: bool
    ptest_before: Optional[str] = None
    ptest_after: Optional[str] = None
    series_state: Optional[dict] = None
    current_step: Optional[str] = None
    skip_confirm: bool = False
    subproject: Optional[str] = None
    bbappend: bool = False
    version: Optional[str] = None
    sign_off: bool = False

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict."""
        return {
            'workspace_path': str(self.workspace_path),
            'cve_id': self.cve_id,
            'recipe': self.recipe,
            'commit_hash': self.commit_hash,
            'hash_details': self.hash_details,
            'meta_layer': str(self.meta_layer) if self.meta_layer else None,
            'skip_build': self.skip_build,
            'skip_ptest': self.skip_ptest,
            'ptest_before': self.ptest_before,
            'ptest_after': self.ptest_after,
            'series_state': self.series_state,
            'current_step': self.current_step,
            'skip_confirm': self.skip_confirm,
            'subproject': self.subproject,
            'bbappend': self.bbappend,
            'version': self.version,
            'sign_off': self.sign_off
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'WorkflowState':
        """Create from dict (e.g., loaded from JSON)."""
        return cls(
            workspace_path=Path(data['workspace_path']),
            cve_id=data['cve_id'],
            recipe=data['recipe'],
            commit_hash=data['commit_hash'],
            hash_details=data.get('hash_details', []),
            meta_layer=Path(data['meta_layer']) if data.get('meta_layer') else None,
            skip_build=data['skip_build'],
            skip_ptest=data.get('skip_ptest', False),
            ptest_before=data.get('ptest_before'),
            ptest_after=data.get('ptest_after'),
            series_state=data.get('series_state'),
            current_step=data.get('current_step'),
            skip_confirm=data.get('skip_confirm', False),
            subproject=data.get('subproject'),
            bbappend=data.get('bbappend', False),
            version=data.get('version'),
            sign_off=data.get('sign_off', False)
        )


def load_cve_metadata(cve_file: Path) -> dict:
    """Load CVE metadata from JSON file.

    Args:
        cve_file: Path to JSON file containing CVE fix information

    Returns:
        Dict mapping CVE IDs to their metadata (name, hashes, hash_details, series)

    Raises:
        MetadataError: If file not found or invalid JSON
    """
    try:
        with open(cve_file, encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError as e:
        raise MetadataError(f"CVE metadata file not found: {cve_file}") from e
    except json.JSONDecodeError as e:
        raise MetadataError(f"Invalid JSON in {cve_file}: {e}") from e


def save_workflow_state(state: WorkflowState) -> None:
    """Save workflow state to file for resume (atomic write)."""
    import tempfile

    from .bitbake_ops import get_state_dir  # lazy to avoid circular import

    state_dir = get_state_dir()
    state_file = state_dir / f"{state.workspace_path.name}.json"
    fd, tmp_path = tempfile.mkstemp(dir=state_dir, prefix='.state_', suffix='.json')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(state.to_dict(), f, indent=2)
        os.replace(tmp_path, state_file)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def save_progress(state: WorkflowState, step: str) -> None:
    """Save current progress to state file."""
    state.current_step = step
    save_workflow_state(state)
