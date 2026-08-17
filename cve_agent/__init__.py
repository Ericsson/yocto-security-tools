# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""CVE Agent - Orchestrates CVE backporting with AI-assisted conflict resolution.

Wraps cve_corrector and spawns AI sessions to resolve conflicts, build errors,
and test failures during CVE backporting.
"""
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

# Exit codes (single source of truth: shared/exit_codes.py)
from shared.exit_codes import (
    EXIT_AGENT_ERROR,
    EXIT_AI_TIMEOUT,
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
    EXIT_TRUST_DECLINED,
)
from shared.paths import data_dir

from .result import (
    BuildStatus,
    FailureClass,
    ResultOutcome,
    SecurityStatus,
    WorkflowStatus,
    migrate_legacy_status,
    outcome_for_host_skip,
)

# Exit codes that trigger the resolution loop (agent can attempt to fix)
RECOVERABLE_EXITS = {EXIT_CONFLICT, EXIT_PTEST_ERROR, EXIT_BUILD_ERROR}

# Exit codes that require immediate escalation (no point retrying)
UNRECOVERABLE_EXITS = {EXIT_CHECKOUT_ERROR, EXIT_PATCH_ERROR,
                       EXIT_METADATA_ERROR, EXIT_GIT_ERROR,
                       EXIT_PTEST_PREEXISTING, EXIT_DEVTOOL_ERROR,
                       EXIT_BUILD_PREEXISTING, EXIT_NOT_APPLICABLE,
                       EXIT_IGNORED_BY_STATUS}

# Default paths
DEFAULT_KNOWLEDGE_PATH = data_dir() / 'knowledge.json'
DEFAULT_MAX_RETRIES = 3
DEFAULT_SESSION_TIMEOUT = 600
CORRECTOR_CMD = [sys.executable, '-m', 'cve_corrector']


def resolve_agent_instructions() -> Path:
    """Resolve the agent prompt file, preferring the stable synced copy.

    ``cve_agent.setup.sync_agent_instructions()`` copies the packaged
    AGENT_INSTRUCTIONS.md to a stable, package-location-independent path
    under data_dir() whenever agents are (re)installed. Prefer that copy so
    behavior stays consistent with what the kiro agent JSON's ``prompt``
    field points at; fall back to the packaged file if the sync hasn't run
    yet (e.g. before the first ``ensure_agents()`` call, or when running the
    ``claude`` backend, which doesn't install kiro agents).

    Resolved fresh on each call (not cached) so a sync that happens after
    this module was first imported — e.g. ``ensure_agents()`` running later
    in the same process as ``main()`` does — is picked up.
    """
    from .setup import PACKAGED_AGENT_INSTRUCTIONS, STABLE_AGENT_INSTRUCTIONS
    if STABLE_AGENT_INSTRUCTIONS.is_file():
        return STABLE_AGENT_INSTRUCTIONS
    return PACKAGED_AGENT_INSTRUCTIONS


def read_shared_agent_instructions() -> str:
    """Read the packaged backend-neutral instructions for runtime assembly.

    The stable copy used by kiro-cli's static ``file://`` prompt includes the
    Kiro-specific tool preamble. Runtime backends must therefore read the
    packaged source directly before adding their own preamble, or a Claude or
    native session could receive contradictory Kiro tool names.
    """
    from .setup import PACKAGED_AGENT_INSTRUCTIONS

    if not PACKAGED_AGENT_INSTRUCTIONS.is_file():
        raise FileNotFoundError(
            f"Packaged agent instructions not found: {PACKAGED_AGENT_INSTRUCTIONS}")
    return PACKAGED_AGENT_INSTRUCTIONS.read_text(encoding="utf-8")


# Kept for backward compatibility (existing tests/callers patch this
# constant directly). Computed once at import time; DO NOT use in new code —
# call resolve_agent_instructions() instead, which re-checks the stable
# synced copy on every call and picks up a sync that happens later in the
# same process (e.g. ensure_agents() runs before context building in the
# real CLI flow).
AGENT_INSTRUCTIONS = resolve_agent_instructions()


class ResultStatus(Enum):
    """Outcome status for a CVE processing attempt."""
    SUCCESS = "success"
    CONFLICT_RESOLVED = "conflict_resolved"
    FAILED = "failed"
    ESCALATED = "escalated"
    SKIPPED = "skipped"


@dataclass
class AgentConfig:
    """Configuration for a single CVE agent run."""
    cve_id: str
    cve_info_path: Optional[Path] = None
    trust_mode: bool = False
    max_retries: int = DEFAULT_MAX_RETRIES
    max_total_attempts: int = 0  # 0 = no cap beyond per-step max_retries
    mirror_dir: Optional[Path] = None
    meta_layer: Optional[Path] = None
    skip_ptest: bool = False
    clean: bool = False
    model: str = "claude-sonnet-5"
    session_timeout: int = DEFAULT_SESSION_TIMEOUT
    interactive: bool = False
    bbappend: bool = False
    skip_cve_applicability: bool = False
    fix_urls: list[str] = field(default_factory=list)
    recipe: Optional[str] = None
    backend: str = "kiro"
    backend_profile: Optional[str] = None
    backend_selector: Optional[str] = None
    skip_sources: list[str] = field(default_factory=list)
    sign_off: bool = False
    no_knowledge: bool = False


@dataclass
class CveResult:
    """Outcome of processing a single CVE."""
    cve_id: str
    status: ResultStatus
    retries: int = 0
    duration: float = 0.0
    resolution_summary: str = ""
    # Backend cost summed across all AI sessions run for this CVE (initial
    # attempt + retries + any extended-chain re-runs). ``None`` when the
    # backend reported no cost (e.g. claude, or an interrupted kiro session).
    total_credits: Optional[float] = None
    credits_unit: Optional[str] = None
    outcome: Optional[ResultOutcome] = None
    failure_class: Optional[FailureClass] = None
    failure_code: Optional[str] = None

    def __post_init__(self) -> None:
        if self.outcome is None:
            if self.status in {ResultStatus.SUCCESS, ResultStatus.CONFLICT_RESOLVED}:
                self.outcome = migrate_legacy_status(
                    self.status.value, build_evidence=True)
            elif self.status is ResultStatus.SKIPPED:
                self.outcome = outcome_for_host_skip()
            else:
                self.outcome = migrate_legacy_status(
                    self.status.value, failure_code=self.failure_code)
        if self.failure_class is None:
            self.failure_class = self.outcome.failure_class
        if self.failure_code is None:
            self.failure_code = self.outcome.failure_code

    def to_dict(self) -> dict[str, object]:
        """Serialize the authoritative outcome plus compatibility metadata."""
        assert self.outcome is not None
        value = self.outcome.to_dict()
        value.update({
            "cve_id": self.cve_id,
            "retries": self.retries,
            "duration": self.duration,
            "resolution_summary": self.resolution_summary,
            "total_credits": self.total_credits,
            "credits_unit": self.credits_unit,
            # Compatibility only.  Do not use this field for release gates.
            "legacy_status": self.status.value,
        })
        return value


def get_build_dir(workspace_path: Path) -> Path:
    """Derive the Yocto build directory from a devtool workspace path.

    The devtool workspace structure is: <build>/workspace/sources/<recipe>,
    so the build directory is three levels up from the workspace path.

    Args:
        workspace_path: Path to the devtool workspace source directory.

    Returns:
        Path to the Yocto build directory.
    """
    return workspace_path.parent.parent.parent


def get_agent_dir(workspace_path: Path) -> Path:
    """Get or create the agent working directory outside the git workspace.

    Uses the build workspace's cve_agent/ directory to avoid polluting
    the source git repo with agent artifacts.

    Args:
        workspace_path: Path to the devtool workspace source directory.

    Returns:
        Path to the cve_agent/<recipe> directory, created if needed.
    """
    recipe = workspace_path.name
    build_workspace = workspace_path.parent.parent
    agent_dir = build_workspace / 'cve_agent' / recipe
    agent_dir.mkdir(parents=True, exist_ok=True)
    return agent_dir


__all__ = [
    'AgentConfig', 'CveResult', 'ResultStatus', 'ResultOutcome',
    'WorkflowStatus', 'BuildStatus', 'SecurityStatus', 'FailureClass',
    'RECOVERABLE_EXITS', 'UNRECOVERABLE_EXITS',
    'DEFAULT_KNOWLEDGE_PATH', 'DEFAULT_MAX_RETRIES', 'DEFAULT_SESSION_TIMEOUT',
    'CORRECTOR_CMD', 'AGENT_INSTRUCTIONS', 'resolve_agent_instructions',
    'read_shared_agent_instructions',
    'get_build_dir', 'get_agent_dir',
    'EXIT_SUCCESS', 'EXIT_CONFLICT', 'EXIT_CHECKOUT_ERROR', 'EXIT_PTEST_ERROR',
    'EXIT_BUILD_ERROR', 'EXIT_PATCH_ERROR', 'EXIT_METADATA_ERROR', 'EXIT_GIT_ERROR',
    'EXIT_PTEST_PREEXISTING', 'EXIT_DEVTOOL_ERROR', 'EXIT_BUILD_PREEXISTING',
    'EXIT_ALREADY_APPLIED', 'EXIT_NOT_APPLICABLE', 'EXIT_IGNORED_BY_STATUS',
    'EXIT_TRUST_DECLINED', 'EXIT_AGENT_ERROR', 'EXIT_AI_TIMEOUT',
]
