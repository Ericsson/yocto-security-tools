# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""CVE processing orchestration — single-CVE workflow and resolution loop."""
import dataclasses
import json
import shutil
import time
from pathlib import Path
from typing import Optional

from . import (
    EXIT_ALREADY_APPLIED,
    EXIT_BUILD_PREEXISTING,
    EXIT_NOT_APPLICABLE,
    EXIT_PTEST_PREEXISTING,
    EXIT_SUCCESS,
    RECOVERABLE_EXITS,
    UNRECOVERABLE_EXITS,
    AgentConfig,
    CveResult,
    ResultStatus,
    get_agent_dir,
)
from .context import build_context
from .corrector import get_workspace_path, load_cve_metadata, run_corrector
from .git import get_changed_files, get_upstream_sha, run_git_stdout
from .knowledge import KnowledgeBase, gather_pattern_details, save_knowledge_pattern
from .review import build_change_summary, request_approval
from .session import guarded_session


@dataclasses.dataclass
class _AttemptOutcome:
    """Result of a single resolution attempt."""
    result: Optional[CveResult] = None
    next_step: Optional[int] = None


def _make_result(cve_id: str, status: ResultStatus, retries: int,
                 start_time: float, summary: str) -> CveResult:
    """Create a CveResult with computed duration."""
    return CveResult(
        cve_id=cve_id,
        status=status,
        retries=retries,
        duration=time.monotonic() - start_time,
        resolution_summary=summary,
    )


def _read_conclusion(workspace_path: Path) -> Optional[str]:
    """Read the agent conclusion file if the CVE was deemed not applicable."""
    conclusion_file = get_agent_dir(workspace_path) / 'conclusion.json'
    if not conclusion_file.exists():
        return None
    try:
        data = json.loads(conclusion_file.read_text(encoding='utf-8'))
        if data.get('not_applicable'):
            return data.get('reason', 'CVE not applicable (no details)')
    except (json.JSONDecodeError, OSError):
        pass
    return None


def _is_empty_cherry_pick(workspace_path: Path, cve_info: dict) -> bool:
    """Check if the upstream commit produced no actual changes in the workspace."""
    upstream_sha = get_upstream_sha(cve_info, workspace_path)
    if upstream_sha == "unknown":
        return False
    upstream_files = get_changed_files(
        ['diff-tree', '--no-commit-id', '--name-only', '-r', upstream_sha],
        workspace_path
    )
    if not upstream_files:
        # Verify the SHA is actually valid — empty set from a git failure
        # is not the same as "no files changed"
        return bool(run_git_stdout(['cat-file', '-t', upstream_sha], workspace_path))
    applied = run_git_stdout(
        ['diff', 'original-version..HEAD', '--'] + sorted(upstream_files),
        workspace_path
    )
    return not applied.strip()


def _resolution_loop(config: AgentConfig, workspace_path: Path,
                     exit_code: int, cve_info: dict,
                     knowledge_base: KnowledgeBase) -> CveResult:
    """Run the resolution loop: context -> AI backend -> approval -> continue."""
    start_time = time.monotonic()
    current_step = exit_code
    attempt = 0
    total_attempts = 0
    max_total = config.max_total_attempts if config.max_total_attempts > 0 else None

    while attempt < config.max_retries:
        attempt += 1
        total_attempts += 1
        if max_total and total_attempts > max_total:
            return _make_result(
                config.cve_id, ResultStatus.ESCALATED, total_attempts,
                start_time, "Total attempt cap reached")
        print(f"\n--- Resolution attempt {attempt}/{config.max_retries} "
              f"for {config.cve_id} ---")

        outcome = _run_single_resolution_attempt(
            config, workspace_path, current_step, cve_info,
            knowledge_base, attempt, start_time
        )
        if outcome.result is not None:
            return outcome.result

        if outcome.next_step is not None and outcome.next_step != current_step:
            print(f"Step changed ({current_step} -> {outcome.next_step}), "
                  f"resetting attempt counter")
            current_step = outcome.next_step
            attempt = 0

    return _make_result(
        config.cve_id, ResultStatus.ESCALATED,
        attempt, start_time,
        f"Max retries ({config.max_retries}) exhausted at step {current_step}"
    )


def _run_single_resolution_attempt(
        config: AgentConfig, workspace_path: Path, exit_code: int,
        cve_info: dict, knowledge_base: KnowledgeBase,
        attempt: int, start_time: float) -> _AttemptOutcome:
    """Execute one resolution attempt: context -> session -> approval -> continue."""
    context_file = build_context(
        workspace_path, exit_code, config.cve_id, cve_info, knowledge_base,
        model=config.model, backend=config.backend
    )
    upstream_sha = get_upstream_sha(cve_info, workspace_path)
    session_result = guarded_session(
        context_file, workspace_path, upstream_sha, cve_info, config.model,
        config.session_timeout, config.cve_id, config.interactive,
        backend_name=config.backend)

    if not session_result.resolved:
        print(f"{config.backend} session did not resolve conflicts for {config.cve_id}")
        if config.trust_mode:
            return _AttemptOutcome()
        response = input(
            f"Retry {config.backend} session? [y]es / [n]o (escalate): "
        ).strip().lower()
        if response in ('n', 'no'):
            return _AttemptOutcome(result=_make_result(
                config.cve_id, ResultStatus.ESCALATED,
                attempt, start_time, f"{config.backend} session failed to resolve"
            ))
        return _AttemptOutcome()

    conclusion_reason = _read_conclusion(workspace_path)
    if conclusion_reason:
        print("\n\u26a0 Agent concluded CVE is not applicable:")
        print(f"  {conclusion_reason}")
        run_corrector(config, mark_not_applicable=conclusion_reason)
        return _AttemptOutcome(result=_make_result(
            config.cve_id, ResultStatus.SKIPPED,
            attempt, start_time, conclusion_reason
        ))

    if not workspace_path.exists():
        return _AttemptOutcome(result=_make_result(
            config.cve_id, ResultStatus.CONFLICT_RESOLVED,
            attempt, start_time,
            f"Resolved via {config.backend} (workspace finalized)"
        ))

    approval, feedback = request_approval(workspace_path, upstream_sha, config)

    if approval == "edit":
        if feedback:
            agent_dir = get_agent_dir(workspace_path)
            (agent_dir / 'human_feedback.txt').write_text(
                feedback, encoding='utf-8')
        return _AttemptOutcome()
    if approval == "rejected":
        return _AttemptOutcome(result=_make_result(
            config.cve_id, ResultStatus.ESCALATED,
            attempt, start_time, "Human rejected resolution"
        ))

    return _finalize_resolution(
        config, knowledge_base, workspace_path,
        upstream_sha, attempt, start_time
    )


def _finalize_resolution(config: AgentConfig, knowledge_base: KnowledgeBase,
                         workspace_path: Path, upstream_sha: str,
                         attempt: int, start_time: float) -> _AttemptOutcome:
    """Run --continue after approval and return outcome."""
    recipe = workspace_path.name
    summary = build_change_summary(workspace_path, upstream_sha)
    details = gather_pattern_details(workspace_path, upstream_sha)

    continue_exit, _ = run_corrector(config, continue_mode=True)

    if continue_exit in (EXIT_SUCCESS, EXIT_ALREADY_APPLIED):
        save_knowledge_pattern(
            config, knowledge_base, summary, upstream_sha, recipe,
            details=details
        )
        return _AttemptOutcome(result=_make_result(
            config.cve_id, ResultStatus.CONFLICT_RESOLVED,
            attempt, start_time, f"Resolved via {config.backend}"
        ))

    if continue_exit in UNRECOVERABLE_EXITS:
        return _AttemptOutcome(result=_make_result(
            config.cve_id, ResultStatus.FAILED,
            attempt, start_time, f"Unrecoverable error (exit {continue_exit})"
        ))

    print(f"--continue exited with recoverable code {continue_exit}, retrying...")
    return _AttemptOutcome(next_step=continue_exit)


def _handle_not_applicable(config: AgentConfig, cve_info: dict,
                           knowledge_base: KnowledgeBase,
                           start_time: float,
                           cve_data: Optional[dict] = None,
                           workspace_path: Optional[Path] = None) -> CveResult:
    """Run agent analysis on an empty cherry-pick and write CVE_STATUS."""
    if cve_data is None:
        try:
            cve_data = load_cve_metadata(config.cve_info_path)
        except (FileNotFoundError, ValueError) as err:
            return _make_result(
                config.cve_id, ResultStatus.FAILED, 0, start_time, str(err)
            )
    if workspace_path is None:
        workspace_path = get_workspace_path(config, cve_data)
    if not workspace_path:
        return _make_result(
            config.cve_id, ResultStatus.SKIPPED, 0, start_time,
            "Patch already applied — nothing to backport"
        )

    print("\n--- Analysis: cherry-pick produced no changes ---")
    context_file = build_context(
        workspace_path, EXIT_SUCCESS, config.cve_id, cve_info, knowledge_base,
        model=config.model, backend=config.backend
    )
    upstream_sha = get_upstream_sha(cve_info, workspace_path)
    guarded_session(context_file, workspace_path, upstream_sha, cve_info,
                         config.model, config.session_timeout, config.cve_id,
                         config.interactive, backend_name=config.backend)

    reason = _read_conclusion(workspace_path)
    if not reason:
        reason = "Patch already applied — nothing to backport"

    print(f"Conclusion: {reason}")
    run_corrector(config, mark_not_applicable=reason)

    return _make_result(config.cve_id, ResultStatus.SKIPPED, 0, start_time,
                        reason)


def _handle_clean_apply(config: AgentConfig, workspace_path: Path,
                        cve_info: dict, knowledge_base: KnowledgeBase,
                        start_time: float) -> CveResult:
    """Handle the analysis phase after a clean apply (exit 0)."""
    context_file = build_context(
        workspace_path, EXIT_SUCCESS, config.cve_id, cve_info, knowledge_base,
        model=config.model, backend=config.backend
    )
    print("\n--- Mandatory analysis phase ---")
    upstream_sha = get_upstream_sha(cve_info, workspace_path)
    guarded_session(context_file, workspace_path, upstream_sha, cve_info,
                         config.model, config.session_timeout, config.cve_id,
                         config.interactive, backend_name=config.backend)

    conclusion_reason = _read_conclusion(workspace_path)
    if conclusion_reason:
        print(f"\n--- Agent concluded {config.cve_id} is not applicable ---")
        print(f"Reason: {conclusion_reason}")
        run_corrector(config, mark_not_applicable=conclusion_reason)
        return _make_result(config.cve_id, ResultStatus.SKIPPED, 0,
                            start_time, conclusion_reason)

    approval, _ = request_approval(workspace_path, upstream_sha, config)

    if approval == "rejected":
        return _make_result(
            config.cve_id, ResultStatus.ESCALATED, 0, start_time,
            "Human rejected during analysis"
        )
    if approval == "edit":
        return _resolution_loop(
            config, workspace_path, EXIT_SUCCESS, cve_info, knowledge_base
        )

    recipe = workspace_path.name
    summary = build_change_summary(workspace_path, upstream_sha)
    details = gather_pattern_details(workspace_path, upstream_sha)
    continue_exit, _ = run_corrector(config, continue_mode=True)
    if continue_exit in (EXIT_SUCCESS, EXIT_ALREADY_APPLIED):
        save_knowledge_pattern(
            config, knowledge_base, summary, upstream_sha, recipe,
            details=details
        )
        return _make_result(
            config.cve_id, ResultStatus.SUCCESS, 0, start_time,
            "Clean apply with analysis"
        )
    if continue_exit in UNRECOVERABLE_EXITS:
        return _make_result(
            config.cve_id, ResultStatus.FAILED, 0, start_time,
            f"Failed after analysis (exit {continue_exit})"
        )

    return _resolution_loop(
        config, workspace_path, continue_exit, cve_info, knowledge_base
    )


def process_single_cve(config: AgentConfig,
                       knowledge_base: KnowledgeBase) -> CveResult:
    """Process a single CVE through the full agent workflow."""
    start_time = time.monotonic()
    print(f"\n{'=' * 60}")
    print(f"Processing {config.cve_id}")
    print(f"{'=' * 60}")

    try:
        if config.cve_info_path:
            cve_data = load_cve_metadata(config.cve_info_path)
        elif config.fix_url and config.recipe:
            from shared.url_parser import parse_fix_url
            url_metadata = parse_fix_url(config.fix_url)
            cve_data = {config.cve_id: {'name': config.recipe, **url_metadata}}
        else:
            return _make_result(
                config.cve_id, ResultStatus.FAILED, 0, start_time,
                "No --cve-info or --fix-url provided"
            )
    except (FileNotFoundError, ValueError) as err:
        return _make_result(
            config.cve_id, ResultStatus.FAILED, 0, start_time, str(err)
        )
    cve_info = cve_data.get(config.cve_id, {})
    if not cve_info:
        result = _make_result(
            config.cve_id, ResultStatus.FAILED, 0, start_time,
            "CVE not found in metadata"
        )
        return result

    exit_code, corrector_output = run_corrector(config)
    print(f"cve-corrector exited with code {exit_code}")

    if exit_code in UNRECOVERABLE_EXITS:
        if exit_code == EXIT_ALREADY_APPLIED or '--allow-empty' in corrector_output:
            result = _handle_not_applicable(
                config, cve_info, knowledge_base, start_time,
                cve_data=cve_data
            )
        elif exit_code == EXIT_NOT_APPLICABLE:
            result = _make_result(
                config.cve_id, ResultStatus.SKIPPED, 0, start_time,
                "Vulnerable code not present in recipe version"
            )
        elif exit_code == EXIT_PTEST_PREEXISTING:
            result = _make_result(
                config.cve_id, ResultStatus.SKIPPED, 0, start_time,
                "Pre-patch ptest already failing — unknown pre-existing issue, aborting"
            )
        elif exit_code == EXIT_BUILD_PREEXISTING:
            result = _make_result(
                config.cve_id, ResultStatus.SKIPPED, 0, start_time,
                "Pre-patch build already failing — skipping"
            )
        else:
            result = _make_result(
                config.cve_id, ResultStatus.FAILED, 0, start_time,
                f"Unrecoverable error (exit {exit_code})"
            )
        return result

    workspace_path = get_workspace_path(config, cve_data)
    if not workspace_path:
        if exit_code == EXIT_SUCCESS:
            result = _make_result(
                config.cve_id, ResultStatus.SUCCESS, 0, start_time,
                "Clean apply (workspace already finalized)"
            )
        else:
            result = _make_result(
                config.cve_id, ResultStatus.FAILED, 0, start_time,
                "Could not determine workspace path"
            )
        return result

    if config.clean:
        agent_dir = get_agent_dir(workspace_path)
        if agent_dir.exists():
            shutil.rmtree(agent_dir)
            agent_dir.mkdir(parents=True, exist_ok=True)
            print(f"Cleaned agent state: {agent_dir}")

    if exit_code == EXIT_SUCCESS:
        if _is_empty_cherry_pick(workspace_path, cve_info):
            upstream_sha = get_upstream_sha(cve_info, workspace_path)
            print(f"\nEmpty cherry-pick for {config.cve_id} — upstream fix "
                  f"already present in tree ({upstream_sha[:12]})")
            result = _make_result(
                config.cve_id, ResultStatus.SKIPPED, 0, start_time,
                f"Empty cherry-pick — fix already in tree ({upstream_sha[:12]})"
            )
        else:
            result = _handle_clean_apply(
                config, workspace_path, cve_info, knowledge_base, start_time
            )
    elif exit_code in RECOVERABLE_EXITS:
        result = _resolution_loop(
            config, workspace_path, exit_code, cve_info, knowledge_base
        )
    else:
        result = _make_result(
            config.cve_id, ResultStatus.FAILED, 0, start_time,
            f"Unexpected exit code {exit_code}"
        )

    return result
