# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""CVE processing orchestration — single-CVE workflow and resolution loop."""
import dataclasses
import json
import os
import shutil
import time
from pathlib import Path
from typing import Optional

from shared.url_parser import HASH_RE, extract_commit_hash

from . import (
    EXIT_ALREADY_APPLIED,
    EXIT_BUILD_ERROR,
    EXIT_BUILD_PREEXISTING,
    EXIT_IGNORED_BY_STATUS,
    EXIT_NOT_APPLICABLE,
    EXIT_PTEST_ERROR,
    EXIT_PTEST_PREEXISTING,
    EXIT_SUCCESS,
    RECOVERABLE_EXITS,
    UNRECOVERABLE_EXITS,
    AgentConfig,
    CveResult,
    ResultStatus,
    get_agent_dir,
)
from .commit_notes import (
    Violation,
    check_note_budget,
    format_violations,
    has_hard_violation,
)
from .context import build_context
from .corrector import get_workspace_path, load_cve_metadata, run_corrector
from .git import compute_allowed_files, get_changed_files, get_upstream_sha, run_git_stdout
from .knowledge import KnowledgeBase, gather_pattern_details, save_knowledge_pattern
from .review import build_change_summary, request_approval
from .session import guarded_session

# Safety cap on how many times a single CVE run may be re-launched with an
# agent-suggested, human/trust-accepted commit appended to the chain. Prevents
# a misbehaving session from suggesting an endless stream of commits.
_MAX_CHAIN_EXTENSIONS = 3

# Safety cap on how many times a single CVE run may be bounced back to the AI
# purely to shorten over-budget ``Conflicts Resolved:`` notes. Past this, the
# resolution is accepted with a warning: discarding a technically correct
# backport over commit-message prose would be the worse outcome.
_MAX_NOTE_REJECTS = 2


@dataclasses.dataclass
class _AttemptOutcome:
    """Result of a single resolution attempt."""
    result: Optional[CveResult] = None
    next_step: Optional[int] = None
    # Set when the attempt was bounced solely because the AI's commit notes
    # exceeded the length budget, so the loop can cap those retries separately
    # from genuine resolution failures.
    note_rejected: bool = False


@dataclasses.dataclass
class _Escalation:
    """A parsed ``needs_human`` conclusion.

    ``suggested_commits`` holds any upstream commits the agent named as needed
    to complete the backport but which reach files outside its current
    allowed-files scope (a companion/prerequisite commit). Each entry is a
    commit URL or a full SHA; empty when the agent asked for review without
    proposing a concrete commit.
    """
    reason: str
    suggested_commits: list[str] = dataclasses.field(default_factory=list)


class _AcceptedSuggestion(Exception):
    """Signals that a human (or ``--trust``) accepted agent-suggested commits.

    Carries the full, ordered ``--fix-url`` chain (original fix first, then the
    accepted commits) to re-run the corrector with. The corrector records the
    whole chain in its ``series_state``, and ``get_all_upstream_shas`` feeds
    that back into the next session's allowed files — so the guard extends to
    the suggested commits' files automatically, no guard code changes needed.
    """

    def __init__(self, fix_urls: list[str], new_hashes: list[str]) -> None:
        super().__init__()
        self.fix_urls = fix_urls
        self.new_hashes = new_hashes


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


def _read_escalation(workspace_path: Path) -> Optional[_Escalation]:
    """Read the agent conclusion file if it asked for human review.

    Distinct from :func:`_read_conclusion`: a ``needs_human`` conclusion means
    the CVE *is* applicable but can't be safely auto-backported (e.g. a
    prerequisite that reaches outside the allowed files, or a structural
    dependency). It must escalate to a human — NOT be marked not-applicable,
    which would wrongly report the vulnerability as a non-issue.

    When the agent also names ``suggested_commits`` (a companion/prerequisite
    commit whose files fall outside the current allowed scope), those are
    returned so the caller can offer to re-run with an extended commit chain.

    Returns:
        An :class:`_Escalation` if the agent requested review, else ``None``.
    """
    try:
        conclusion_file = get_agent_dir(workspace_path) / 'conclusion.json'
        if not conclusion_file.exists():
            return None
        data = json.loads(conclusion_file.read_text(encoding='utf-8'))
        if data.get('needs_human'):
            reason = data.get('reason', 'Agent requested human review (no details)')
            raw = data.get('suggested_commits')
            suggested: list[str] = []
            if isinstance(raw, list):
                suggested = [str(c).strip() for c in raw if str(c).strip()]
            return _Escalation(reason=reason, suggested_commits=suggested)
    except (json.JSONDecodeError, OSError):
        pass
    return None


def _clear_conclusion(workspace_path: Path) -> None:
    """Delete any ``conclusion.json`` left over from a previous attempt.

    ``conclusion.json`` lives in the persistent agent dir, which survives
    across resolution attempts within a single CVE run. Both
    :func:`_read_conclusion` and :func:`_read_escalation` read it *after* a
    session to learn that session's verdict. If an earlier attempt wrote a
    ``needs_human`` (or ``not_applicable``) verdict and a later attempt then
    *resolves* the conflict without writing a fresh conclusion, the stale file
    would be misread as the new session's verdict — discarding a good
    resolution and reporting the CVE as escalated (or skipped). Clearing it
    before each session guarantees the orchestrator only ever observes the
    verdict of the session that just ran.
    """
    try:
        conclusion_file = get_agent_dir(workspace_path) / 'conclusion.json'
        conclusion_file.unlink()
    except (FileNotFoundError, OSError):
        # FileNotFoundError: nothing to clear. OSError also covers a
        # non-resolvable agent dir (e.g. get_agent_dir's mkdir failing in
        # synthetic unit-test paths) — clearing is best-effort, so ignore it.
        pass


def _original_fix_url(cve_info: dict) -> Optional[str]:
    """Return the first fix-commit URL from the CVE metadata, if any.

    Prefers ``patches`` (the human-facing fix URLs), falling back to
    ``hash_details`` URLs. Only returns a URL that :func:`extract_commit_hash`
    can resolve to a commit — otherwise it is useless as the head of a
    ``--fix-url`` chain.
    """
    for url in cve_info.get('patches') or []:
        if isinstance(url, str) and extract_commit_hash(url):
            return url
    for detail in cve_info.get('hash_details') or []:
        url = detail.get('url')
        if isinstance(url, str) and extract_commit_hash(url):
            return url
    return None


def _normalize_suggestion(suggestion: str, ref_url: Optional[str],
                          ref_hash: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Resolve one agent suggestion to a ``(fix_url, hash)`` pair.

    A suggestion is either a full commit URL or a bare commit SHA. A URL is
    accepted as-is once :func:`extract_commit_hash` confirms it names a commit.
    A bare SHA is turned into a fetchable URL by substituting it into the
    original fix URL's template (``ref_url``) — the sibling commit lives in the
    same repository and forge, so the proven URL shape carries over verbatim,
    which keeps this forge-agnostic. Returns ``(None, None)`` when the
    suggestion cannot be resolved.
    """
    if '://' in suggestion:
        commit_hash = extract_commit_hash(suggestion)
        return (suggestion, commit_hash) if commit_hash else (None, None)
    if HASH_RE.fullmatch(suggestion) and ref_url and ref_hash and ref_hash in ref_url:
        candidate = ref_url.replace(ref_hash, suggestion)
        if extract_commit_hash(candidate) == suggestion:
            return candidate, suggestion
    return None, None


def _build_extended_chain(cve_info: dict,
                          suggested: list[str]) -> tuple[list[str], list[str]]:
    """Build the ordered ``--fix-url`` chain for a re-run.

    The chain is ``[original_fix_url, *accepted_suggestions]``. Suggestions
    that cannot be resolved to a fetchable URL, or that duplicate a commit
    already in the chain, are skipped.

    Returns:
        ``(fix_urls, new_hashes)``. Both are empty if there is no resolvable
        original fix URL or no genuinely new commit to add.
    """
    original_url = _original_fix_url(cve_info)
    if not original_url:
        print("  \u26a0 No resolvable fix URL in metadata — cannot build an "
              "extended chain; escalating")
        return [], []

    hashes = cve_info.get('hashes') or []
    original_hash = hashes[0] if hashes else None
    existing = set(hashes)

    chain = [original_url]
    new_hashes: list[str] = []
    for suggestion in suggested:
        url, commit_hash = _normalize_suggestion(
            suggestion, original_url, original_hash)
        if not url or not commit_hash:
            print(f"  \u26a0 Could not resolve suggested commit '{suggestion}' "
                  f"to a fetchable URL — skipping")
            continue
        if commit_hash in existing or commit_hash in new_hashes:
            print(f"  Suggested commit {commit_hash[:12]} already in chain — "
                  f"skipping")
            continue
        chain.append(url)
        new_hashes.append(commit_hash)

    if not new_hashes:
        return [], []
    return chain, new_hashes


def _accept_suggestion(config: AgentConfig, new_hashes: list[str]) -> bool:
    """Decide whether to accept agent-suggested commits.

    ``--trust`` auto-accepts (the operator has already opted into unattended
    operation). Interactive runs prompt the human. A non-interactive run
    without ``--trust`` cannot safely widen scope on its own, so it declines
    and the caller escalates.
    """
    joined = ', '.join(h[:12] for h in new_hashes)
    if config.trust_mode:
        print(f"  --trust: auto-accepting suggested commit(s) {joined}; "
              f"re-running with extended scope")
        return True
    if config.interactive:
        response = input(
            f"  Accept suggested commit(s) {joined} and re-run with extended "
            f"scope? [y/N]: "
        ).strip().lower()
        return response in ('y', 'yes')
    print("  Non-interactive without --trust: cannot auto-accept a scope "
          "extension — escalating")
    return False


def _handle_escalation(config: AgentConfig, cve_info: dict,
                       escalation: _Escalation, attempt: int,
                       start_time: float) -> CveResult:
    """Report an escalation and, if commits were suggested and accepted,
    signal a re-run with an extended chain.

    Raises:
        _AcceptedSuggestion: when suggested commits are accepted (interactive
            approval or ``--trust``), carrying the new ``--fix-url`` chain.
    """
    print("\n\u26a0 Agent escalated to human review:")
    print(f"  {escalation.reason}")
    if escalation.suggested_commits:
        print(f"  Agent suggested commit(s): "
              f"{', '.join(escalation.suggested_commits)}")
        chain, new_hashes = _build_extended_chain(
            cve_info, escalation.suggested_commits)
        if new_hashes and _accept_suggestion(config, new_hashes):
            raise _AcceptedSuggestion(chain, new_hashes)
    return _make_result(
        config.cve_id, ResultStatus.ESCALATED, attempt, start_time,
        escalation.reason
    )


def validate_commit_notes(workspace_path: Path) -> list[Violation]:
    """Check HEAD's ``Conflicts Resolved:`` notes against the length budget.

    Backstop for the workspace ``commit-msg`` hook
    (:func:`cve_agent.git.install_notes_hook`): the hook catches the AI's own
    commits, this catches anything that reached HEAD another way (a manual
    edit, or a commit created before the hook was installed).

    Args:
        workspace_path: Path to the devtool workspace.

    Returns:
        Budget violations for HEAD's commit message, empty when it fits.
    """
    commit_msg = run_git_stdout(['log', '-1', '--format=%B'], workspace_path)
    return check_note_budget(commit_msg)


def _append_note_report_to_audit_log(workspace_path: Path, cve_id: str,
                                     report: str) -> None:
    """Record a note-budget report in the session's audit log.

    Best-effort: the audit log is operator-facing telemetry, so a failure to
    write it must never affect the resolution outcome.
    """
    try:
        recipe = workspace_path.name
        log_path = (get_agent_dir(workspace_path)
                    / f'{recipe}-{cve_id}-ai-changes.log')
        with log_path.open('a', encoding='utf-8') as handle:
            handle.write(f"\n=== Commit note budget ===\n{report}\n")
    except OSError:
        pass


def _enforce_note_budget(config: AgentConfig, workspace_path: Path,
                         note_rejects: int) -> Optional[_AttemptOutcome]:
    """Bounce the attempt back to the AI if HEAD's notes are over budget.

    Soft violations are reported and allowed through. A hard violation sends
    the overage to the next session as feedback — unless
    :data:`_MAX_NOTE_REJECTS` bounces have already been spent, in which case it
    is reported and accepted.

    Args:
        config: Agent configuration.
        workspace_path: Path to the devtool workspace.
        note_rejects: Bounces already spent in this CVE run.

    Returns:
        A retry outcome when the attempt should be bounced, else ``None`` to
        continue to approval.
    """
    violations = validate_commit_notes(workspace_path)
    if not violations:
        return None

    report = format_violations(violations)
    print(f"\n{report}")
    _append_note_report_to_audit_log(workspace_path, config.cve_id, report)

    if not has_hard_violation(violations):
        return None

    if note_rejects >= _MAX_NOTE_REJECTS:
        print(f"\n\u26a0 Commit notes still over budget after "
              f"{_MAX_NOTE_REJECTS} rejection(s) — accepting the resolution "
              f"and continuing to review")
        return None

    agent_dir = get_agent_dir(workspace_path)
    directive = (
        f"{report}\n\nRewrite ONLY the `Conflicts Resolved:` notes in the "
        f"commit message with `git commit --amend -F <file>` (never "
        f"`--amend --no-edit`, which resubmits the same rejected message). Do "
        f"not change any code and do not redo the resolution — it is already "
        f"correct."
    )
    feedback_file = agent_dir / 'human_feedback.txt'
    # Never drop feedback a human left for this attempt — append to it.
    existing = (feedback_file.read_text(encoding='utf-8').strip()
                if feedback_file.exists() else '')
    feedback_file.write_text(
        f"{existing}\n\n{directive}" if existing else directive,
        encoding='utf-8')
    print("\nSending the overage back to the AI to shorten the notes "
          f"(bounce {note_rejects + 1}/{_MAX_NOTE_REJECTS})")
    return _AttemptOutcome(note_rejected=True)


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
                     knowledge_base: Optional[KnowledgeBase]) -> CveResult:
    """Run the resolution loop: context -> AI backend -> approval -> continue."""
    start_time = time.monotonic()
    current_step = exit_code
    attempt = 0
    total_attempts = 0
    note_rejects = 0
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
            knowledge_base, attempt, start_time, note_rejects
        )
        if outcome.note_rejected:
            # A bounce over commit-message prose must not spend a resolution
            # attempt: the backport itself is already correct, and escalating
            # it for being wordy is exactly what _MAX_NOTE_REJECTS exists to
            # prevent. `note_rejects` caps these, and `total_attempts` still
            # counts them against any --max-total-attempts ceiling.
            note_rejects += 1
            attempt -= 1
        if outcome.result is not None:
            return outcome.result

        if outcome.next_step is not None and outcome.next_step != current_step:
            print(f"Step changed ({current_step} -> {outcome.next_step}), "
                  f"resetting attempt counter")
            current_step = outcome.next_step
            attempt = 0
            # A new phase writes new notes, so it gets its own bounce budget —
            # otherwise notes added during a build/ptest amend would never be
            # checked once the conflict phase spent the allowance.
            note_rejects = 0

    return _make_result(
        config.cve_id, ResultStatus.ESCALATED,
        attempt, start_time,
        f"Max retries ({config.max_retries}) exhausted at step {current_step}"
    )


def _run_single_resolution_attempt(
        config: AgentConfig, workspace_path: Path, exit_code: int,
        cve_info: dict, knowledge_base: Optional[KnowledgeBase],
        attempt: int, start_time: float,
        note_rejects: int = 0) -> _AttemptOutcome:
    """Execute one resolution attempt: context -> session -> approval -> continue."""
    # Discard any conclusion.json from a previous attempt so the reads below
    # reflect only this session's verdict — a stale needs_human/not_applicable
    # file would otherwise override a resolution this attempt actually makes.
    _clear_conclusion(workspace_path)
    # Pre-flight: without a file scope there is nothing the session may touch.
    # The scope guard would reject every write and the AI can only escalate, so
    # escalate here instead of paying for a session that cannot succeed.
    allowed = compute_allowed_files(cve_info, workspace_path)
    if not allowed:
        upstream_sha = get_upstream_sha(cve_info, workspace_path)
        reason = (
            f"Cannot determine the file scope for {config.cve_id}: upstream "
            f"commit {upstream_sha[:12] if upstream_sha else 'unknown'} lists "
            f"no files in {workspace_path} and the workspace holds no "
            f"corrector changes or unmerged paths to fall back on. Nothing "
            f"can be modified or staged — needs human review."
        )
        print(f"\n\u26a0 {reason}")
        return _AttemptOutcome(result=_make_result(
            config.cve_id, ResultStatus.ESCALATED, attempt, start_time, reason))

    print("Building AI context (upstream diffs, knowledge, conflict details)...")
    context_file = build_context(
        workspace_path, exit_code, config.cve_id, cve_info, knowledge_base,
        model=config.model, backend=config.backend
    )
    upstream_sha = get_upstream_sha(cve_info, workspace_path)

    # Snapshot HEAD before the session to detect no-op resolutions
    pre_session_head = run_git_stdout(
        ['rev-parse', 'HEAD'], workspace_path
    ).strip()

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

    escalation = _read_escalation(workspace_path)
    if escalation:
        return _AttemptOutcome(result=_handle_escalation(
            config, cve_info, escalation, attempt, start_time))

    if not workspace_path.exists():
        return _AttemptOutcome(result=_make_result(
            config.cve_id, ResultStatus.CONFLICT_RESOLVED,
            attempt, start_time,
            f"Resolved via {config.backend} (workspace finalized)"
        ))

    # Detect no-op sessions: if the AI didn't change HEAD and the failure
    # was a build or ptest error, skip approval and retry immediately.
    # There's nothing for the human to review — the AI didn't fix anything.
    post_session_head = run_git_stdout(
        ['rev-parse', 'HEAD'], workspace_path
    ).strip()
    if (pre_session_head == post_session_head
            and exit_code in (EXIT_BUILD_ERROR, EXIT_PTEST_ERROR)):
        print(f"AI session made no changes to resolve exit code {exit_code}, "
              f"retrying...")
        return _AttemptOutcome()

    # The AI made a real change (HEAD moved, or this is a conflict resolution).
    # Before anything else, hold it to the commit-note budget: the workspace
    # commit-msg hook already rejects over-long notes as the AI writes them,
    # but a manual edit or a pre-hook commit can still reach HEAD.
    note_outcome = _enforce_note_budget(config, workspace_path, note_rejects)
    if note_outcome is not None:
        return note_outcome

    # Show the human the review *before* finalizing: request_approval runs
    # against the still-present workspace, and only on approval does
    # _finalize_resolution run --continue (build + ptest + devtool finish).
    # Verifying the build before approval is not done here — it would require
    # running --continue, whose devtool finish removes the workspace and leaves
    # nothing to review, and it would also finalize a change the human has not
    # yet approved. The agent self-verifies its build before finishing (see
    # AGENT_INSTRUCTIONS.md "Build Verification"), and --continue re-verifies
    # authoritatively after approval, retrying on a recoverable failure.
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


def _finalize_resolution(config: AgentConfig, knowledge_base: Optional[KnowledgeBase],
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
                           knowledge_base: Optional[KnowledgeBase],
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
                        cve_info: dict, knowledge_base: Optional[KnowledgeBase],
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

    escalation = _read_escalation(workspace_path)
    if escalation:
        return _handle_escalation(config, cve_info, escalation, 0, start_time)

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
                       knowledge_base: Optional[KnowledgeBase]) -> CveResult:
    """Process a single CVE through the full agent workflow.

    Wraps :func:`_run_cve_pipeline` in a re-run loop: when the agent suggests a
    companion/prerequisite commit and it is accepted (interactive approval or
    ``--trust``), the pipeline raises :class:`_AcceptedSuggestion` and we
    re-launch with the accepted commit appended to the ``--fix-url`` chain. The
    corrector then cherry-picks the whole chain, which widens the session's
    allowed-files guard to the suggested commit's files automatically.
    """
    start_time = time.monotonic()
    print(f"\n{'=' * 60}")
    print(f"Processing {config.cve_id}")
    print(f"{'=' * 60}")

    accepted_hashes: set[str] = set()
    extensions = 0
    total_credits: Optional[float] = None
    credits_unit: Optional[str] = None
    while True:
        try:
            result = _run_cve_pipeline(config, knowledge_base, start_time)
            total_credits, credits_unit = _accumulate_credits(
                config, total_credits, credits_unit)
            result.total_credits = total_credits
            result.credits_unit = credits_unit
            return result
        except _AcceptedSuggestion as accepted:
            # Read this run's credits before the next pipeline's clean=True
            # wipes the agent dir, so re-run costs accumulate rather than reset.
            total_credits, credits_unit = _accumulate_credits(
                config, total_credits, credits_unit)
            genuinely_new = [h for h in accepted.new_hashes
                             if h not in accepted_hashes]
            if not genuinely_new or extensions >= _MAX_CHAIN_EXTENSIONS:
                result = _make_result(
                    config.cve_id, ResultStatus.ESCALATED, 0, start_time,
                    "Suggested commits already tried or chain-extension cap "
                    f"({_MAX_CHAIN_EXTENSIONS}) reached — escalating"
                )
                result.total_credits = total_credits
                result.credits_unit = credits_unit
                return result
            accepted_hashes.update(genuinely_new)
            extensions += 1
            # Keep --cve-info (version + recipe metadata); the fix-url chain is
            # authoritative for which commits are applied, and clean=True forces
            # a fresh cherry-pick of the whole chain.
            config = dataclasses.replace(
                config, fix_urls=accepted.fix_urls, clean=True)
            print(f"\n{'=' * 60}")
            print(f"Re-running {config.cve_id} with extended commit chain "
                  f"({len(accepted.fix_urls)} commits, "
                  f"+{len(genuinely_new)} accepted)")
            print(f"{'=' * 60}")


def _resolve_cve_data(config: AgentConfig) -> Optional[dict]:
    """Build the CVE metadata dict from ``--cve-info`` or ``--fix-url``.

    Mirrors the resolution in :func:`_run_cve_pipeline` so credit aggregation
    can locate the recipe workspace by the same rules. Returns ``None`` when
    neither source is available or metadata can't be loaded.
    """
    if config.cve_info_path:
        return load_cve_metadata(config.cve_info_path)
    if config.fix_urls and config.recipe:
        from shared.url_parser import parse_fix_urls
        url_metadata = parse_fix_urls(config.fix_urls)
        return {config.cve_id: {'name': config.recipe, **url_metadata}}
    return None


def _accumulate_credits(
        config: AgentConfig, running_total: Optional[float],
        running_unit: Optional[str]) -> tuple[Optional[float], Optional[str]]:
    """Fold this pipeline run's session credits into the running per-CVE total.

    Reads ``sum_session_credits`` from the recipe's agent dir (populated by
    :func:`cve_agent.session.guarded_session` via ``sessions.log``) and adds it
    to ``running_total``. The agent dir is derived straight from ``BBPATH`` and
    the recipe name rather than via :func:`get_workspace_path`, because a
    successful run's ``devtool finish`` removes the source workspace before we
    get here — but the agent dir lives outside it and survives. Failures to
    resolve it are non-fatal (credits are best-effort telemetry), so the
    running total is returned unchanged.
    """
    from .session import sum_session_credits

    agent_dir = _agent_dir_for(config)
    if agent_dir is None:
        return running_total, running_unit

    run_credits, run_unit = sum_session_credits(agent_dir)
    if run_credits is None:
        return running_total, running_unit
    if running_total is None:
        return run_credits, run_unit
    return running_total + run_credits, running_unit or run_unit


def _agent_dir_for(config: AgentConfig) -> Optional[Path]:
    """Resolve the recipe's agent dir from ``BBPATH`` + recipe name.

    Mirrors :func:`cve_agent.get_agent_dir`'s layout
    (``<build>/workspace/cve_agent/<recipe>``) without needing the source
    workspace to exist, so it still works after ``devtool finish``. Returns
    ``None`` when the recipe or ``BBPATH`` can't be determined.
    """
    try:
        cve_data = _resolve_cve_data(config)
    except Exception:
        return None
    recipe = (cve_data or {}).get(config.cve_id, {}).get('name')
    bbpath = os.environ.get('BBPATH', '')
    if not recipe or not bbpath:
        return None
    return Path(bbpath.split(':')[0]) / 'workspace' / 'cve_agent' / recipe


def _run_cve_pipeline(config: AgentConfig, knowledge_base: Optional[KnowledgeBase],
                      start_time: float) -> CveResult:
    """Run the CVE pipeline once (corrector -> resolution loop).

    May raise :class:`_AcceptedSuggestion`, which :func:`process_single_cve`
    catches to re-run with an extended commit chain.
    """
    try:
        cve_data = _resolve_cve_data(config)
        if cve_data is None:
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
        elif exit_code == EXIT_IGNORED_BY_STATUS:
            result = _make_result(
                config.cve_id, ResultStatus.SKIPPED, 0, start_time,
                "Recipe's CVE_STATUS marks this CVE as ignored or already patched"
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
