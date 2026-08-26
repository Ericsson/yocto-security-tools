# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""AI session management for CVE agent.

Spawns AI sessions with context files, wraps them with file-scope
enforcement (pre-commit hook + post-session revert) and the backport-note
length budget (commit-msg hook).
"""
import difflib
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import TracebackType
from typing import Optional

from shared.git_runner import (
    copy_missing_files_from_devtool,
    force_checkout_branch,
    merge_diff_flags,
)

from . import get_agent_dir
from .backend import SessionResult, get_backend
from .git import (
    compute_allowed_files,
    expand_path_variants,
    get_all_upstream_shas,
    install_notes_hook,
    install_scope_hook,
    remove_notes_hook,
    remove_scope_hook,
    revert_unauthorized_changes,
    run_capture,
    run_git_stdout,
    upstream_changed_files,
    warn_if_hooks_disabled,
)


def check_resolution_state(workspace_path: Path) -> bool:
    """Check if the workspace has unresolved conflicts.

    Returns:
        True if no conflict markers remain, False otherwise.
    """
    if not workspace_path.exists():
        return True
    result = run_capture(
        ['git', 'status', '--porcelain'], cwd=workspace_path
    )
    if result.returncode != 0:
        return False
    for line in result.stdout.splitlines():
        if line and len(line) >= 2 and (line[0] == 'U' or line[1] == 'U'):
            return False
    return True


# Path-variant expansion now lives in ``cve_agent.git`` so ``context.py`` and
# the scope guard share one implementation. Kept as a module-level alias for
# existing callers/tests that reference it here.
_expand_path_variants = expand_path_variants


def _ensure_cve_branch(workspace_path: Path, cve_id: str) -> None:
    """Check out the CVE branch so the agent commits onto the source of truth.

    The CVE branch is named after the CVE id (see
    ``cve_corrector.workspace.prepare_cve_branch``). It holds the cherry-picked
    upstream fix and is the branch ``cherry_pick_to_devtool`` transfers to the
    throwaway ``devtool`` branch. If the agent were left on ``devtool`` (where
    the corrector's build step leaves it), any amend would be discarded on the
    next resume.

    After landing on the CVE branch, restore the files the devtool branch
    tracks but the (upstream-history) CVE branch does not — generated autotools
    output (configure, Makefile.in, ...) and secondary-tarball payloads such as
    libxml2's ``xmlconf/`` W3C conformance suite. Switching branches drops
    them, and without them the agent's own ``devtool build`` verification fails
    in do_configure/do_compile before it can even test the fix. They are
    restored as untracked working-tree files, exactly as the corrector does
    before each build step.

    A no-op when ``cve_id`` is empty, the workspace is gone, or the branch does
    not exist (e.g. some unit-test setups).

    Args:
        workspace_path: Path to the devtool workspace.
        cve_id: CVE identifier, which is also the CVE branch name.
    """
    if not cve_id or not workspace_path.exists():
        return
    current = run_git_stdout(
        ['rev-parse', '--abbrev-ref', 'HEAD'], cwd=workspace_path
    ).strip()
    if current != cve_id:
        branch_exists = run_capture(
            ['git', 'rev-parse', '--verify', '--quiet', f'refs/heads/{cve_id}'],
            cwd=workspace_path,
        ).returncode == 0
        if not branch_exists:
            return
        if not force_checkout_branch(workspace_path, cve_id):
            print(f"\u26a0 Failed to check out CVE branch {cve_id} before "
                  f"session (currently on {current}) — the agent's fix may "
                  f"not persist")
            return
    copy_missing_files_from_devtool(workspace_path)


def guarded_session(context_file: Path, workspace_path: Path,
                    upstream_sha: str, cve_info: dict,
                    model: str = "claude-sonnet-5",
                    timeout: int = 300,
                    cve_id: str = "",
                    interactive: bool = False,
                    backend_name: str = "kiro") -> SessionResult:
    """Run AI session with file-scope enforcement.

    Installs a git pre-commit hook that blocks unauthorized files, runs the
    AI session via the configured backend, then verifies and reverts any
    unauthorized changes.
    """
    # Ensure the agent operates on the CVE branch — the source of truth that
    # cherry_pick_to_devtool transfers to the devtool branch. The corrector's
    # build step leaves the *devtool* branch checked out, and the agent's
    # command allow-list forbids switching branches, so without this the agent
    # would amend its fix onto devtool. That fix is then orphaned when the
    # session forces back to the CVE branch, and wiped entirely on the next
    # resume when reset_devtool_to_base + cherry_pick_to_devtool re-apply the
    # unfixed CVE-branch commit — silently reverting the agent's work every
    # round. Landing the amend on the CVE branch keeps the fix on the branch
    # that actually feeds the final patch.
    print("Preparing workspace (CVE branch checkout, restoring build files)...")
    _ensure_cve_branch(workspace_path, cve_id)

    all_shas = get_all_upstream_shas(cve_info, workspace_path)
    # The allowed set is computed by the same helper that fills context.md's
    # Allowed Files section, so the guard and the AI's instructions agree.
    allowed = compute_allowed_files(cve_info, workspace_path)
    # Snapshot upstream diffs per file before the session (single pass per SHA)
    upstream_diffs: dict[str, str] = {}
    for sha in all_shas:
        flags = merge_diff_flags(workspace_path, sha)
        for f in upstream_changed_files(workspace_path, sha):
            raw = run_git_stdout(['show', *flags, sha, '--', f], cwd=workspace_path)
            upstream_diffs[f] = _extract_diff_hunks(raw)

    recipe = workspace_path.name

    # The allowed set is the hard scope boundary for the whole session. It
    # intentionally permits the agent to bring in an in-scope prerequisite
    # (Strategy A in AGENT_INSTRUCTIONS.md): a `git cherry-pick` of a
    # prerequisite commit whose files are all within `allowed` passes the
    # pre-commit hook and survives revert_unauthorized_changes as its own
    # commit. A prerequisite reaching files OUTSIDE `allowed` is rejected by
    # the hook (and stripped post-session), which is the mechanical signal
    # for the agent to fall back to human review rather than widen its scope.
    # Both guards are installed inside the try: if installing the second one
    # fails, or anything between here and the session raises, cleanup must
    # still strip whichever hook did get written.
    result: SessionResult | None = None
    primary_error: tuple[BaseException, TracebackType | None] | None = None
    cleanup_errors: list[BaseException] = []
    pre_session_head: str | None = None
    # Cleanup must also run for KeyboardInterrupt/SystemExit, but the original
    # control-flow exception is preserved and re-raised after every guard step.
    try:
        install_scope_hook(workspace_path, allowed)
        # Same lifecycle as the scope guard: rejects the AI's own commits when
        # its `Conflicts Resolved:` notes blow the per-file budget, and is gone
        # before review.amend_commit_with_summary() appends the change summary.
        install_notes_hook(workspace_path)
        warn_if_hooks_disabled(workspace_path)
        print(f"\n=== Allowed files for this session ({len(allowed)}) ===")
        for f in sorted(allowed):
            print(f"  {f}")

        # Snapshot HEAD before session so audit log only covers agent changes
        pre_session_head = run_git_stdout(
            ['rev-parse', 'HEAD'], cwd=workspace_path
        ).strip()

        prompt = (
            f"Read the file {context_file} and follow all instructions in it. "
            f"The file contains conflict context, patch details, and resolution "
            f"steps for a CVE backport. Complete all tasks described in the "
            f"file.\n\n"
            f"Key details (also in the file):\n"
            f"- Recipe: {workspace_path.name}\n"
            f"- Agent dir: {get_agent_dir(workspace_path)}\n"
            f"- Workspace: {workspace_path}\n"
            f"- Allowed files: {', '.join(sorted(allowed))}\n"
        )

        backend = get_backend(backend_name)
        agent_dir = get_agent_dir(workspace_path)
        _log_session_start(agent_dir, context_file)

        print(f"Starting {backend_name} session (timeout {timeout}s)...")
        result = backend.run_session(
            prompt, workspace_path, allowed, model, timeout, interactive)
    except BaseException as exc:
        primary_error = (exc, exc.__traceback__)

    try:
        remove_scope_hook(workspace_path)
    except BaseException as exc:
        cleanup_errors.append(exc)
    try:
        remove_notes_hook(workspace_path)
    except BaseException as exc:
        cleanup_errors.append(exc)

    if workspace_path.exists():
        try:
            revert_unauthorized_changes(workspace_path, allowed)
        except BaseException as exc:
            cleanup_errors.append(exc)
        if pre_session_head is not None:
            try:
                _write_audit_log(
                    workspace_path, recipe, cve_id, all_shas, upstream_diffs,
                    pre_session_head)
            except BaseException as exc:
                cleanup_errors.append(exc)

    if primary_error is not None:
        for cleanup_error in cleanup_errors:
            print(
                "Session cleanup also failed: "
                f"{type(cleanup_error).__name__}",
                file=sys.stderr,
            )
        error, traceback = primary_error
        raise error.with_traceback(traceback)
    if cleanup_errors:
        error = cleanup_errors[0]
        for secondary in cleanup_errors[1:]:
            print(
                f"Additional session cleanup failure: {type(secondary).__name__}",
                file=sys.stderr,
            )
        raise error.with_traceback(error.__traceback__)
    if result is None:
        raise RuntimeError("backend returned no session result")

    _log_session_end(agent_dir, result)

    if result.transcript_path is not None:
        print(f"{backend_name} transcript: {result.transcript_path}")
    if result.failure_reason:
        print(
            f"{backend_name} session unresolved: {result.failure_reason}",
            file=sys.stderr,
        )

    return result


def _extract_diff_hunks(git_show_output: str) -> str:
    """Extract only the diff --git portion from git show output, stripping the commit header."""
    lines = git_show_output.splitlines()
    for i, line in enumerate(lines):
        if line.startswith('diff --git '):
            return '\n'.join(lines[i:])
    return ''


def _hunk_lines(diff: str) -> list[str]:
    """Extract only hunk content lines, ignoring headers and line numbers."""
    return [
        line for line in diff.splitlines()
        if line.startswith(('+', '-', ' '))
        and not line.startswith(('--- ', '+++ '))
    ]


def _format_diff_lines(diff: str) -> list[str]:
    """Format diff lines, marking actual +/- changes with a highlight prefix."""
    out = []
    for line in diff.splitlines():
        if line.startswith('+') and not line.startswith('+++'):
            out.append(f'  |>> {line}')
        elif line.startswith('-') and not line.startswith('---'):
            out.append(f'  |<< {line}')
        else:
            out.append(f'  |   {line}')
    return out


def _split_diff_by_file(diff: str) -> dict[str, str]:
    """Split a multi-file git diff into a per-file dict keyed by filepath."""
    per_file: dict[str, str] = {}
    current_file = None
    current_lines: list[str] = []
    for line in diff.splitlines():
        if line.startswith('diff --git '):
            if current_file:
                per_file[current_file] = '\n'.join(current_lines)
            parts = line.split(' b/', 1)
            current_file = parts[1] if len(parts) == 2 else None
            current_lines = [line]
        elif current_file:
            current_lines.append(line)
    if current_file:
        per_file[current_file] = '\n'.join(current_lines)
    return per_file


def _get_backport_note(workspace_path: Path) -> str:
    """Extract a representative backport-rationale line from HEAD's message.

    ``Conflicts Resolved:`` is just a bare section header with no content
    of its own, so this returns the first ``- <detail>`` bullet under it —
    the closest thing to a one-line rationale in the current format.
    """
    commit_msg = run_git_stdout(['log', '-1', '--format=%B'], cwd=workspace_path)
    lines = commit_msg.splitlines()
    in_conflicts_block = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('Conflicts Resolved:'):
            in_conflicts_block = True
            continue
        if in_conflicts_block and stripped.startswith('- '):
            return stripped
    for line in lines:
        if 'backport' in line.lower():
            return line.strip()
    return ''


def _build_deviation_section(filepath: str, agent_diff: str,
                              upstream_diff: str, backport_note: str) -> list[str]:
    """Build log lines for a single file that deviates from upstream.

    Shows the upstream diff once, then only the lines that differ between
    the upstream and agent versions (unified-style diff of the two patches).
    """
    upstream_hunks = _hunk_lines(upstream_diff)
    agent_hunks = _hunk_lines(agent_diff)

    # Build a compact view of what changed between upstream and agent
    delta = list(difflib.unified_diff(
        upstream_hunks, agent_hunks,
        fromfile='upstream', tofile='agent', lineterm=''))

    lines = [
        f'File: {filepath}',
        '-' * 72,
    ]
    if delta:
        lines.append('  Differences from upstream patch:')
        for d in delta:
            lines.append(f'  | {d}')
    lines.append('')
    lines.append('  Full upstream diff (for reference):')
    lines.extend(_format_diff_lines(upstream_diff))
    lines.append('')
    if backport_note:
        lines.append(f'  Resolution rationale: {backport_note}')
    lines.append('')
    return lines


def _write_audit_log(workspace_path: Path, recipe: str, cve_id: str,
                     all_shas: list[str], upstream_diffs: dict[str, str],
                     pre_session_head: str) -> None:
    """Write a human-readable audit log of AI changes that deviate from upstream.

    Only compares files that the agent modified during its session (from
    pre_session_head to HEAD), not files from prior clean cherry-picks.

    Args:
        workspace_path: Path to workspace.
        recipe: Recipe name.
        cve_id: CVE identifier.
        all_shas: All upstream SHAs that were cherry-picked.
        upstream_diffs: Map of filepath -> upstream diff content.
        pre_session_head: Git ref of HEAD before the kiro session started.
    """
    agent_dir = get_agent_dir(workspace_path)
    log_path = agent_dir / f'{recipe}-{cve_id}-ai-changes.log'
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

    lines = [
        'AI Changes Audit Log',
        f'Recipe:    {recipe}',
        f'CVE:       {cve_id}',
        f'Timestamp: {timestamp}',
        f'Upstream commits: {" ".join(all_shas)}',
        '=' * 72,
        '',
    ]

    agent_diff = run_git_stdout(['diff', 'original-version..HEAD', '--'], cwd=workspace_path)
    agent_per_file = _split_diff_by_file(agent_diff)
    backport_note = _get_backport_note(workspace_path)

    # Only audit files the agent actually changed during its session
    agent_touched = set(run_git_stdout(
        ['diff', '--name-only', f'{pre_session_head}..HEAD'], cwd=workspace_path
    ).splitlines())

    # Identify files not present in the baseline — these are new-file
    # creations that should have been omitted from the backport.
    baseline_new = set()
    for filepath in agent_per_file:
        if not run_git_stdout(
            ['ls-tree', 'original-version', '--', filepath],
            cwd=workspace_path
        ):
            baseline_new.add(filepath)

    deviations = 0
    for filepath, agent_file_diff in sorted(agent_per_file.items()):
        if filepath not in agent_touched:
            continue
        # Flag new files not in upstream as potential unauthorized additions
        if filepath in baseline_new:
            if filepath not in upstream_diffs:
                deviations += 1
                lines.extend([
                    f'--- NEW FILE (not in upstream): {filepath}',
                    'This file was created by the agent but is not part of',
                    'the upstream fix. Review whether it is necessary.',
                    '',
                ])
            continue
        upstream_hunk = upstream_diffs.get(filepath, '')
        # Skip files not in the upstream patch — these are guard reverts
        # (e.g. .gitignore deletions) and won't be in the final commit.
        if not upstream_hunk:
            continue
        if _hunk_lines(agent_file_diff) == _hunk_lines(upstream_hunk):
            continue
        deviations += 1
        lines.extend(_build_deviation_section(filepath, agent_file_diff,
                                              upstream_hunk, backport_note))

    if deviations == 0:
        if not agent_per_file:
            lines.append('Empty cherry-pick — upstream fix already present in tree.')
        else:
            lines.append('No deviations from upstream patch — agent applied commits verbatim.')
    else:
        lines.insert(6, f'Total deviations: {deviations} file(s)\n')

    separator = '\n\n' if log_path.exists() else ''
    with open(log_path, 'a', encoding='utf-8') as f:
        f.write(separator + '\n'.join(lines))
    print(f'\nAudit log written to: {log_path}')
    if deviations > 0:
        print(f'  {deviations} deviation(s) from upstream — review it')


def _log_session_start(agent_dir: Path, context_file: Path) -> None:
    """Log session start to the sessions log file."""
    log_file = agent_dir / 'sessions.log'
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    with open(log_file, 'a', encoding='utf-8') as log:
        log.write(f"[{timestamp}] SESSION START context={context_file}\n")


def _log_session_end(agent_dir: Path, result: SessionResult) -> None:
    """Log session end to the sessions log file.

    Appends the backend's per-session cost (``credits=<amount> unit=<unit>``)
    when present, so :func:`sum_session_credits` can tally it across a CVE's
    retry attempts. The RESOLVED/UNRESOLVED status and measured ``duration``
    tokens are kept unchanged for backward compatibility with existing log
    readers.
    """
    log_file = agent_dir / 'sessions.log'
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    status = "RESOLVED" if result.resolved else "UNRESOLVED"
    line = (f"[{timestamp}] SESSION END {status} "
            f"duration={result.duration:.1f}s")
    if result.credits is not None:
        line += f" credits={result.credits:.2f} unit={result.credits_unit}"
    with open(log_file, 'a', encoding='utf-8') as log:
        log.write(line + "\n")


# Matches the ``credits=<amount> unit=<unit>`` tokens written by
# _log_session_end. ``unit`` runs to end-of-token (no spaces in a unit label).
_CREDITS_LOG_RE = re.compile(
    r"credits=(?P<amount>[0-9]+(?:\.[0-9]+)?)\s+unit=(?P<unit>\S+)")


def sum_session_credits(agent_dir: Path) -> tuple[Optional[float], Optional[str]]:
    """Sum per-session credits recorded in ``agent_dir/sessions.log``.

    Reads the ``credits=<amount> unit=<unit>`` tokens appended by
    :func:`_log_session_end` and returns their total plus the unit.

    Returns:
        ``(total, unit)`` when at least one session recorded a cost, else
        ``(None, None)``.
    """
    log_file = agent_dir / 'sessions.log'
    try:
        text = log_file.read_text(encoding='utf-8')
    except OSError:
        return None, None

    matches = list(_CREDITS_LOG_RE.finditer(text))
    if not matches:
        return None, None
    total = sum(float(m.group('amount')) for m in matches)
    return total, matches[0].group('unit')
