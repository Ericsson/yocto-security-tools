# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""AI session management for CVE agent.

Spawns AI sessions with context files, wraps them with file-scope
enforcement (pre-commit hook + post-session revert).
"""
import difflib
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from . import get_agent_dir
from .backend import SessionResult, get_backend
from .git import (
    get_all_upstream_shas,
    get_changed_files,
    install_scope_hook,
    remove_scope_hook,
    revert_unauthorized_changes,
    run_git_stdout,
)


def check_resolution_state(workspace_path: Path) -> bool:
    """Check if the workspace has unresolved conflicts.

    Returns:
        True if no conflict markers remain, False otherwise.
    """
    if not workspace_path.exists():
        return True
    result = subprocess.run(
        ['git', 'status', '--porcelain'],
        cwd=workspace_path, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        return False
    for line in result.stdout.splitlines():
        if line and len(line) >= 2 and (line[0] == 'U' or line[1] == 'U'):
            return False
    return True


_COMMON_PREFIXES = ('src/', 'lib/', 'source/')


def _expand_path_variants(allowed: set[str], workspace_path: Path) -> set[str]:
    """Expand allowed paths to include variants with/without common prefixes.

    If upstream uses src/foo.c but workspace has foo.c (or vice versa),
    include both so the scope guard doesn't reject the agent's work.
    Also handles monorepo subprojects/ prefixes (e.g. gstreamer).
    """
    expanded = set(allowed)
    for filepath in list(allowed):
        # Handle subprojects/<name>/ prefix (monorepo pattern)
        parts = filepath.split('/')
        if len(parts) > 2 and parts[0] == 'subprojects':
            # Strip subprojects/<name>/ prefix
            stripped = '/'.join(parts[2:])
            if (workspace_path / stripped).exists():
                expanded.add(stripped)
        else:
            # Try adding subprojects/<name>/ prefix by finding matching dirs
            # Don't scan workspace_path.parent — too expensive
            pass

        for prefix in _COMMON_PREFIXES:
            if filepath.startswith(prefix):
                stripped = filepath[len(prefix):]
                if (workspace_path / stripped).exists():
                    expanded.add(stripped)
            else:
                prefixed = prefix + filepath
                if (workspace_path / prefixed).exists():
                    expanded.add(prefixed)
    return expanded


def guarded_session(context_file: Path, workspace_path: Path,
                    upstream_sha: str, cve_info: dict,
                    model: str = "claude-sonnet-4.6",
                    timeout: int = 300,
                    cve_id: str = "",
                    interactive: bool = False,
                    backend_name: str = "kiro") -> SessionResult:
    """Run AI session with file-scope enforcement.

    Installs a git pre-commit hook that blocks unauthorized files, runs the
    AI session via the configured backend, then verifies and reverts any
    unauthorized changes.
    """
    all_shas = get_all_upstream_shas(cve_info, workspace_path)
    allowed: set[str] = set()
    # Snapshot upstream diffs per file before the session (single pass per SHA)
    upstream_diffs: dict[str, str] = {}
    for sha in all_shas:
        files = get_changed_files(['show', '--name-only', '--format=', sha], workspace_path)
        allowed |= files
        for f in files:
            raw = run_git_stdout(['show', sha, '--', f], cwd=workspace_path)
            upstream_diffs[f] = _extract_diff_hunks(raw)

    # Fallback: if SHAs don't exist in repo, derive from workspace diff
    if not allowed:
        diff_output = run_git_stdout(
            ['diff', '--name-only', 'original-version..HEAD'], cwd=workspace_path
        )
        allowed.update(f for f in diff_output.splitlines() if f)
        conflict_output = run_git_stdout(
            ['diff', '--name-only', '--diff-filter=U'], cwd=workspace_path
        )
        allowed.update(f for f in conflict_output.splitlines() if f)

    recipe = workspace_path.name

    # Path-normalize: add variants without/with common prefixes (src/, lib/)
    # to handle cases where upstream SHA paths differ from workspace layout
    allowed = _expand_path_variants(allowed, workspace_path)

    install_scope_hook(workspace_path, allowed)
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
        f"steps for a CVE backport. Complete all tasks described in the file."
    )

    backend = get_backend(backend_name)
    agent_dir = get_agent_dir(workspace_path)
    _log_session_start(agent_dir, context_file)

    try:
        result = backend.run_session(
            prompt, workspace_path, allowed, model, timeout, interactive)
    finally:
        remove_scope_hook(workspace_path)

    _log_session_end(agent_dir, result.resolved, result.duration)

    if not workspace_path.exists():
        return result

    revert_unauthorized_changes(workspace_path, allowed)
    _write_audit_log(workspace_path, recipe, cve_id, all_shas, upstream_diffs,
                     pre_session_head)
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
    """Extract the first backport-related line from the HEAD commit message."""
    commit_msg = run_git_stdout(['log', '-1', '--format=%B'], cwd=workspace_path)
    for line in commit_msg.splitlines():
        if ('Backport-Resolution' in line
                or 'Backport Resolution' in line
                or 'Conflicts Resolved' in line
                or 'backport' in line.lower()):
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


def _log_session_end(agent_dir: Path, resolved: bool, duration: float) -> None:
    """Log session end to the sessions log file."""
    log_file = agent_dir / 'sessions.log'
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    status = "RESOLVED" if resolved else "UNRESOLVED"
    with open(log_file, 'a', encoding='utf-8') as log:
        log.write(f"[{timestamp}] SESSION END {status} duration={duration:.1f}s\n")
