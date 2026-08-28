# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Approval gate and change review for CVE agent.

Displays upstream vs backported diffs, builds change summaries, and
handles human approval / rejection / edit flow.
"""
import subprocess
from pathlib import Path

from shared import TEXT_ENCODING, TEXT_ERRORS, build_git_env

from . import AgentConfig, get_agent_dir
from .git import (
    get_changed_files,
    merge_diff_flags,
    run_git_display,
    run_git_stdout,
    upstream_changed_files,
)
from .interdiff import generate_interdiff, generate_interdiff_artifacts


def request_approval(workspace_path: Path, upstream_sha: str,
                     config: AgentConfig) -> tuple[str, str]:
    """Show changes from upstream and request human approval.

    In trust mode, auto-approves and amends the commit message.

    Args:
        workspace_path: Path to the devtool workspace.
        upstream_sha: Upstream commit SHA being backported.
        config: Agent configuration.

    Returns:
        Tuple of (action, feedback) where action is one of
        "approved", "rejected", or "edit".
    """
    summary = build_change_summary(workspace_path, upstream_sha)

    if config.trust_mode:
        amend_commit_with_summary(workspace_path, upstream_sha, summary)
        return "approved", ""

    diff_path = _save_review_diff(workspace_path, upstream_sha)
    _display_changes(workspace_path, upstream_sha, summary, config.cve_id)
    print(f"\nFull diff saved to: {diff_path}")
    print("Review it with your editor before approving.")

    while True:
        response = input(
            f"\nApprove? [y]es / [n]o (fix manually) / "
            f"[e]dit (re-enter {config.backend}): "
        ).strip().lower()
        if response in ('y', 'yes'):
            amend_commit_with_summary(workspace_path, upstream_sha, summary)
            return "approved", ""
        if response in ('n', 'no'):
            print("\nTo fix manually:")
            print(f"  1. cd {workspace_path}")
            print("  2. Edit the files as needed")
            print("  3. git add <files> && git commit --amend --no-edit")
            print("  4. Re-run: cve-corrector --continue --yes")
            print("\nOr to resume with the agent:")
            print(f"  cve-agent --cve-id {config.cve_id}"
                  f" --cve-info {config.cve_info_path}")
            return "rejected", ""
        if response in ('e', 'edit'):
            feedback = input(f"What should the {config.backend} agent change? > ").strip()
            return "edit", feedback
        print("Invalid input. Enter y, n, or e.")


def build_change_summary(workspace_path: Path, upstream_sha: str) -> str:
    """Generate a human-readable summary of deviations from upstream.

    Args:
        workspace_path: Path to workspace.
        upstream_sha: Upstream commit SHA.

    Returns:
        Formatted change summary string.
    """
    upstream_set = upstream_changed_files(workspace_path, upstream_sha)
    applied_set = get_changed_files(
        ['diff', '--name-only', 'original-version..HEAD'], workspace_path
    )

    lines = [f"Changes from upstream commit {upstream_sha[:12]}:"]

    for filepath in sorted(upstream_set & applied_set):
        delta = run_git_stdout(
            ['diff', f'{upstream_sha}..HEAD', '--', filepath], workspace_path
        )
        if delta.strip():
            lines.append(f"  - {filepath}: adapted from upstream")

    for filepath in sorted(upstream_set - applied_set):
        lines.append(f"  - {filepath}: omitted from backport")

    if len(lines) == 1:
        if not applied_set:
            lines.append("  (empty cherry-pick — fix already present in tree)")
        else:
            lines.append("  (no deviations from upstream)")
    return '\n'.join(lines)


_AGENT_NOTE_MARKERS = (
    'Conflicts Resolved:',
    '## ', '### Conflicts Resolved',
)


def _dedupe_agent_notes(commit_msg: str) -> str:
    """Collapse repeated AI backport-note blocks into a single block.

    Across resolution retries (e.g. conflict fixed, then a later ptest/build
    failure triggers another AI session), the AI backend may append a
    fresh ``Conflicts Resolved:`` block on top of one already present from
    an earlier attempt instead of updating it in place. This strips all but
    the last such block, keeping the most recent (most complete) resolution
    notes.

    Args:
        commit_msg: Full commit message, possibly with duplicated note
            blocks.

    Returns:
        Commit message with only the final note block retained.
    """
    lines = commit_msg.splitlines()
    block_starts = [
        i for i, line in enumerate(lines)
        if line.strip().startswith(_AGENT_NOTE_MARKERS)
    ]
    if len(block_starts) <= 1:
        return commit_msg

    # Keep everything before the first block, then only the last block
    # onward — earlier blocks are superseded duplicates.
    kept = lines[:block_starts[0]] + lines[block_starts[-1]:]

    result = '\n'.join(kept)
    if commit_msg.endswith('\n') and not result.endswith('\n'):
        result += '\n'
    return result


def amend_commit_with_summary(workspace_path: Path, upstream_sha: str,
                              summary: str) -> None:
    """Amend the HEAD commit message to append the change summary.

    If the AI replaced the original upstream message with backport notes,
    restores the original message and appends the notes after it.

    Args:
        workspace_path: Path to workspace.
        upstream_sha: Upstream commit SHA.
        summary: Change summary to append.
    """
    current_msg = run_git_stdout(['log', '-1', '--format=%B'], workspace_path)

    if f"Changes from upstream commit {upstream_sha[:12]}" in current_msg:
        return

    current_msg = _dedupe_agent_notes(current_msg)
    lines = current_msg.rstrip().splitlines()

    has_agent_notes = any(
        line.strip().startswith(_AGENT_NOTE_MARKERS) for line in lines
    )

    # Check if original upstream message body was preserved.
    # If the first non-blank line after the subject is a note marker,
    # or the subject itself is a note, the AI replaced the body.
    original_subject = run_git_stdout(
        ['log', '-1', '--format=%s', upstream_sha], workspace_path
    ).strip()

    body_preserved = True
    if has_agent_notes and original_subject:
        # Case 1: subject itself is a marker (entire message replaced)
        if lines and lines[0].strip().startswith(_AGENT_NOTE_MARKERS):
            body_preserved = False
        else:
            # Case 2: subject kept but body starts with a note
            body_start = 1
            while body_start < len(lines) and not lines[body_start].strip():
                body_start += 1
            if body_start < len(lines) and lines[body_start].strip().startswith(
                _AGENT_NOTE_MARKERS
            ):
                body_preserved = False

    if has_agent_notes and not body_preserved and original_subject:
        # AI replaced the body — restore original and append notes
        original_body = run_git_stdout(
            ['log', '-1', '--format=%b', upstream_sha], workspace_path
        ).rstrip()

        # Extract notes from current message
        note_start = None
        for i, line in enumerate(lines):
            if line.strip().startswith(_AGENT_NOTE_MARKERS):
                note_start = i
                break
        agent_notes = '\n'.join(lines[note_start:]) if note_start is not None else ''

        # Reconstruct: original subject + body + notes + summary
        new_msg = original_subject + '\n'
        if original_body:
            new_msg += '\n' + original_body + '\n'
        if agent_notes:
            new_msg += '\n' + agent_notes + '\n'
        new_msg += '\n' + summary + '\n'
    elif has_agent_notes:
        # Original message preserved with notes — just append summary
        new_msg = '\n'.join(lines).strip() + f'\n\n{summary}\n'
    else:
        # No notes — strip trailing CVE block and append summary
        last_cve_idx = None
        for i in range(len(lines) - 1, -1, -1):
            if lines[i].startswith('CVE:'):
                last_cve_idx = i
                break
        if last_cve_idx is not None:
            end = last_cve_idx
            while end > 0 and not lines[end - 1].strip():
                end -= 1
            lines = lines[:end]
        new_msg = '\n'.join(lines).strip() + f'\n\n{summary}\n'

    result = subprocess.run(
        ['git', 'commit', '--no-edit', '--amend', '-m', new_msg],
        cwd=workspace_path, env=build_git_env(), check=False
    )
    if result.returncode != 0:
        import logging
        logging.getLogger(__name__).warning(
            "git commit --amend failed (rc=%d) — commit message not updated",
            result.returncode
        )


def _save_review_diff(workspace_path: Path, upstream_sha: str) -> Path:
    """Save a combined diff file for external review.

    When the ``interdiff`` binary is available, also persists the two
    patch files it was run against (upstream commit patch and the final
    backported patch) under ``cve_agent/<recipe>/interdiff-<sha>/``, and
    appends the exact ``interdiff`` command to the diff file so the
    delta can be reproduced standalone, outside this tool.

    Args:
        workspace_path: Path to workspace.
        upstream_sha: Upstream commit SHA.

    Returns:
        Path to the saved diff file.
    """
    agent_dir = get_agent_dir(workspace_path)
    diff_path = agent_dir / f"review-{upstream_sha[:12]}.diff"

    flags = merge_diff_flags(workspace_path, upstream_sha)
    upstream_diff = run_git_stdout(['show', *flags, upstream_sha], workspace_path)
    upstream_files = upstream_changed_files(workspace_path, upstream_sha)
    if upstream_files:
        backport_diff = run_git_stdout(
            ['diff', 'original-version..HEAD', '--'] + sorted(upstream_files),
            workspace_path
        )
    else:
        backport_diff = ''

    if not backport_diff.strip():
        diff_path.write_text(
            f"=== UPSTREAM COMMIT {upstream_sha} ===\n\n"
            f"{upstream_diff}\n\n"
            f"=== EMPTY CHERRY-PICK ===\n\n"
            f"Upstream fix already present in tree — no new changes.\n",
            encoding='utf-8',
        )
    else:
        content = (
            f"=== UPSTREAM COMMIT {upstream_sha} ===\n\n"
            f"{upstream_diff}\n\n"
            f"=== BACKPORTED DIFF (original-version..HEAD) ===\n\n"
            f"{backport_diff}\n"
        )
        interdiff_files_dir = agent_dir / f"interdiff-{upstream_sha[:12]}"
        artifacts = generate_interdiff_artifacts(
            upstream_diff, backport_diff, keep_files_dir=interdiff_files_dir
        )
        if artifacts:
            content += (
                f"\n=== INTERDIFF (upstream \u2192 backport) ===\n\n"
                f"{artifacts.output}\n"
                f"--- Reproduce outside this tool ---\n"
                f"Original upstream patch : {artifacts.old_patch_path}\n"
                f"Final backported patch  : {artifacts.new_patch_path}\n"
                f"Command                 : {artifacts.command}\n"
            )
        diff_path.write_text(content, encoding='utf-8')
    return diff_path


def _display_changes(workspace_path: Path, upstream_sha: str,
                     summary: str, cve_id: str) -> None:
    """Display upstream patch, applied changes, and delta for review.

    Args:
        workspace_path: Path to workspace.
        upstream_sha: Upstream commit SHA.
        summary: Pre-built change summary string.
    """
    print("\n" + "=" * 60)
    print("RESOLUTION REVIEW")
    print("=" * 60)

    flags = merge_diff_flags(workspace_path, upstream_sha)
    upstream_files = upstream_changed_files(workspace_path, upstream_sha)

    # Check if the upstream commit actually produced changes in the workspace
    if upstream_files:
        applied_diff = run_git_stdout(
            ['diff', 'original-version..HEAD', '--'] + sorted(upstream_files),
            workspace_path
        )
    else:
        applied_diff = ''

    if not applied_diff.strip():
        print(f"\nEmpty cherry-pick for {cve_id} — upstream fix already "
              f"present in tree.")
        print(f"Upstream commit: {upstream_sha[:12]}")
        if upstream_files:
            print(f"Files in upstream patch: {', '.join(sorted(upstream_files))}")
        print("\nNo new changes to review.")
    else:
        print("\n--- Original upstream patch ---")
        run_git_display(['show', *flags, '--stat', upstream_sha], workspace_path)

        print("\n--- What was applied ---")
        run_git_display(
            ['diff', '--stat', 'original-version..HEAD', '--'] + sorted(upstream_files),
            workspace_path
        )

        print("\n--- Changes from upstream ---")
        print(summary)

        upstream_diff = run_git_stdout(['show', *flags, upstream_sha], workspace_path)
        interdiff = generate_interdiff(upstream_diff, applied_diff)
        print("\n--- Interdiff (upstream \u2192 backport) ---")
        if interdiff:
            print(interdiff)
        else:
            print("(interdiff unavailable — install patchutils for a "
                  "concise adaptation diff)")

        print("\n--- Final commit ---")
        run_git_display(['log', '-1', '--format=%B', 'HEAD'], workspace_path)

    agent_dir = get_agent_dir(workspace_path)
    log_path = agent_dir / f'{workspace_path.name}-{cve_id}-ai-changes.log'
    if log_path.exists():
        print("\n--- AI Changes Audit Log ---")
        print(log_path.read_text(encoding=TEXT_ENCODING, errors=TEXT_ERRORS))

    print("=" * 60)
