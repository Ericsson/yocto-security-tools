# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Approval gate and change review for CVE agent.

Displays upstream vs backported diffs, builds change summaries, and
handles human approval / rejection / edit flow.
"""
import subprocess
from pathlib import Path

from shared import build_git_env

from . import AgentConfig, get_agent_dir
from .git import get_changed_files, run_git_display, run_git_stdout


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
            "\nApprove? [y]es / [n]o (fix manually) / [e]dit (re-enter kiro-cli): "
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
            feedback = input("What should kiro change? > ").strip()
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
    upstream_set = get_changed_files(
        ['diff-tree', '--no-commit-id', '--name-only', '-r', upstream_sha],
        workspace_path
    )
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


def amend_commit_with_summary(workspace_path: Path, upstream_sha: str,
                              summary: str) -> None:
    """Amend the HEAD commit message to append the change summary.

    Skips if kiro already wrote detailed backport notes.

    Args:
        workspace_path: Path to workspace.
        upstream_sha: Upstream commit SHA.
        summary: Change summary to append.
    """
    current_msg = run_git_stdout(['log', '-1', '--format=%B'], workspace_path)

    if f"Changes from upstream commit {upstream_sha[:12]}" in current_msg:
        return

    # Strip trailing CVE/Upstream-Status block added by cve_corrector,
    # but only if kiro has not written Backport-Resolution notes after it.
    lines = current_msg.rstrip().splitlines()

    has_kiro_notes = any(
        line.strip().startswith((
            'Backport-Resolution:', 'Backport changes:',
            'Conflict resolution notes:',
            '## ', '### Conflicts Resolved',
        ))
        for line in lines
    )

    if not has_kiro_notes:
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

    if has_kiro_notes:
        # kiro already wrote detailed notes — amend to normalize whitespace
        # but do not append the auto-generated summary.
        new_msg = '\n'.join(lines).strip() + '\n'
    else:
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

    Args:
        workspace_path: Path to workspace.
        upstream_sha: Upstream commit SHA.

    Returns:
        Path to the saved diff file.
    """
    agent_dir = get_agent_dir(workspace_path)
    diff_path = agent_dir / f"review-{upstream_sha[:12]}.diff"

    upstream_diff = run_git_stdout(['show', upstream_sha], workspace_path)
    upstream_files = get_changed_files(
        ['show', '--name-only', '--format=', upstream_sha], workspace_path
    )
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
        diff_path.write_text(
            f"=== UPSTREAM COMMIT {upstream_sha} ===\n\n"
            f"{upstream_diff}\n\n"
            f"=== BACKPORTED DIFF (original-version..HEAD) ===\n\n"
            f"{backport_diff}\n",
            encoding='utf-8',
        )
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

    upstream_files = get_changed_files(
        ['show', '--name-only', '--format=', upstream_sha], workspace_path
    )

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
        run_git_display(['show', '--stat', upstream_sha], workspace_path)

        print("\n--- What was applied ---")
        run_git_display(
            ['diff', '--stat', 'original-version..HEAD', '--'] + sorted(upstream_files),
            workspace_path
        )

        print("\n--- Changes from upstream ---")
        print(summary)

        print("\n--- Final commit ---")
        run_git_display(['log', '-1', '--format=%B', 'HEAD'], workspace_path)

    agent_dir = get_agent_dir(workspace_path)
    log_path = agent_dir / f'{workspace_path.name}-{cve_id}-ai-changes.log'
    if log_path.exists():
        print("\n--- AI Changes Audit Log ---")
        print(log_path.read_text(encoding='utf-8'))

    print("=" * 60)
