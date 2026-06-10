# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Git helpers, upstream SHA resolution, and file-scope enforcement.

Provides git command wrappers, upstream SHA lookup from CVE metadata /
cve_corrector state, and the three-layer scope guard (pre-commit hook,
post-session revert of unauthorized changes).
"""
import json
import subprocess
from pathlib import Path
from typing import Optional

from shared import build_git_env
from shared.git_runner import (
    run_git_display,  # noqa: F401
    run_git_stdout,  # noqa: F401
)

from . import get_build_dir


def get_upstream_sha(cve_info: dict, workspace_path: Path) -> str:
    """Get the primary upstream SHA from CVE info or workspace state.

    For display/logging purposes. Use get_all_upstream_shas() for
    computing the full set of allowed files.

    Args:
        cve_info: CVE metadata dict.
        workspace_path: Path to workspace.

    Returns:
        Upstream SHA string, or "unknown" if not found.
    """
    state = _load_corrector_state(workspace_path)
    if state:
        return state.get('commit_hash', 'unknown')

    hashes = cve_info.get('hashes', [])
    return hashes[0] if hashes else "unknown"


def get_all_upstream_shas(cve_info: dict, workspace_path: Path) -> list[str]:
    """Get all upstream SHAs whose files are in scope for this CVE fix.

    For a PR series, returns all commits in the series. For single
    commits, returns the one that was applied.

    Args:
        cve_info: CVE metadata dict.
        workspace_path: Path to workspace.

    Returns:
        List of SHA strings. May be empty if nothing found.
    """
    state = _load_corrector_state(workspace_path)

    if state and state.get('series_state'):
        commits = state['series_state'].get('commits', [])
        if commits:
            return commits

    if state and state.get('commit_hash'):
        return [state['commit_hash']]

    hashes = cve_info.get('hashes', [])
    return [hashes[0]] if hashes else []


def get_changed_files(git_args: list[str], cwd: Path) -> set[str]:
    """Run a git command and return the output lines as a set.

    Args:
        git_args: Git arguments to run.
        cwd: Working directory.

    Returns:
        Set of non-empty output lines.
    """
    output = run_git_stdout(git_args, cwd)
    return set(line for line in output.splitlines() if line)


# --- File-scope enforcement ---

def install_scope_hook(workspace_path: Path, allowed: set[str]) -> None:
    """Install a git pre-commit hook that rejects unauthorized files.

    Backs up any existing hook and writes a script that checks staged files
    against the allowed set.

    Args:
        workspace_path: Path to workspace.
        allowed: Set of file paths allowed to be committed.
    """
    hooks_dir = workspace_path / '.git' / 'hooks'
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / 'pre-commit'
    backup_path = hooks_dir / 'pre-commit.bak'

    if hook_path.exists():
        hook_path.rename(backup_path)

    # Write allowed files to a separate data file (avoids heredoc injection
    # and handles filenames with special characters safely).
    allowed_file = hooks_dir / 'cve-agent-allowed-files'
    allowed_file.write_text('\n'.join(sorted(allowed)), encoding='utf-8')

    hook_path.write_text(
        '#!/bin/bash\n'
        '# CVE Agent scope guard — auto-installed, auto-removed\n'
        f'ALLOWED_FILE="{allowed_file}"\n'
        'while IFS= read -r f; do\n'
        '  if ! grep -qxF "$f" "$ALLOWED_FILE"; then\n'
        '    echo "BLOCKED by CVE agent: $f is not in the upstream commit" >&2\n'
        '    echo "Unstage it with: git reset HEAD -- $f" >&2\n'
        '    exit 1\n'
        '  fi\n'
        'done < <(git diff --cached --name-only)\n',
        encoding='utf-8',
    )
    hook_path.chmod(0o755)


def remove_scope_hook(workspace_path: Path) -> None:
    """Remove the scope guard pre-commit hook, restoring any backup.

    Args:
        workspace_path: Path to workspace.
    """
    hooks_dir = workspace_path / '.git' / 'hooks'
    hook_path = hooks_dir / 'pre-commit'
    backup_path = hooks_dir / 'pre-commit.bak'

    if hook_path.exists():
        hook_path.unlink()
    allowed_file = hooks_dir / 'cve-agent-allowed-files'
    if allowed_file.exists():
        allowed_file.unlink()
    if backup_path.exists():
        backup_path.rename(hook_path)


def revert_unauthorized_changes(workspace_path: Path,
                                allowed: set[str]) -> None:
    """Revert committed changes to unauthorized files.

    Working-tree changes are left alone (they are ephemeral and get
    cleaned by git_clean_workspace before devtool transfer).  Only
    committed unauthorized files are removed from the commit.

    Args:
        workspace_path: Path to workspace.
        allowed: Set of file paths allowed by the upstream commit.
    """

    # Revert unauthorized committed changes.
    # Use soft reset to squash all commits since original-version, then
    # selectively re-commit only allowed files. This handles multiple
    # commits and --no-verify bypasses.
    # Guard: if agent switched to devtool branch, force back to CVE branch
    # before checking committed changes.
    current_branch = run_git_stdout(['rev-parse', '--abbrev-ref', 'HEAD'], workspace_path).strip()
    if current_branch == 'devtool':
        # Find the CVE branch (any branch that isn't devtool/main/master)
        branches = run_git_stdout(['branch', '--list'], workspace_path).splitlines()
        cve_branch = None
        for b in branches:
            name = b.strip().lstrip('* ')
            if name and name not in ('devtool', 'main', 'master', 'devtool-base'):
                cve_branch = name
                break
        if cve_branch:
            print(f"\n⚠ Agent switched to devtool branch — forcing back to {cve_branch}")
            subprocess.run(
                ['git', 'checkout', cve_branch],
                cwd=workspace_path, env=build_git_env(), check=False
            )
        else:
            return
    committed = set(run_git_stdout(
        ['diff', '--name-only', 'original-version..HEAD'], workspace_path
    ).splitlines())
    commit_unauthorized = committed - allowed

    if not commit_unauthorized:
        return

    print(f"\n⚠ Removing {len(commit_unauthorized)} unauthorized file(s) from commit:")
    for filepath in sorted(commit_unauthorized):
        print(f"  - {filepath}")

    # Preserve commit message, then soft-reset to original-version
    msg = run_git_stdout(['log', '-1', '--format=%B'], workspace_path)
    saved_head_result = subprocess.run(
        ['git', 'rev-parse', 'HEAD'],
        cwd=workspace_path, env=build_git_env(), capture_output=True, text=True, check=False
    )
    saved_head = saved_head_result.stdout.strip() if saved_head_result.returncode == 0 else None
    result = subprocess.run(
        ['git', 'reset', '--soft', 'original-version'],
        cwd=workspace_path, env=build_git_env(), check=False
    )
    if result.returncode != 0:
        print("⚠ Failed to reset to original-version — leaving branch unchanged")
        return

    # Unstage unauthorized files and restore/remove them
    for filepath in commit_unauthorized:
        subprocess.run(
            ['git', 'reset', 'HEAD', '--', filepath],
            cwd=workspace_path, env=build_git_env(), capture_output=True, check=False
        )
        exists_at_base = subprocess.run(
            ['git', 'cat-file', '-e', f'original-version:{filepath}'],
            cwd=workspace_path, env=build_git_env(), capture_output=True, check=False
        ).returncode == 0
        if exists_at_base:
            subprocess.run(
                ['git', 'checkout', 'original-version', '--', filepath],
                cwd=workspace_path, env=build_git_env(), check=False
            )
        else:
            full_path = workspace_path / filepath
            if full_path.exists():
                full_path.unlink()

    # Re-commit with only allowed changes
    commit_result = subprocess.run(
        ['git', 'commit', '-m', msg],
        cwd=workspace_path, env=build_git_env(), check=False
    )
    if commit_result.returncode != 0:
        print(f"⚠ Re-commit failed — restoring branch to {(saved_head or 'HEAD')[:12]}")
        if saved_head:
            subprocess.run(
                ['git', 'reset', '--soft', saved_head],
                cwd=workspace_path, env=build_git_env(), check=False
            )


# --- Internal helpers ---

def _load_corrector_state(workspace_path: Path) -> Optional[dict]:
    """Load the cve_corrector state file for this workspace.

    Args:
        workspace_path: Path to workspace.

    Returns:
        State dict, or None if not found.
    """
    recipe = workspace_path.name
    build_dir = get_build_dir(workspace_path)
    state_file = build_dir / 'workspace' / 'cve_corrector' / f'{recipe}.json'
    if state_file.exists():
        try:
            return json.loads(state_file.read_text(encoding='utf-8'))
        except (json.JSONDecodeError, OSError):
            pass
    return None
