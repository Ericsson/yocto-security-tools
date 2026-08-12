# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
'''Git repository management: data repo cloning.'''
import logging
import subprocess
import time
from pathlib import Path


def ensure_data_repo(repo_dir, clone_url, name, branch=None):
    '''Clone a git repository if missing, or pull latest if it exists.

    Skips pull if last updated less than 24 hours ago.

    Args:
        repo_dir: Directory where the repo should live (supports ~).
        clone_url: Git clone URL for the repository.
        name: Human-readable name for log messages.
        branch: Branch to clone/checkout (default: repo default branch).

    Returns:
        Expanded Path to the repository directory, or None on failure.
    '''
    repo_path = Path(repo_dir).expanduser()

    if repo_path.is_dir():
        marker = repo_path / '.last_pull'
        if marker.exists():
            age = time.time() - marker.stat().st_mtime
            if age < 86400:
                return repo_path
        print(f"Updating {name} in {repo_path}...")
        try:
            fetch_cmd = ['git', 'fetch', '--depth', '1', 'origin']
            if branch:
                fetch_cmd.append(branch)
            subprocess.run(
                fetch_cmd,
                cwd=repo_path, check=True,
                capture_output=True, timeout=300)
            reset_target = f'origin/{branch}' if branch else 'origin/HEAD'
            subprocess.run(
                ['git', 'reset', '--hard', reset_target],
                cwd=repo_path, check=True,
                capture_output=True, timeout=60)
            marker.touch()
        except subprocess.CalledProcessError as e:
            logging.warning("git fetch failed for %s: %s (using stale data)",
                            name, e.stderr.decode().strip() if e.stderr else "")
        except subprocess.TimeoutExpired:
            logging.warning("git fetch timed out for %s (using stale data)", name)
        return repo_path

    print(f"Cloning {name} into {repo_path}...")
    repo_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = ['git', 'clone', '--depth', '1']
    if branch:
        cmd += ['-b', branch]
    cmd += ['--', clone_url, str(repo_path)]
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=1800)
        return repo_path
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        logging.error("Failed to clone %s: %s", name, e)
        return None
