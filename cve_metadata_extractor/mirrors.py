# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
'''Git repository management: mirrors and data repo cloning.'''
import logging
import os
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


def extract_repo_url_from_patch(url):
    '''Extract repository URL from a patch URL'''
    from shared.url_parser import deduce_repo_url  # pylint: disable=import-outside-toplevel
    return deduce_repo_url(url)


def find_repo_urls_from_metadata(metadata):
    '''Find repository URLs from hash_details in metadata'''
    urls = set()
    for hash_detail in metadata.get('hash_details', []):
        url = hash_detail.get('url')
        if url:
            repo_url = extract_repo_url_from_patch(url)
            if repo_url:
                urls.add(repo_url)
    return list(urls)


def create_or_update_mirror(repo_url, component_name,
                            mirrors_dir='data/mirrors'):
    '''Create or update a bare git mirror repository'''
    os.makedirs(mirrors_dir, exist_ok=True)
    mirror_path = os.path.join(mirrors_dir, f"{component_name}.git")

    if os.path.isdir(mirror_path):
        print(f"  Updating mirror: {component_name}")
        try:
            subprocess.run(['git', 'remote', 'update'], cwd=mirror_path,
                          check=True, capture_output=True, timeout=300)
            return mirror_path
        except subprocess.CalledProcessError as e:
            print(f"  Failed to update mirror: {e}")
            return None
    else:
        print(f"  Creating mirror: {component_name}")
        try:
            subprocess.run(
                ['git', 'clone', '--mirror', '--', repo_url, mirror_path],
                check=True, capture_output=True, timeout=300)
            return mirror_path
        except subprocess.CalledProcessError as e:
            print(f"  Failed to create mirror: {e}")
            return None


def create_mirrors(results, args):
    '''Create or update git mirrors for repositories'''
    print(f"\nCreating/updating mirrors for {len(results)} CVEs...")
    all_repos = {}
    for metadata in results.values():
        if not metadata.get('hashes'):
            continue
        repo_urls = find_repo_urls_from_metadata(metadata)
        component_name = metadata.get('name', 'unknown')
        for repo_url in repo_urls:
            if component_name not in all_repos:
                all_repos[component_name] = repo_url

    print(f"Found {len(all_repos)} unique repositories to mirror")
    failed_repos = []
    for idx, (component, repo_url) in enumerate(all_repos.items(), 1):
        print(f"[{idx}/{len(all_repos)}] {component}: {repo_url}")
        result = create_or_update_mirror(
            repo_url, component, args.repo_dir)
        if result is None:
            failed_repos.append((component, repo_url))

    print(f"Mirrors created/updated in {args.repo_dir}")

    if failed_repos:
        print(f"\nFailed to mirror {len(failed_repos)} repositories:")
        for component, repo_url in failed_repos:
            print(f"  - {component}: {repo_url}")

    return failed_repos
