# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
'''Check status of a CVE in upstream OpenEmbedded.

Queries OE git repositories and mailing lists to determine if a CVE
fix has been merged, submitted, or is under review.
'''

import argparse
import json
import logging
import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from shared import TEXT_ENCODING, TEXT_ERRORS

from .config import load_config as _load_cfg

# Group IDs for lists.openembedded.org
API_URL = "https://lists.openembedded.org/api/v1"

OE_CORE_ID = 67612
OPENEMBEDDED_DEVEL_ID = 67613
OPENEMBEDDED_SECURITY_DISCUSSIONS_ID = 142008

# Repository URLs to check for commits (overridable via config)
_OE_REPO_DEFAULTS = {
    'oe_core_url': "https://git.openembedded.org/openembedded-core",
    'oe_core_contrib_url': "https://git.openembedded.org/openembedded-core-contrib",
    'meta_openembedded_url': "https://git.openembedded.org/meta-openembedded",
    'meta_openembedded_contrib_url': "https://git.openembedded.org/meta-openembedded-contrib",
}


def _get_repo_url(key):
    """Get repo URL from config (lazy), falling back to default."""
    return _load_cfg().get(key, _OE_REPO_DEFAULTS[key])


def check_cve(token, group, cve, branch):
    '''Check if a CVE has been seen in the mailing list.'''
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{API_URL}/searcharchives?group_id={group}&q={cve}"

    resp = requests.get(url, headers=headers, timeout=30)
    try:
        result = resp.json()
    except (ValueError, KeyError):
        logging.debug("Failed to parse API response for %s", cve)
        return None
    if 'total_count' not in result:
        logging.debug("Unexpected API response for %s: %s",
                      cve, str(result)[:200])
        return None
    total = result['total_count']
    status = None
    if total == 0:
        return status
    for msg in result['data']:
        subject = msg["subject"] \
            .replace("<strong>", "") \
            .replace("</strong>", "")
        if any(p in subject for p in ("CVE report",
                                      "update CVE exclusions",
                                      "linux-yocto",
                                      "CVE metrics")):
            continue
        name = msg["name"]
        created = msg['created'].split("T", 1)[0]
        body = msg['body']
        if len(body) > 1000:
            body = body[0:1000]

        logging.log(5, subject)
        if branch in subject and (cve in subject or cve in body):
            logging.log(5, "%s: %s - %s -%s", cve, subject, name, created)
            status = f'submitted on {created} by {name}: {subject}'
            return status
        if branch in subject and "Patch review" in subject:
            return f"under review: {subject} - {created}"
    return status


def find_fetch_head(repo_path):
    """Return the path to FETCH_HEAD inside the repo."""
    git_dir = f"{repo_path}/.git"
    if not os.path.exists(git_dir):
        if os.path.exists(f"{repo_path}/config"):
            git_dir = repo_path
        else:
            return None
    return f"{git_dir}/FETCH_HEAD"


def get_mtime(head_file):
    """Return modification time of path as aware UTC datetime."""
    ts = Path(head_file).stat().st_mtime
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def do_get_repo(repo_dir, repo_url):
    '''Checkout or update a repository.'''
    name = repo_url.split("/")[-1]
    repo = f"{repo_dir}/{name}"
    if not repo_needs_update(repo):
        return repo
    if os.path.exists(repo):
        print(f"  Fetching {name}...", end='', flush=True)
        subprocess.run(
            ["git", "-C", repo, "fetch", "--all"],
            check=True, capture_output=True,
            encoding=TEXT_ENCODING, errors=TEXT_ERRORS, timeout=300)
        print(" done")
    else:
        print(f"  Cloning {name} (first run, may take a few minutes)...",
              end='', flush=True)
        subprocess.run(
            ["git", "clone", "--bare", "--", repo_url, repo],
            check=True, capture_output=True,
            encoding=TEXT_ENCODING, errors=TEXT_ERRORS, timeout=600)
        print(" done")
    return repo


def get_cve_in_branch(repo, branch, cve):
    '''Check git log in branch for CVE.'''
    status = None
    try:
        proc = subprocess.run(
            ["git", "-C", repo, "log", branch, "--grep", cve,
             '--pretty=format:"%cd %h %s by %an"', "--date=short"],
            check=True, capture_output=True,
            encoding=TEXT_ENCODING, errors=TEXT_ERRORS, timeout=100)
        if len(proc.stdout) > 0:
            logging.debug(proc.stdout)
            status = f"merged: {proc.stdout.strip()}"
    except subprocess.CalledProcessError as e:
        logging.debug("Git command failed: stdout: %s\nstderr:%s", e.stdout, e.stderr)
    except subprocess.TimeoutExpired as e:
        logging.debug(e)
    return status


def repo_needs_update(repo_dir):
    '''Returns True if it is time to fetch again.'''
    fetch_head = find_fetch_head(repo_dir)
    if not fetch_head:
        return True
    now = datetime.now(timezone.utc)
    threshold = timedelta(minutes=60)
    if not os.path.exists(fetch_head):
        return True
    last_fetch = get_mtime(fetch_head)
    age = now - last_fetch
    return age >= threshold


# NOTE: This cache is not thread-safe. The tool is single-threaded by design.
# If batch/parallel mode is added in the future, protect with threading.Lock.
_OE_STATUS_CACHE = {}
_OE_STATUS_CACHE_FILE = None
_OE_STATUS_TTL = 12 * 3600  # 12 hours


def _load_oe_cache(repo_dir):
    """Load OE status cache from disk."""
    global _OE_STATUS_CACHE, _OE_STATUS_CACHE_FILE
    _OE_STATUS_CACHE_FILE = Path(repo_dir) / 'oe-status-cache.json'
    if _OE_STATUS_CACHE_FILE.exists():
        try:
            with open(_OE_STATUS_CACHE_FILE, encoding='utf-8') as f:
                _OE_STATUS_CACHE = json.load(f)
        except (json.JSONDecodeError, OSError):
            _OE_STATUS_CACHE = {}


def _save_oe_cache():
    """Save OE status cache to disk."""
    if _OE_STATUS_CACHE_FILE:
        _OE_STATUS_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(_OE_STATUS_CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(_OE_STATUS_CACHE, f, indent=1)


def do_check_status(token, repo_dir, cve, branch):
    '''Check if a CVE is in a known branch or in the mailing list.

    Results are cached for 12 hours per CVE+branch combination.
    '''
    import time as _time

    # Initialize cache on first call
    if not _OE_STATUS_CACHE_FILE:
        _load_oe_cache(repo_dir)

    cache_key = f"{cve}:{branch}"
    cached = _OE_STATUS_CACHE.get(cache_key)
    if cached is not None:
        age = _time.time() - cached.get('_ts', 0)
        if age < _OE_STATUS_TTL:
            return cached['status']

    # Not cached or expired — do the actual check
    status = _do_check_status_uncached(token, repo_dir, cve, branch)

    # Cache the result
    _OE_STATUS_CACHE[cache_key] = {'status': status, '_ts': _time.time()}
    _save_oe_cache()
    return status


def _do_check_status_uncached(token, repo_dir, cve, branch):
    '''Actual upstream status check (uncached).'''
    branches = [
        (_get_repo_url('oe_core_url'), branch, None),
        (_get_repo_url('oe_core_contrib_url'), f"stable/{branch}-next", "in_next"),
        (_get_repo_url('oe_core_contrib_url'), f"stable/{branch}-next", "in_next"),
        (_get_repo_url('meta_openembedded_url'), branch, None),
        (_get_repo_url('meta_openembedded_url'), f"{branch}-next", "in_next"),
        (_get_repo_url('meta_openembedded_contrib_url'), f"stable/{branch}-next", "in_next"),
    ]

    for repo_url, br, status_hint in branches:
        logging.debug("Checking %s: %s", repo_url, br)
        repo = do_get_repo(repo_dir, repo_url)
        status = get_cve_in_branch(repo, br, cve)
        if status:
            return f"{status_hint}: {status}" if status_hint else status

    for mailing_list in (OE_CORE_ID, OPENEMBEDDED_DEVEL_ID):
        logging.debug("Checking %s", mailing_list)
        status = check_cve(token, mailing_list, cve, branch)
        if status:
            return status
    return "not_found"


def main():
    '''Tool to check status of a CVE in upstream OpenEmbedded.'''
    home = os.getenv('HOME')
    parser = argparse.ArgumentParser(
        description='Check status of a CVE in upstream OpenEmbedded')
    parser.add_argument("--cve", type=str, help="CVE to check", required=True)
    parser.add_argument("--branch", type=str, help="Branch to filter",
                        default="scarthgap")
    parser.add_argument("--token", type=str,
                        help="Token to access openembedded.org API",
                        default=None)
    parser.add_argument("--repo_dir", type=str,
                        help="Directory with git repositories",
                        default=f"{home}/git")
    parser.add_argument("-D", "--debug", help='Enable debug',
                        action="store_true")

    args = parser.parse_args()
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(format='[%(filename)s:%(lineno)d] %(message)s',
                        level=log_level)

    token = args.token or os.getenv('OPENEMBEDDED_TOKEN')
    if not token:
        print("Provide a token to connect to the API, "
              "as parameter or environment variable")
        return 1

    if not os.path.isdir(args.repo_dir):
        os.makedirs(args.repo_dir)
    status = do_check_status(token, args.repo_dir, args.cve, args.branch)
    print(status)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
