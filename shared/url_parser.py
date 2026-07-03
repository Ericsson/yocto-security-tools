# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""URL parsing utilities for extracting commit hashes and PR commits.

This module is the single source of truth for URL-to-hash/series parsing,
used by both cve_metadata_extractor (with caching) and cve_corrector/cve_agent
(direct CLI use).
"""
import re
from typing import Optional

HASH_RE = re.compile(r'[0-9a-fA-F]{7,40}')

IGNORED_URL_PATTERNS = [
    'marc.info', 'NEWS.html#', '/blob/', 'bugzilla', 'viewtopic',
    'bugreport', 'hg.mozilla.org', 'bounties', 'bugs.launchpad.net',
    'hackerone', 'lore.kernel.org', 'jvn.jp', 'forum', 'gist', 'lapis',
    'access', 'user-attachments', 'advisory', 'issues', 'reddit',
]

_PR_RE = re.compile(r'https://github\.com/([^/]+)/([^/]+)/pull/(\d+)')


def extract_commit_hash(url: str) -> Optional[str]:
    """Extract a commit hash from a URL.

    Skips URLs matching ignored patterns and pure-numeric matches.

    Args:
        url: URL string potentially containing a commit hash.

    Returns:
        Hash string if found, None otherwise.
    """
    if any(p in url for p in IGNORED_URL_PATTERNS):
        return None
    match = HASH_RE.search(url)
    if match:
        h = match.group(0)
        if h.isdigit():
            return None
        return h
    return None


def fetch_github_pr_commits(pr_url: str,
                            token: Optional[str] = None) -> list[str]:
    """Fetch commit SHAs from a GitHub pull request via the API.

    Args:
        pr_url: GitHub PR URL (e.g. https://github.com/owner/repo/pull/123).
        token: GitHub API token. If None, reads from GITHUB_TOKEN env var.

    Returns:
        Ordered list of commit SHA strings. Empty list on failure.
    """
    import os  # pylint: disable=import-outside-toplevel

    import requests  # pylint: disable=import-outside-toplevel

    clean_url = pr_url.split('#')[0]
    match = _PR_RE.match(clean_url)
    if not match:
        return []

    owner, repo, pr_number = match.groups()
    api_url = (f'https://api.github.com/repos/{owner}/{repo}'
               f'/pulls/{pr_number}/commits')

    if token is None:
        token = os.getenv('GITHUB_TOKEN')
    if not token:
        print("  WARNING: GITHUB_TOKEN not set, skipping PR series extraction")
        return []

    print(f"  Fetching PR commits from {clean_url}...")
    try:
        commits: list[str] = []
        page = 1
        while True:
            response = requests.get(
                api_url, headers={'Authorization': f'token {token}'},
                params={'per_page': 100, 'page': page}, timeout=30)
            response.raise_for_status()
            page_commits = response.json()
            if not page_commits:
                break
            commits.extend(c['sha'] for c in page_commits)
            if len(page_commits) < 100:
                break
            page += 1
        print(f"  Found {len(commits)} commits in PR")
        return commits
    except requests.RequestException as e:
        print(f"  Failed to fetch PR commits: {e}")
        return []


_GITLAB_ISSUE_RE = re.compile(
    r'https://(gitlab\.[^/]+)/(.+?)/-/issues/(\d+)')


def fetch_gitlab_issue_commits(issue_url: str) -> list[str]:
    """Fetch commit SHAs from merge requests linked to a GitLab issue.

    Uses the public GitLab API (unauthenticated). If GITLAB_TOKEN is set,
    it is sent for private project access.

    Args:
        issue_url: Full GitLab issue URL.

    Returns:
        Ordered list of commit SHA strings. Empty list on failure.
    """
    import os  # pylint: disable=import-outside-toplevel

    import requests  # pylint: disable=import-outside-toplevel

    match = _GITLAB_ISSUE_RE.match(issue_url.split('#')[0])
    if not match:
        return []

    host, project_path, issue_iid = match.groups()
    encoded_project = project_path.replace('/', '%2F')
    base = f'https://{host}/api/v4/projects/{encoded_project}'

    headers: dict[str, str] = {}
    token = os.getenv('GITLAB_TOKEN')
    if token:
        headers['PRIVATE-TOKEN'] = token

    print(f"  Fetching GitLab issue commits from {issue_url}...")
    try:
        resp = requests.get(
            f'{base}/issues/{issue_iid}/closed_by',
            headers=headers, timeout=10)
        resp.raise_for_status()
        mrs = resp.json()
    except requests.RequestException as e:
        print(f"  Failed to fetch GitLab issue MRs: {e}")
        return []

    commits: list[str] = []
    for mr in mrs:
        mr_iid = mr.get('iid')
        if not mr_iid:
            continue
        try:
            resp = requests.get(
                f'{base}/merge_requests/{mr_iid}/commits',
                headers=headers, timeout=10)
            resp.raise_for_status()
            for c in resp.json():
                sha = c.get('id', '')
                if sha and sha not in commits:
                    commits.append(sha)
        except requests.RequestException:
            pass

    print(f"  Found {len(commits)} commits from GitLab issue")
    return commits


# Patterns that indicate a URL is not a git repository.
_REPO_SKIP_PATTERNS = (
    "bugzilla", "viewtopic", "inbox.", "mail.python.org",
    "openwall.com", "cve.org", "nvd.nist.gov",
    "/archives/", "/advisories/", "/lists/", "seclists.org",
    "marc.info", "bugreport", "hackerone", "lore.kernel.org",
    "issues", "reddit",
)

# URL substrings that indicate a valid git hosting forge.
_GIT_INDICATORS = (
    "github.com", "gitlab.com", "gitlab.", "git.savannah",
    "sourceware.org/git", "git.kernel.org", "git.openssl.org",
    "git.gnome.org", "git.freedesktop.org", "codeberg.org",
    "bitbucket.org", ".git",
)


def deduce_repo_url(url: str) -> Optional[str]:
    """Deduce the git repository URL from a commit/patch URL.

    Handles GitHub, GitLab, gitweb, Savannah, Sourceware, ncurses
    special-case, and other common forge patterns.

    Args:
        url: A commit, patch, or pull request URL.

    Returns:
        Repository URL string, or None if not deducible.
    """
    if any(p in url for p in _REPO_SKIP_PATTERNS):
        return None

    # ncurses special-case
    if 'ncurses' in url and 'commit' in url:
        return 'https://github.com/ThomasDickey/ncurses-snapshots'

    from urllib.parse import urlparse  # pylint: disable=import-outside-toplevel
    parsed = urlparse(url)
    host = parsed.hostname or ''

    # Gitweb ?p=<repo>;a=commit style
    if '?p=' in url and ';a=' in url:
        repo_name = url.split('?p=')[1].split(';', maxsplit=1)[0]
        if host == 'sourceware.org' or host.endswith('.sourceware.org'):
            return f'https://sourceware.org/git/{repo_name}'
        if 'sourceware.org' in host:
            return None  # lookalike host
        if host == 'git.savannah.gnu.org' or host.endswith('.savannah.gnu.org'):
            return f'https://git.savannah.gnu.org/git/{repo_name}'
        if 'savannah.gnu.org' in host:
            return None  # lookalike host
        # Generic gitweb
        return f'{parsed.scheme}://{parsed.netloc}/{repo_name}'

    # Savannah /cgit/ or /git/ path style
    if host == 'git.savannah.gnu.org' or host.endswith('.savannah.gnu.org'):
        if '/cgit/' in parsed.path:
            repo_name = parsed.path.split('/cgit/')[1].split('/')[0]
        elif '/git/' in parsed.path:
            repo_name = parsed.path.split('/git/')[1].split('/')[0]
        else:
            return None
        return f'https://git.savannah.gnu.org/git/{repo_name}'
    if 'savannah.gnu.org' in host:
        return None  # lookalike host

    # Sourceware /cgit/ or /git/ path style
    # (e.g. https://sourceware.org/cgit/bzip2/commit/?id=... -> .../git/bzip2)
    if host == 'sourceware.org' or host.endswith('.sourceware.org'):
        if '/cgit/' in parsed.path:
            repo_name = parsed.path.split('/cgit/')[1].split('/')[0]
        elif '/git/' in parsed.path:
            repo_name = parsed.path.split('/git/')[1].split('/')[0]
        else:
            return None
        if not repo_name:
            return None
        return f'https://sourceware.org/git/{repo_name}'
    if 'sourceware.org' in host:
        return None  # lookalike host

    # Strip commit/PR/MR path suffixes to get base repo URL
    base_url = (url.replace("gitweb.cgi?p=", "")
                .split("-/commit")[0].split("-/merge_requests")[0]
                .split("-/issues")[0]
                .split("/pull/")[0].split("/commit")[0]
                .split("/releases")[0])

    if any(p in base_url for p in _REPO_SKIP_PATTERNS):
        return None
    if any(g in base_url for g in _GIT_INDICATORS):
        return base_url.rstrip('/')
    return None


def parse_fix_url(url: str) -> dict:
    """Parse a fix URL into hashes, hash_details, and series.

    Auto-detects commit URLs vs PR URLs.

    Args:
        url: GitHub commit URL or PR URL.

    Returns:
        Dict with keys: hashes, hash_details, series.

    Raises:
        ValueError: If no hash or PR commits could be extracted.
    """
    clean_url = url.split('#')[0]

    # PR URL
    if _PR_RE.match(clean_url):
        commits = fetch_github_pr_commits(url)
        if not commits:
            raise ValueError(
                f"Could not extract commits from PR: {url}")
        return {
            'hashes': commits,
            'hash_details': [{'hash': h, 'url': clean_url, 'source': 'cli'}
                             for h in commits],
            'series': [{'pull_url': clean_url, 'commits': commits}],
        }

    # Commit URL
    commit_hash = extract_commit_hash(url)
    if commit_hash:
        return {
            'hashes': [commit_hash],
            'hash_details': [{'hash': commit_hash, 'url': url,
                              'source': 'cli'}],
            'series': [],
        }

    raise ValueError(f"Could not extract commit hash from URL: {url}")
