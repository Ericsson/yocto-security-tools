# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""URL parsing utilities for extracting commit hashes and PR commits.

This module is the single source of truth for URL-to-hash/series parsing,
used by both cve_metadata_extractor (with caching) and cve_corrector/cve_agent
(direct CLI use).
"""
import re
from typing import Optional
from urllib.parse import parse_qsl, urlparse

# Unanchored on purpose: consumers such as cve_metadata_extractor.debian use
# HASH_RE.findall() to pull hashes out of free-text notes. Checks that need a
# whole-string match use HASH_RE.fullmatch().
HASH_RE = re.compile(r'[0-9a-fA-F]{7,40}')
_HASH_TOKEN_RE = r'([0-9a-fA-F]{7,40})(?![0-9a-fA-F])'
# URL path shapes that identify a commit object.
_COMMIT_PATH_RES = (
    # GitHub/GitLab/cgit/gitweb: /commit/<hash>, /-/commit/<hash>,
    # /commits/<hash> (commit within a PR), /commitdiff/<hash>
    re.compile(rf'/(?:-/)?commit(?:s|diff)?/+{_HASH_TOKEN_RE}(?:[/.]|$)'),
    # Fossil: /info/<hash>
    re.compile(rf'/info/+{_HASH_TOKEN_RE}(?:[/.]|$)'),
    # kernel.org /stable/c/<hash> shortlinks and Pagure /c/<hash>. Anchored at
    # the end of the path: a bare /c/ segment is too common in unrelated URLs
    # (file-sharing links embed a hex account id as /c/<id>/<file>).
    re.compile(rf'/c/+{_HASH_TOKEN_RE}/?$'),
    # SourceForge: /ci/<hash>
    re.compile(rf'/ci/+{_HASH_TOKEN_RE}(?:[/.]|$)'),
    # Gitiles (*.googlesource.com): /<repo>/+/<hash>
    re.compile(rf'/\+/+{_HASH_TOKEN_RE}(?:[/.]|$)'),
    # 9front: /<hash>/commit.html
    re.compile(rf'/{_HASH_TOKEN_RE}/commit\.html$'),
    # Patch artifacts named after the commit: /<hash>.patch, /<hash>.diff
    re.compile(rf'/{_HASH_TOKEN_RE}\.(?:patch|diff)$'),
)

# Hosts that serve a bare /<hash> path as a commit redirect.
_BARE_HASH_HOSTS = frozenset({'kernel.dance'})

# Path segments that, combined with an id=/h= query parameter, denote a
# commit view. cgit exposes the same commit as /commit/, /patch/ and /diff/.
_COMMIT_VIEW_SEGMENTS = frozenset({'commit', 'commitdiff', 'patch', 'diff'})

IGNORED_URL_PATTERNS = [
    'marc.info', 'NEWS.html#', '/blob/', 'bugzilla', 'viewtopic',
    'bugreport', 'hg.mozilla.org', 'bounties', 'bugs.launchpad.net',
    'hackerone', 'lore.kernel.org', 'jvn.jp', 'forum', 'gist', 'lapis',
    'access', 'user-attachments', 'advisory', 'issues', 'reddit',
]

_PR_RE = re.compile(r'https://github\.com/([^/]+)/([^/]+)/pull/(\d+)')


def extract_commit_hash(url: str) -> Optional[str]:
    """Extract a commit hash from a URL.

    Only extracts from URL structures that identify a commit:
    ``/commit/<hash>`` and ``/-/commit/<hash>`` (GitHub, GitLab),
    ``/commits/<hash>`` (commit within a pull request), ``/commitdiff/``,
    cgit ``/commit|patch|diff/?id=<hash>``, gitweb
    ``?p=<repo>;a=commit;h=<hash>``, kernel.org ``/stable/c/<hash>``
    shortlinks, Pagure ``/c/<hash>``, SourceForge ``/ci/<hash>``,
    Gitiles ``/+/<hash>``, Fossil ``/info/<hash>``, 9front
    ``/<hash>/commit.html``, and patch artifacts named ``/<hash>.patch``.

    This avoids treating arbitrary hexadecimal-looking document IDs,
    advisory UUIDs, message IDs or Gerrit change IDs as Git commits.
    Ranges (``/compare/<a>..<b>``), blob and tree views, and non-Git
    revisions (Mercurial ``/rev/<id>``) are deliberately not extracted:
    they do not name a single Git commit the corrector could cherry-pick.

    Args:
        url: URL string potentially containing a commit hash.

    Returns:
        Hash string if found, None otherwise.
    """
    if any(p in url for p in IGNORED_URL_PATTERNS):
        return None

    parsed = urlparse(url)
    for path_re in _COMMIT_PATH_RES:
        path_match = path_re.search(parsed.path)
        if path_match:
            return _non_numeric_hash(path_match.group(1))

    bare_path = parsed.path.strip('/')
    if ((parsed.hostname or '').lower() in _BARE_HASH_HOSTS
            and HASH_RE.fullmatch(bare_path)):
        return _non_numeric_hash(bare_path)

    # Gitweb commonly separates query parameters with semicolons rather than
    # ampersands, and some references percent-encode them; normalise every
    # form before parsing.
    raw_query = re.sub('%3B', ';', parsed.query, flags=re.IGNORECASE)
    query = dict(parse_qsl(raw_query.replace(';', '&'),
                           keep_blank_values=True))
    path_parts = {part for part in parsed.path.split('/') if part}
    action = query.get('a')
    is_commit_view = (
        bool(path_parts & _COMMIT_VIEW_SEGMENTS)
        or action in {'commit', 'commitdiff'}
        # Old-style gitweb links omit the action: ?p=<repo>;h=<hash>. An
        # explicit non-commit action (a=blob, a=tree) means h= is a blob or
        # tree object, not a commit, so it must not be accepted here.
        or ('p' in query and action is None)
    )
    if is_commit_view:
        for key in ('id', 'h', 'hash', 'commit'):
            candidate = query.get(key, '')
            if HASH_RE.fullmatch(candidate):
                return _non_numeric_hash(candidate)
    return None


def _non_numeric_hash(candidate: str) -> Optional[str]:
    """Return a hexadecimal hash candidate unless it is purely numeric."""
    return None if candidate.isdigit() else candidate


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


def _savannah_domain(host: str) -> Optional[str]:
    """Return ``'gnu.org'``/``'nongnu.org'`` if host is a genuine Savannah
    host on that domain, or None otherwise (including for lookalike hosts
    such as ``savannah.gnu.org.evil.com``).

    Any subdomain depth is accepted (``git.``, ``cgit.git.``,
    ``https.git.``, ...) since Savannah fronts the same repositories under
    several hostnames.
    """
    for domain in ('savannah.gnu.org', 'savannah.nongnu.org'):
        if host == domain or host.endswith(f'.{domain}'):
            return domain.removeprefix('savannah.')
    return None


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

    # Gitweb ?p=<repo> style (e.g. ?p=binutils-gdb.git;a=commit;h=... or
    # ?p=binutils-gdb.git;h=...)
    if '?p=' in url:
        repo_name = url.split('?p=')[1].split(';', maxsplit=1)[0]
        if host == 'sourceware.org' or host.endswith('.sourceware.org'):
            return f'https://sourceware.org/git/{repo_name}'
        if 'sourceware.org' in host:
            return None  # lookalike host
        savannah_domain = _savannah_domain(host)
        if savannah_domain:
            return f'https://https.git.savannah.{savannah_domain}/git/{repo_name}'
        if 'savannah.' in host:
            return None  # lookalike host
        # Generic gitweb
        return f'{parsed.scheme}://{parsed.netloc}/{repo_name}'

    # Savannah /cgit/ or /git/ path style, on either the gnu.org or
    # nongnu.org Savannah instance (e.g. cgit.git.savannah.nongnu.org).
    # Savannah's plain https://git. host 302-redirects every request to
    # https://https.git. (its actual TLS-terminating vhost); some git/proxy
    # configs don't follow that redirect, so build the URL against
    # https.git. directly.
    savannah_domain = _savannah_domain(host)
    if savannah_domain:
        if '/cgit/' in parsed.path:
            repo_name = parsed.path.split('/cgit/')[1].split('/')[0]
        elif '/git/' in parsed.path:
            repo_name = parsed.path.split('/git/')[1].split('/')[0]
        else:
            return None
        return f'https://https.git.savannah.{savannah_domain}/git/{repo_name}'
    if 'savannah.' in host:
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

    # BusyBox's canonical cgit uses /<repo>/commit/?id=<sha>, while the Git
    # endpoint is the same URL with the commit-view suffix removed.
    if host == 'git.busybox.net':
        parts = [part for part in parsed.path.split('/') if part]
        if len(parts) >= 2 and parts[1] in _COMMIT_VIEW_SEGMENTS:
            return f'{parsed.scheme}://{parsed.netloc}/{parts[0]}'
        return None

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


def parse_fix_urls(urls: list[str]) -> dict:
    """Parse one or more fix URLs into hashes, hash_details, and series.

    Auto-detects commit URLs vs PR URLs. URLs are processed in the order
    given and that order is preserved throughout the result: the caller
    owns ordering, nothing is sorted here.

    A single URL yields the historical single-fix shape (a commit URL
    produces no ``series``; a PR URL produces its PR series). Two or more
    URLs yield exactly one ``series`` entry holding every commit in caller
    order — an ordered *dependent chain* meant to be applied as a whole,
    with any PR commits expanded inline. Duplicate commits collapse to
    their first occurrence.

    This function is a pure parser: whether a chain *must* apply in full is
    a caller policy (see ``WorkflowConfig.require_all_commits``), not
    something encoded in the returned metadata.

    Args:
        urls: Commit and/or pull request URLs, in application order.

    Returns:
        Dict with keys: hashes, hash_details, series.

    Raises:
        ValueError: If ``urls`` is empty, or if any single URL yields no
            commits (the offending URL is named in the message).
    """
    if not urls:
        raise ValueError("No fix URLs provided")

    commits: list[str] = []
    origin_url: dict[str, str] = {}
    pr_urls: list[str] = []

    def _record(commit_hash: str, url: str) -> None:
        """Append a commit, keeping the first occurrence's originating URL."""
        if commit_hash not in origin_url:
            origin_url[commit_hash] = url
            commits.append(commit_hash)

    for url in urls:
        clean_url = url.split('#')[0]

        # PR URL — expand to its commits, inline and in PR order.
        if _PR_RE.match(clean_url):
            pr_commits = fetch_github_pr_commits(url)
            if not pr_commits:
                raise ValueError(f"Could not extract commits from PR: {url}")
            pr_urls.append(clean_url)
            for commit_hash in pr_commits:
                _record(commit_hash, clean_url)
            continue

        # Commit URL
        single_hash = extract_commit_hash(url)
        if not single_hash:
            raise ValueError(f"Could not extract commit hash from URL: {url}")
        _record(single_hash, url)

    # One series entry when the commits form an ordered chain: either the
    # caller passed several URLs, or a PR already defines a chain.
    series = ([{'pull_url': pr_urls[0] if pr_urls else '', 'commits': commits}]
              if len(urls) > 1 or pr_urls else [])

    return {
        'hashes': commits,
        'hash_details': [{'hash': h, 'url': origin_url[h], 'source': 'cli'}
                         for h in commits],
        'series': series,
    }
