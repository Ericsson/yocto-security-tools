# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
'''Utility functions and constants for CVE metadata extraction.'''
import re

from shared.url_parser import (  # noqa: F401
    _GITLAB_ISSUE_RE,
    HASH_RE,
    extract_commit_hash,
    fetch_github_pr_commits,
    fetch_gitlab_issue_commits,
)

from .config import load_config

URL_RE = re.compile(r'https?://[^\s)]+')


# Global PR cache
PR_CACHE = {}
_cfg = load_config()
PR_CACHE_FILE = _cfg['pr_cache_file']


def normalize_component_name(name):
    '''Normalize component name: remove -native suffix and force lowercase.'''
    if name and name.endswith('-native'):
        name = name[:-7]
    return name.lower() if name else name


def load_pr_cache():
    '''Load PR cache from file'''
    global PR_CACHE  # pylint: disable=global-statement
    from shared.json_cache import cache_load
    data = cache_load(PR_CACHE_FILE)
    if data:
        PR_CACHE = data
        print(f"Loaded {len(PR_CACHE)} cached GitHub PRs")


def save_pr_cache():
    '''Save PR cache to file'''
    from shared.json_cache import cache_dump
    cache_dump(PR_CACHE, PR_CACHE_FILE)


def deduplicate_metadata(hashes, patches):
    '''Remove duplicate hashes and patches, merging sources'''
    seen_hashes = {}
    for h in hashes:
        key = h['hash']
        if key not in seen_hashes:
            seen_hashes[key] = dict(h, sources=[h['source']])
        elif h['source'] not in seen_hashes[key]['sources']:
            seen_hashes[key]['sources'].append(h['source'])
    unique_hashes = []
    for h in seen_hashes.values():
        h['source'] = ', '.join(sorted(h.pop('sources')))
        unique_hashes.append(h)

    seen_patches = {}
    for p in patches:
        key = p['url']
        if key not in seen_patches:
            seen_patches[key] = dict(p, sources=[p['source']])
        elif p['source'] not in seen_patches[key]['sources']:
            seen_patches[key]['sources'].append(p['source'])
    unique_patches = []
    for p in seen_patches.values():
        p['source'] = ', '.join(sorted(p.pop('sources')))
        unique_patches.append(p)

    return unique_hashes, unique_patches


def process_pr_url(url, series):
    '''Process a GitHub PR URL and add commits to series if found.'''
    pr_commits = extract_github_pr_commits(url)
    if pr_commits:
        series.append({'pull_url': url.split('#')[0], 'commits': pr_commits})


def process_gitlab_issue_url(url, series):
    '''Process a GitLab issue URL and add linked MR commits to series.'''
    clean_url = url.split('#')[0]

    if clean_url in PR_CACHE:
        print(f"  Using cached GitLab issue commits from {clean_url}")
        commits = PR_CACHE[clean_url]
    else:
        commits = fetch_gitlab_issue_commits(url)
        if commits:
            PR_CACHE[clean_url] = commits
            save_pr_cache()

    if commits:
        series.append({'pull_url': clean_url, 'commits': commits})


def extract_github_pr_commits(pr_url):
    '''Extract commit hashes from a GitHub pull request (cached).'''
    clean_url = pr_url.split('#')[0]

    if clean_url in PR_CACHE:
        print(f"  Using cached PR commits from {clean_url}")
        return PR_CACHE[clean_url]

    result = fetch_github_pr_commits(pr_url)
    if result:
        PR_CACHE[clean_url] = result
        save_pr_cache()
    return result


def tag_results(hashes, patches, refs, source):
    '''Add source attribution to hashes, patches, and references.'''
    return (
        [{'hash': h['hash'], 'url': h['url'], 'source': source}
         for h in hashes],
        [{'url': p['url'], 'source': source} for p in patches],
        [{'url': r, 'source': source} for r in refs],
    )
