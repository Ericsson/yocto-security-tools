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


def merge_references(refs):
    '''Deduplicate references by url, combining sources into a sorted list.

    Accepts entries in either shape:
    - Fresh from `tag_results`: {'url', 'source', 'is_poc'?} (single source)
    - Already merged: {'url', 'sources', 'is_poc'?} (source list)

    `is_poc` is sticky: once any entry for a url is flagged, the merged
    entry keeps `is_poc: True`. It is a purely additive key — omitted
    entirely for urls no source ever flagged as a PoC/exploit reference.
    '''
    merged = {}
    for ref in refs:
        url = ref['url']
        entry = merged.setdefault(url, {'url': url, 'sources': set()})
        if 'source' in ref:
            entry['sources'].add(ref['source'])
        entry['sources'].update(ref.get('sources', ()))
        if ref.get('is_poc'):
            entry['is_poc'] = True

    result = []
    for entry in merged.values():
        out = {'url': entry['url'], 'sources': sorted(entry['sources'])}
        if entry.get('is_poc'):
            out['is_poc'] = True
        result.append(out)
    return result


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


def resolve_url_refs(url, series):
    '''Dispatch PR/issue URLs into series; return the commit hash, if any.'''
    if '/pull/' in url:
        process_pr_url(url, series)
    elif _GITLAB_ISSUE_RE.match(url):
        process_gitlab_issue_url(url, series)
    return extract_commit_hash(url)


def poc_ref(url):
    '''Mark a reference url as a PoC/exploit link for tag_results().

    Use this instead of constructing a raw (url, True) tuple, so the one
    place that defines what a "PoC reference" looks like on the wire is
    this function, not a convention repeated at every call site.
    '''
    return (url, True)


def tag_results(hashes, patches, refs, source):
    '''Add source attribution to hashes, patches, and references.

    Each entry in `refs` is normally a plain URL string. A source that can
    structurally identify a reference as a proof-of-concept/exploit link
    (e.g. an API label or reference-tag enum) marks it with `poc_ref(url)`
    instead of a plain string; the resulting reference dict then carries
    an optional `is_poc: True` key. Plain strings never get the key, so
    this is purely additive and existing consumers of `references` are
    unaffected.
    '''
    tagged_refs = []
    for r in refs:
        if isinstance(r, tuple):
            url, is_poc = r
        else:
            url, is_poc = r, False
        entry = {'url': url, 'source': source}
        if is_poc:
            entry['is_poc'] = True
        tagged_refs.append(entry)
    return (
        [{'hash': h['hash'], 'url': h['url'], 'source': source}
         for h in hashes],
        [{'url': p['url'], 'source': source} for p in patches],
        tagged_refs,
    )
