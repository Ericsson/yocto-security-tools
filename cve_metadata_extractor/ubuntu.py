# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
'''Ubuntu Security API CVE metadata extraction with file-based caching.'''
import logging
import os
import time

import requests

from .config import load_config
from .sources import SOURCE_REGISTRY, CveSource
from .utils import (
    _GITLAB_ISSUE_RE,
    URL_RE,
    extract_commit_hash,
    process_gitlab_issue_url,
    process_pr_url,
    tag_results,
)

_cfg = load_config()
UBUNTU_API = _cfg.get('ubuntu_api', 'https://ubuntu.com')


def get_ubuntu_cve(cache, cve_id, refresh=False):
    '''Fetch Ubuntu CVE data by CVE ID with file-based caching.

    Args:
        cache: Cache directory path.
        cve_id: CVE identifier (e.g. "CVE-2026-35386").
        refresh: If True, bypass cache and re-fetch.

    Returns:
        Dict with Ubuntu CVE data, or {} if not found.
    '''
    os.makedirs(cache, exist_ok=True)
    cache_file = os.path.join(cache, f'{cve_id}-ubuntu.json')

    from shared.json_cache import cache_dump, cache_exists, cache_load
    if cache_exists(cache_file) and not refresh:
        return cache_load(cache_file)

    max_retries = 3
    base_delay = float(_cfg.get('ubuntu_delay', 1.0))
    data = {}
    for attempt in range(max_retries):
        try:
            time.sleep(base_delay * (2 ** attempt))
            resp = requests.get(
                f'{UBUNTU_API}/security/cves/{cve_id}.json', timeout=30)
            if resp.status_code == 404:
                break
            if resp.status_code == 429:
                logging.warning('Ubuntu API rate limited for %s, retrying...',
                                cve_id)
                continue
            resp.raise_for_status()
            data = resp.json()
            break
        except requests.RequestException as e:
            logging.warning('Ubuntu API request failed for %s (attempt %d/%d):'
                            ' %s', cve_id, attempt + 1, max_retries, e)
    else:
        logging.warning('Gave up fetching Ubuntu data for %s after %d'
                        ' attempts', cve_id, max_retries)

    cache_dump(data, cache_file)
    return data


def _process_url(url, hashes, patch_links, series, *, add_patch_link=False):
    '''Extract hash, detect PRs/issues, and add to results for a single URL.'''
    if '/pull/' in url:
        process_pr_url(url, series)
    elif _GITLAB_ISSUE_RE.match(url):
        process_gitlab_issue_url(url, series)
    h = extract_commit_hash(url)
    if h and not any(e['hash'] == h for e in hashes):
        hashes.append({'hash': h, 'url': url})
        if add_patch_link:
            patch_links.append({'url': url, 'tags': 'fix'})


def extract_from_ubuntu_response(ubuntu_data):
    '''Extract fix hashes and patch references from Ubuntu CVE data.

    Extracts:
    - Patch URLs from patches dict (format: "label: URL")
    - Reference URLs from references list

    Args:
        ubuntu_data: Dict from Ubuntu Security API response.

    Returns:
        Tuple of (patch_links, hashes, series, references).
    '''
    patch_links, hashes, series, references = [], [], [], []
    if not ubuntu_data:
        return patch_links, hashes, series, references

    # Extract from patches dict: {package: ["label: URL", ...]}
    for urls in (ubuntu_data.get('patches') or {}).values():
        for entry in urls:
            match = URL_RE.search(entry)
            if not match:
                continue
            url = match.group(0)
            patch_links.append({'url': url, 'tags': 'patch'})
            _process_url(url, hashes, patch_links, series)

    # Extract from references list
    for url in ubuntu_data.get('references') or []:
        if not url:
            continue
        references.append(url)
        _process_url(url, hashes, patch_links, series, add_patch_link=True)

    return patch_links, hashes, series, references


_CIRCUIT_BREAKER_THRESHOLD = 3


class UbuntuSource(CveSource):
    '''Ubuntu Security API source.'''
    name = 'ubuntu'
    cli_args = [
        (['--no-ubuntu'], {
            'action': 'store_true',
            'help': 'Disable Ubuntu source',
        }),
    ]

    def __init__(self) -> None:
        self._failures = 0

    def setup(self, args, cfg):
        self._cache = args.cache
        self._refresh = args.refresh

    def is_enabled(self, args):
        return not args.no_ubuntu

    def extract(self, cve_id, stats):
        '''Extract metadata from Ubuntu Security API for a single CVE.'''
        hashes, patches, series, references = [], [], [], []
        if self._failures >= _CIRCUIT_BREAKER_THRESHOLD:
            logging.warning('Ubuntu source disabled after %d consecutive'
                            ' failures; skipping %s',
                            self._failures, cve_id)
            return hashes, patches, series, references
        try:
            ubuntu_data = get_ubuntu_cve(self._cache, cve_id, self._refresh)
            patch_links, hash_list, pr_series, refs = \
                extract_from_ubuntu_response(ubuntu_data)
            if hash_list:
                stats['ubuntu_hashes'] += 1
            if patch_links:
                stats['ubuntu_patches'] += 1
            hashes, patches, references = tag_results(
                hash_list, patch_links, refs, 'ubuntu')
            series = pr_series
            self._failures = 0
        except Exception:  # pylint: disable=broad-except
            self._failures += 1
            logging.warning('Failed to extract from Ubuntu for %s'
                            ' (%d/%d failures)',
                            cve_id, self._failures,
                            _CIRCUIT_BREAKER_THRESHOLD, exc_info=True)
        return hashes, patches, series, references

    def deduce_component(self, cve_id, cache):
        '''Deduce component name from cached Ubuntu data.'''
        from shared.json_cache import cache_load
        cache_file = os.path.join(cache, f'{cve_id}-ubuntu.json')
        data = cache_load(cache_file)
        if not data:
            return None
        try:
            for pkg in data.get('packages', []):
                name = pkg.get('name')
                if name:
                    return name
        except (TypeError, AttributeError):
            pass
        return None


SOURCE_REGISTRY.append(UbuntuSource())
