# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
'''OSV (api.osv.dev) CVE metadata extraction with file-based caching.'''
import logging
import os
import time

import requests

from .config import load_config
from .sources import SOURCE_REGISTRY, CveSource
from .utils import (
    _GITLAB_ISSUE_RE,
    extract_commit_hash,
    process_gitlab_issue_url,
    process_pr_url,
    tag_results,
)

_cfg = load_config()
OSV_API = _cfg.get('osv_api', 'https://api.osv.dev')

_ECOSYSTEM_PREFIXES = (
    ('python3-', 'PyPI'),
    ('golang-', 'Go'),
    ('go-', 'Go'),
    ('nodejs-', 'npm'),
    ('node-', 'npm'),
    ('ruby-', 'RubyGems'),
    ('perl-', 'CPAN'),
)


def guess_ecosystem(component_name):
    '''Map a Yocto recipe name to an OSV ecosystem string.

    Args:
        component_name: Yocto recipe/component name.

    Returns:
        Ecosystem string (e.g. "PyPI") or None if no match.
    '''
    if not component_name:
        return None
    for prefix, ecosystem in _ECOSYSTEM_PREFIXES:
        if component_name.startswith(prefix):
            return ecosystem
    return None


def get_osv_vuln(cache, cve_id, refresh=False):
    '''Fetch OSV vulnerability by CVE ID with file-based caching.

    Args:
        cache: Cache directory path.
        cve_id: CVE identifier (e.g. "CVE-2023-44487").
        refresh: If True, bypass cache and re-fetch.

    Returns:
        Dict with OSV vulnerability data, or {} if not found.
    '''
    os.makedirs(cache, exist_ok=True)
    cache_file = os.path.join(cache, f'{cve_id}-osv.json')

    from shared.json_cache import cache_dump, cache_exists, cache_load
    if cache_exists(cache_file) and not refresh:
        return cache_load(cache_file)

    try:
        time.sleep(0.05)
        resp = requests.get(f'{OSV_API}/v1/vulns/{cve_id}', timeout=10)
        if resp.status_code == 404:
            data = {}
        else:
            resp.raise_for_status()
            data = resp.json()
    except requests.RequestException as e:
        logging.warning('OSV API request failed for %s: %s', cve_id, e)
        data = {}

    cache_dump(data, cache_file)
    return data


def extract_from_osv_response(osv_data):
    '''Extract fix hashes and patch references from an OSV vulnerability.

    Extracts:
    - Fix commit hashes from affected[].ranges (GIT type, events[].fixed)
    - Reference URLs with type FIX or PATCH

    Args:
        osv_data: Dict from OSV API response.

    Returns:
        Tuple of (patch_links, hashes, series, references).
    '''
    patch_links, hashes, series, references = [], [], [], []
    if not osv_data:
        return patch_links, hashes, series, references

    # Extract fix commits from GIT ranges
    for affected in osv_data.get('affected', []):
        for rng in affected.get('ranges', []):
            if rng.get('type') != 'GIT':
                continue
            repo = rng.get('repo', '')
            for event in rng.get('events', []):
                fixed = event.get('fixed')
                if fixed:
                    url = f'{repo}/commit/{fixed}' if repo else ''
                    hashes.append({'hash': fixed, 'url': url})
                    if url:
                        patch_links.append({'url': url, 'tags': 'patch'})

    # Extract from references with type FIX or PATCH
    for ref in osv_data.get('references', []):
        ref_type = ref.get('type', '')
        url = ref.get('url', '')
        if not url:
            continue
        references.append(url)
        if '/pull/' in url:
            process_pr_url(url, series)
        elif _GITLAB_ISSUE_RE.match(url):
            process_gitlab_issue_url(url, series)
        if ref_type in ('FIX', 'PATCH'):
            patch_links.append({'url': url, 'tags': ref_type.lower()})
            h = extract_commit_hash(url)
            if h and not any(e['hash'] == h for e in hashes):
                hashes.append({'hash': h, 'url': url})

    return patch_links, hashes, series, references


class OSVSource(CveSource):
    '''OSV (Open Source Vulnerabilities) source.'''
    name = 'osv'
    cli_args = [
        (['--no-osv'], {
            'action': 'store_true',
            'help': 'Disable OSV source',
        }),
    ]

    def setup(self, args, cfg):
        self._cache = args.cache
        self._refresh = args.refresh

    def is_enabled(self, args):
        return not args.no_osv

    def extract(self, cve_id, stats):
        '''Extract metadata from OSV for a single CVE.'''
        hashes, patches, series, references = [], [], [], []
        try:
            osv_data = get_osv_vuln(self._cache, cve_id, self._refresh)
            patch_links, hash_list, pr_series, refs = \
                extract_from_osv_response(osv_data)
            if hash_list:
                stats['osv_hashes'] += 1
            if patch_links:
                stats['osv_patches'] += 1
            hashes, patches, references = tag_results(
                hash_list, patch_links, refs, 'osv')
            series = pr_series
        except Exception:  # pylint: disable=broad-except
            logging.warning('Failed to extract from OSV for %s',
                            cve_id, exc_info=True)
        return hashes, patches, series, references

    def deduce_component(self, cve_id, cache):
        '''Deduce component name from cached OSV data.'''
        from shared.json_cache import cache_load
        cache_file = os.path.join(cache, f'{cve_id}-osv.json')
        data = cache_load(cache_file)
        if not data:
            return None
        try:
            for affected in data.get('affected', []):
                pkg = affected.get('package', {})
                name = pkg.get('name')
                if name:
                    return name
        except (TypeError, AttributeError):
            pass
        return None


SOURCE_REGISTRY.append(OSVSource())
