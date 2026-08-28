# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
'''Ubuntu CVE Tracker (local git mirror) CVE metadata extraction.

Reads CVE records directly from a local clone of the Ubuntu CVE Tracker
(https://git.launchpad.net/ubuntu-cve-tracker), avoiding the per-CVE HTTP
requests and rate limiting of the Ubuntu Security API (see ubuntu.py).
'''
import logging
import os
import re

from .config import load_config
from .mirrors import ensure_data_repo
from .sources import SOURCE_REGISTRY, CveSource
from .utils import URL_RE, resolve_url_refs, tag_results

_cfg = load_config()
UCT_URL = 'https://git.launchpad.net/ubuntu-cve-tracker'
UCT_BRANCH = 'master'

CVE_RE = re.compile(r'^CVE-\d{4}-\d+$')
PKG_RE = re.compile(r'^Patches_(\S+):', re.M)


def load_uct_record(repo, cve_id):
    '''Load raw UCT record text for cve_id from a local UCT clone.

    Args:
        repo: Path to the UCT clone, or None/empty if unavailable.
        cve_id: CVE identifier (e.g. "CVE-2023-48795").

    Returns:
        Record text, or '' if the repo is unavailable, the id is not a
        well-formed CVE identifier, or no record exists.
    '''
    if not repo or not CVE_RE.match(cve_id):
        return ''
    for sub in ('active', 'retired'):
        path = os.path.join(repo, sub, cve_id)
        if os.path.isfile(path):
            with open(path, encoding='utf-8', errors='replace') as f:
                return f.read()
    return ''


class UctSource(CveSource):
    '''Ubuntu CVE Tracker source (local git mirror, no per-CVE HTTP).'''
    name = 'uct'
    cli_args = [
        (['--no-uct'], {
            'action': 'store_true',
            'help': 'Disable Ubuntu CVE Tracker source',
        }),
        (['--uct-dir'], {
            'default': _cfg.get('uct_dir'),
            'help': 'Ubuntu CVE Tracker clone (default: %(default)s)',
        }),
    ]

    def __init__(self) -> None:
        self._repo = None

    def setup(self, args, cfg):
        self._repo = ensure_data_repo(
            args.uct_dir, cfg.get('uct_url', UCT_URL),
            'Ubuntu CVE Tracker', cfg.get('uct_branch', UCT_BRANCH))
        if not self._repo:
            logging.warning(
                'Ubuntu CVE Tracker repo unavailable at %s; uct source will'
                ' return no data', args.uct_dir)

    def is_enabled(self, args):
        return not args.no_uct

    def extract(self, cve_id, stats):
        '''Extract fix hashes/patches/references from a UCT record.

        Hashes and patches are collected only from the Patches_* region of
        the record (from the first "Patches_<pkg>:" line onward). Commit
        URLs cited in free-text Notes/Description before that point are
        analyst commentary, not confirmed fixes, and must not be reported
        as hashes.
        '''
        hashes, patches, series, refs = [], [], [], []
        text = load_uct_record(self._repo, cve_id)

        match = PKG_RE.search(text)
        head, patch_region = (text[:match.start()], text[match.start():]) \
            if match else (text, '')

        for url in URL_RE.findall(head):
            refs.append(url.rstrip('.,;)'))

        for url in URL_RE.findall(patch_region):
            url = url.rstrip('.,;)')
            refs.append(url)
            h = resolve_url_refs(url, series)
            if h and not any(e['hash'] == h for e in hashes):
                hashes.append({'hash': h, 'url': url})
                patches.append({'url': url, 'tags': 'patch'})

        if hashes:
            stats['uct_hashes'] += 1
        if patches:
            stats['uct_patches'] += 1

        tagged_hashes, tagged_patches, tagged_refs = tag_results(
            hashes, patches, refs, 'uct')
        return tagged_hashes, tagged_patches, series, tagged_refs

    def deduce_component(self, cve_id, cache):
        '''Deduce component name from the first Patches_<pkg> block.'''
        match = PKG_RE.search(load_uct_record(self._repo, cve_id))
        return match.group(1) if match else None


SOURCE_REGISTRY.append(UctSource())
