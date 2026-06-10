# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
'''CVEListV5 and NVD source extractors.'''
import glob
import json
import logging
import os

from .mirrors import ensure_data_repo
from .sources import SOURCE_REGISTRY, CveSource
from .utils import (
    _GITLAB_ISSUE_RE,
    extract_commit_hash,
    process_gitlab_issue_url,
    process_pr_url,
    tag_results,
)


def find_cve_json_file(cve_id, datadir):
    '''Find the CVE JSON file in the directory.'''
    pattern = os.path.join(datadir, '**', f"{cve_id}.json")
    matches = glob.glob(pattern, recursive=True)
    return matches[0] if matches else None


def _process_references(refs, patch_links, hashes, series, references):
    '''Process a list of CVE reference objects.'''
    for ref in refs:
        url = ref.get('url', '')
        references.append(url)
        if '/pull/' in url:
            process_pr_url(url, series)
        elif _GITLAB_ISSUE_RE.match(url):
            process_gitlab_issue_url(url, series)
        if 'tags' in ref and 'patch' in ref['tags']:
            patch_links.append({'url': url, 'tags': ', '.join(ref['tags'])})
        h = extract_commit_hash(url)
        if h:
            hashes.append({'hash': h, 'url': url})


def extract_patch_links(cve_json_path):
    '''Extract all reference links with patch tag from CVE JSON file.'''
    patch_links, hashes, series, references = [], [], [], []
    try:
        with open(cve_json_path, encoding='utf-8') as f:
            cve_data = json.load(f)
        cna_refs = (cve_data.get('containers', {})
                    .get('cna', {}).get('references', []))
        _process_references(cna_refs, patch_links, hashes, series, references)
        _process_references(cve_data.get('references', []),
                            patch_links, hashes, series, references)
    except (json.JSONDecodeError, OSError, KeyError, TypeError) as e:
        logging.debug("Error processing %s: %s", cve_json_path, e)
    return patch_links, hashes, series, references


def _extract_from_json_source(cve_id, data_dir, stats, source):
    '''Extract metadata from a JSON CVE source (CVEListV5 or NVD).'''
    hashes, patches, series, references = [], [], [], []
    try:
        cve_json_path = find_cve_json_file(cve_id, data_dir)
        if cve_json_path:
            patch_links, hash_list, pr_series, refs = extract_patch_links(
                cve_json_path)
            if hash_list:
                stats[f'{source}_hashes'] += 1
            if patch_links:
                stats[f'{source}_patches'] += 1
            hashes, patches, references = tag_results(
                hash_list, patch_links, refs, source)
            series = pr_series
    except (IndexError, FileNotFoundError):
        pass
    return hashes, patches, series, references


def extract_from_cvelistv5(cve_id, cvelistv5_dir, stats):
    '''Extract metadata from CVEListV5 source.'''
    return _extract_from_json_source(cve_id, cvelistv5_dir, stats, 'cvelistv5')


def extract_from_nvd(cve_id, nvd_dir, stats):
    '''Extract metadata from NVD source.'''
    return _extract_from_json_source(cve_id, nvd_dir, stats, 'nvd')


class CVEListV5Source(CveSource):
    '''CVEListV5 official CVE database source.'''
    name = 'cvelistv5'
    _data_dir = None
    cli_args = [
        (['--cvelistv5-dir'], {
            'help': 'CVEListV5 directory (default: {default})',
        }),
        (['--no-cvelistv5'], {
            'action': 'store_true',
            'help': 'Disable CVEListV5 source',
        }),
    ]

    def setup(self, args, cfg):
        if args.no_cvelistv5:
            self._data_dir = None
        elif args.cvelistv5_dir:
            repo = ensure_data_repo(
                args.cvelistv5_dir, cfg['cvelistv5_url'], 'CVEListV5',
                cfg.get('cvelistv5_branch'))
            self._data_dir = str(repo) if repo else None
        else:
            self._data_dir = None

    def is_enabled(self, args):
        return bool(getattr(self, '_data_dir', None))

    def extract(self, cve_id, stats):
        return extract_from_cvelistv5(cve_id, self._data_dir, stats)

    def deduce_component(self, cve_id, cache):
        cve_json_path = find_cve_json_file(cve_id, self._data_dir)
        if not cve_json_path:
            return None
        try:
            with open(cve_json_path, encoding='utf-8') as f:
                data = json.load(f)
            affected = (data.get('containers', {})
                        .get('cna', {}).get('affected', []))
            if affected:
                return (affected[0].get('packageName')
                        or affected[0].get('product'))
        except (IndexError, FileNotFoundError, KeyError):
            pass
        return None


class NVDSource(CveSource):
    '''National Vulnerability Database source.'''
    name = 'nvd'
    _data_dir = None
    cli_args = [
        (['--nvd-dir'], {
            'help': 'NVD data directory (default: {default})',
        }),
        (['--no-nvd'], {
            'action': 'store_true',
            'help': 'Disable NVD source',
        }),
    ]

    def setup(self, args, cfg):
        if args.no_nvd:
            self._data_dir = None
        elif args.nvd_dir:
            repo = ensure_data_repo(
                args.nvd_dir, cfg['nvd_url'], 'NVD',
                cfg.get('nvd_branch'))
            self._data_dir = str(repo) if repo else None
        else:
            self._data_dir = None

    def is_enabled(self, args):
        return bool(getattr(self, '_data_dir', None))

    def extract(self, cve_id, stats):
        return extract_from_nvd(cve_id, self._data_dir, stats)

    def deduce_component(self, cve_id, cache):
        cve_json_path = find_cve_json_file(cve_id, self._data_dir)
        if not cve_json_path:
            return None
        try:
            with open(cve_json_path, encoding='utf-8') as f:
                data = json.load(f)
            configs_data = data.get('configurations', {})
            configs = (configs_data if isinstance(configs_data, list)
                       else configs_data.get('nodes', []))
            if configs and configs[0].get('cpe_match'):
                cpe = configs[0]['cpe_match'][0].get('cpe23Uri', '')
                parts = cpe.split(':')
                if len(parts) > 4:
                    return parts[4]
        except (IndexError, FileNotFoundError, KeyError, TypeError):
            pass
        return None


SOURCE_REGISTRY.extend([CVEListV5Source(), NVDSource()])
