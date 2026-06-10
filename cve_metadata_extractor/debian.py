# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
'''Debian CVE metadata extraction and source patch handling.

Includes tracker parsing, NOTE-line source extraction, DSA list parsing,
and source patch diffing via snapshot.debian.org.
'''
import logging
import os
import re
import tarfile
import time
import urllib.parse
from collections import defaultdict

import requests

from .config import load_config
from .mirrors import ensure_data_repo
from .sources import SOURCE_REGISTRY, CveSource
from .utils import (
    _GITLAB_ISSUE_RE,
    URL_RE,
    extract_commit_hash,
    process_gitlab_issue_url,
    process_pr_url,
)

_cfg = load_config()

CVE_ID_RE = re.compile(r'^(CVE-\d{4}-\d+)\s')
SNAPSHOT_API = _cfg['snapshot_api']
DSA_RE = re.compile(r'\{([^}]+)\}')
FIX_LINE_RE = re.compile(r'^\t\[(\w+)\]\s+-\s+(\S+)\s+(.+)')


def load_dsa_list(dsa_list_path):
    '''Parse DSA list file into a mapping of DSA ID -> info.

    Returns dict: {'DSA-5724-1': {'package': 'openssh',
        'fixes': {'bookworm': '1:9.2p1-2+deb12u3'}, 'cves': [...]}}
    '''
    result = {}
    if not os.path.isfile(dsa_list_path):
        return result
    current_dsa = None
    with open(dsa_list_path, encoding='utf-8') as f:
        for line in f:
            dsa_match = re.match(
                r'\[.*?\]\s+(DSA-\d+-\d+)\s+(\S+)\s+-\s+', line)
            if dsa_match:
                current_dsa = dsa_match.group(1)
                result[current_dsa] = {
                    'package': dsa_match.group(2),
                    'fixes': {}, 'cves': []}
            elif current_dsa and line.startswith('\t{'):
                cve_match = DSA_RE.search(line)
                if cve_match:
                    result[current_dsa]['cves'] = cve_match.group(1).split()
            elif current_dsa and line.startswith('\t['):
                fix_match = re.match(
                    r'\t\[(\w+)\]\s+-\s+\S+\s+(\S+)', line)
                if fix_match and not fix_match.group(2).startswith('<'):
                    result[current_dsa]['fixes'][
                        fix_match.group(1)] = fix_match.group(2)
            elif not line.startswith('\t') and not line.startswith(' '):
                current_dsa = None
    return result


def load_debian_tracker(cve_list_path):
    '''Load CVE NOTE lines from Debian security-tracker data/CVE/list file.

    Returns dict keyed by CVE ID -> list of NOTE text strings.
    '''
    extended = load_debian_tracker_extended(cve_list_path)
    result = {cve_id: entry['notes']
              for cve_id, entry in extended.items() if entry['notes']}
    print(f"Loaded {len(result)} CVEs with notes from Debian tracker")
    return result


def load_debian_tracker_extended(cve_list_path, dsa_list_path=None):
    '''Parse Debian tracker CVE list with fix versions and DSA refs.

    Returns dict: {cve_id: {'notes': [...],
        'fixes': {'bookworm': {'pkg': str, 'version': str}},
        'dsas': [str]}}
    '''
    dsa_data = load_dsa_list(dsa_list_path) if dsa_list_path else {}

    result = {}
    current_cve = None
    entry = {}

    print(f"Loading Debian security-tracker from {cve_list_path}...")
    with open(cve_list_path, encoding='utf-8') as f:
        for line in f:
            cve_match = CVE_ID_RE.match(line)
            if cve_match:
                if current_cve and entry:
                    result[current_cve] = entry
                current_cve = cve_match.group(1)
                entry = {'notes': [], 'fixes': {}, 'dsas': []}
            elif not current_cve:
                continue
            elif line.startswith('\tNOTE: '):
                entry['notes'].append(line.strip()[6:])
            elif line.startswith('\t{'):
                dsa_match = DSA_RE.search(line)
                if dsa_match:
                    for token in dsa_match.group(1).split():
                        if token.startswith(('DSA-', 'DLA-')):
                            entry['dsas'].append(token)
            else:
                fix_match = FIX_LINE_RE.match(line)
                if fix_match:
                    release = fix_match.group(1)
                    pkg = fix_match.group(2)
                    version = fix_match.group(3).split()[0]
                    if not version.startswith('<'):
                        entry['fixes'][release] = {
                            'pkg': pkg, 'version': version}

    if current_cve and entry:
        result[current_cve] = entry

    # Enrich fixes from DSA data when CVE has DSA ref but no [release] line
    for cve_entry in result.values():
        for dsa_id in cve_entry.get('dsas', []):
            dsa_info = dsa_data.get(dsa_id, {})
            pkg = dsa_info.get('package', '')
            for release, version in dsa_info.get('fixes', {}).items():
                if release not in cve_entry['fixes']:
                    cve_entry['fixes'][release] = {
                        'pkg': pkg, 'version': version}

    print(f"Loaded {len(result)} CVEs from Debian tracker (extended)")
    return result


_SNAPSHOT_CACHE = {}


def _snapshot_get(path):
    '''GET JSON from snapshot.debian.org API, with in-memory cache.'''
    if path in _SNAPSHOT_CACHE:
        return _SNAPSHOT_CACHE[path]
    url = f'{SNAPSHOT_API}{path}'
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    result = resp.json()
    _SNAPSHOT_CACHE[path] = result
    return result


def get_snapshot_srcfiles(package, version):
    '''Get source file info for a package version from snapshot API.'''
    encoded = urllib.parse.quote(version, safe='')
    data = _snapshot_get(f'/mr/package/{package}/{encoded}/srcfiles')
    results = []
    for entry in data.get('result', []):
        file_hash = entry['hash']
        info = _snapshot_get(f'/mr/file/{file_hash}/info')
        if info.get('result'):
            first = info['result'][0]
            results.append({
                'hash': file_hash,
                'name': first['name'],
                'archive': first['archive_name'],
                'path': first['path'],
                'timestamp': first['first_seen'],
            })
    return results


def find_debian_tar_url(package, version):
    '''Find download URL for the .debian.tar.xz of a package version.

    Returns (url, filename) or (None, None).
    '''
    try:
        srcfiles = get_snapshot_srcfiles(package, version)
    except Exception:  # pylint: disable=broad-except
        logging.warning('snapshot.debian.org lookup failed for %s %s',
                        package, version, exc_info=True)
        return None, None
    for f in srcfiles:
        if f['name'].endswith('.debian.tar.xz'):
            url = (f'{SNAPSHOT_API}/archive/{f["archive"]}/'
                   f'{f["timestamp"]}{f["path"]}/{f["name"]}')
            return url, f['name']
    return None, None


def find_previous_version(package, fixed_version):
    '''Find the version immediately before fixed_version in same series.

    For 1:9.2p1-2+deb12u3, finds 1:9.2p1-2+deb12u2.
    Falls back to the base version (without +debNNuX) if no prior uX exists.
    '''
    data = _snapshot_get(f'/mr/package/{package}/')
    all_versions = [v['version'] for v in data.get('result', [])]

    match = re.match(r'(.+\+deb\d+u)(\d+)$', fixed_version)
    if not match:
        return None
    prefix = match.group(1)
    fixed_num = int(match.group(2))

    series = {}
    for v in all_versions:
        m = re.match(re.escape(prefix) + r'(\d+)$', v)
        if m:
            series[int(m.group(1))] = v

    candidates = sorted(n for n in series if n < fixed_num)
    if candidates:
        return series[candidates[-1]]

    # Fall back to base version without +debNNuX
    base = prefix.rstrip('u').rsplit('+', 1)[0]
    if base in all_versions:
        return base
    return None


def download_debian_tar(url, cache_dir, filename):
    '''Download a .debian.tar.xz file with caching. Returns local path.'''
    os.makedirs(cache_dir, exist_ok=True)
    local_path = os.path.join(cache_dir, filename)
    if os.path.exists(local_path):
        return local_path
    print(f"  Downloading {filename}...")
    resp = requests.get(url, timeout=120, allow_redirects=True)
    resp.raise_for_status()
    with open(local_path, 'wb') as f:
        f.write(resp.content)
    return local_path


def extract_patches_from_tar(tar_path):
    '''Extract debian/patches/ names and contents from .debian.tar.xz.

    Returns dict: {patch_name: patch_content_bytes}
    '''
    patches = {}
    with tarfile.open(tar_path, 'r:xz') as tar:
        for member in tar.getmembers():
            if (member.isfile()
                    and 'debian/patches/' in member.name
                    and member.name != 'debian/patches/series'):
                name = member.name.split('debian/patches/')[-1]
                if name:
                    extracted = tar.extractfile(member)
                    if extracted:
                        patches[name] = extracted.read()
    return patches


def diff_debian_patches(fixed_patches, previous_patches):
    '''Find patches added in fixed version vs previous version.'''
    new_names = set(fixed_patches) - set(previous_patches)
    return {name: fixed_patches[name] for name in sorted(new_names)}


def _match_patches_to_cve(new_patches, known_hashes):
    '''Filter patches to those matching known commit hashes.

    Searches patch content for any of the known hashes.
    Returns filtered dict, or all patches if no matches found.
    '''
    if not known_hashes:
        return new_patches
    matched = {}
    for name, content in new_patches.items():
        text = content.decode('utf-8', errors='replace')
        if any(h in text for h in known_hashes):
            matched[name] = content
    return matched if matched else new_patches


def extract_debian_source_patches(cve_id, package, fixed_version, cache_dir,
                                  known_hashes=None):
    '''Download fixed and previous .debian.tar.xz, diff patches.

    Returns list of dicts: [{'name': str, 'path': str}]
    '''
    # Check if patches already extracted for this CVE
    out_dir = os.path.join(cache_dir, cve_id, 'debian')
    if os.path.isdir(out_dir):
        existing = []
        for root, _, files in os.walk(out_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                name = os.path.relpath(fpath, out_dir)
                existing.append({'name': name, 'path': fpath})
        if existing:
            print(f"  Using cached Debian patches for {cve_id} "
                  f"({len(existing)} patches)")
            return existing

    print(f"  Extracting Debian source patches for {package} "
          f"{fixed_version}...")

    tar_cache = os.path.join(cache_dir, 'debian-tars')

    fixed_url, fixed_fname = find_debian_tar_url(package, fixed_version)
    if not fixed_url:
        print(f"  No .debian.tar.xz found for {package} {fixed_version}")
        return []

    time.sleep(0.1)

    prev_version = find_previous_version(package, fixed_version)
    if not prev_version:
        print(f"  No previous version found for {package} {fixed_version}")
        return []

    prev_url, prev_fname = find_debian_tar_url(package, prev_version)
    if not prev_url:
        print(f"  No .debian.tar.xz found for {package} {prev_version}")
        return []

    fixed_tar = download_debian_tar(fixed_url, tar_cache, fixed_fname)
    prev_tar = download_debian_tar(prev_url, tar_cache, prev_fname)

    fixed_patches = extract_patches_from_tar(fixed_tar)
    prev_patches = extract_patches_from_tar(prev_tar)
    new_patches = diff_debian_patches(fixed_patches, prev_patches)

    if not new_patches:
        print(f"  No new patches between {prev_version} and {fixed_version}")
        return []

    new_patches = _match_patches_to_cve(new_patches, known_hashes)

    out_dir = os.path.join(cache_dir, cve_id, 'debian')
    os.makedirs(out_dir, exist_ok=True)
    real_out_dir = os.path.realpath(out_dir)
    results = []
    for name, content in new_patches.items():
        filepath = os.path.realpath(os.path.join(out_dir, name))
        if not filepath.startswith(real_out_dir + os.sep):
            logging.warning("Path traversal detected, skipping: %s", name)
            continue
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'wb') as f:
            f.write(content)
        results.append({'name': name, 'path': filepath})
        print(f"  Saved Debian patch: {name}")

    return results

_VERSION_TAG_RE = re.compile(r'\(([^)]+)\)\s*$')


def _parse_note_type(note):
    '''Return "fix" or "test" based on the note prefix, or None.'''
    lower = note.lstrip().lower()
    if lower.startswith('fixed by'):
        return 'fix'
    if lower.startswith('test:') or lower.startswith('test '):
        return 'test'
    return None


def _parse_version_tag(note):
    '''Extract a version tag like "(openssl-3.5.5)" from the end of a note.'''
    match = _VERSION_TAG_RE.search(note)
    return match.group(1) if match else None


def extract_from_debian_tracker(cve_id, debian_data, stats):
    '''Extract metadata from Debian security-tracker NOTE lines.

    Parses "Fixed by:" and "Test:" prefixes to set a type field on hashes.
    Groups commits sharing the same version tag (e.g. "(openssl-3.0.19)")
    into series entries so the corrector can apply them together.

    Args:
        cve_id: CVE identifier string
        debian_data: Dict from load_debian_tracker (CVE ID -> list of notes)
        stats: Mutable stats dict for counters

    Returns:
        Tuple of (hashes, patches, series, references)
    '''
    hashes, patches, series, references = [], [], [], []
    notes = debian_data.get(cve_id, [])
    if not notes:
        return hashes, patches, series, references

    version_groups = defaultdict(list)

    for note in notes:
        note_type = _parse_note_type(note)
        version_tag = _parse_version_tag(note)

        for url in URL_RE.findall(note):
            url = url.rstrip('.,;)')
            references.append(url)
            if '/pull/' in url:
                process_pr_url(url, series)
            elif _GITLAB_ISSUE_RE.match(url):
                process_gitlab_issue_url(url, series)
            h = extract_commit_hash(url)
            if h:
                hashes.append({'hash': h, 'url': url, 'source': 'debian',
                               'type': note_type})
                if version_tag:
                    version_groups[version_tag].append(h)
            if url.endswith('.patch') or '/commit/' in url:
                patches.append({'url': url, 'source': 'debian'})

    for tag, commits in version_groups.items():
        if len(commits) > 1:
            series.append({'pull_url': f'debian:{tag}', 'commits': commits})

    if hashes:
        stats['debian_hashes'] += 1
    if patches:
        stats['debian_patches'] += 1
    references = [{'url': r, 'source': 'debian'} for r in references]
    return hashes, patches, series, references


def download_commit_patches(cve_id, hash_details, cache_dir):
    '''Download .patch files from Debian commit/patch URLs.

    Returns list of local file paths for downloaded patches.
    '''
    patch_dir = os.path.join(cache_dir, cve_id)
    os.makedirs(patch_dir, exist_ok=True)
    downloaded = []
    for detail in hash_details:
        url = detail.get('url', '')
        if detail.get('source') != 'debian':
            continue
        h = detail.get('hash', '')
        if url.endswith('.patch'):
            patch_url, filename = url, os.path.basename(url)
            if not filename:
                continue
        elif '/commit/' in url:
            patch_url = url.rstrip('/') + '.patch'
            filename = f"{h[:12]}.patch" if h else 'unknown.patch'
        else:
            continue
        filepath = os.path.join(patch_dir, filename)
        if os.path.exists(filepath):
            downloaded.append(filepath)
            print(f"  Using cached patch: {filename}")
            continue
        try:
            resp = requests.get(patch_url, timeout=30, stream=True)
            resp.raise_for_status()
            content_length = int(resp.headers.get('content-length', 0))
            if content_length > 10_000_000:
                print(f"  Skipping {filename}: too large ({content_length} bytes)")
                continue
            content = resp.text
            if len(content) > 10_000_000:
                print(f"  Skipping {filename}: too large ({len(content)} bytes)")
                continue
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            downloaded.append(filepath)
            print(f"  Downloaded patch: {filename}")
        except Exception as err:  # pylint: disable=broad-except
            print(f"  Failed to download {patch_url}: {err}")
    return downloaded


class DebianSource(CveSource):
    '''Debian security-tracker source.'''
    name = 'debian'
    _debian_data = None
    _extended = None
    cli_args = [
        (['--debian-tracker-dir'], {
            'help': 'Debian security-tracker directory (default: {default})',
        }),
        (['--no-debian'], {
            'action': 'store_true',
            'help': 'Disable Debian security-tracker source',
        }),
        (['--download-patches'], {
            'action': 'store_true',
            'help': 'Download .patch files and extract Debian source patches',
        }),
        (['--debian-release'], {
            'help': 'Debian release for source patches (default: {default})',
        }),
    ]

    def setup(self, args, cfg):
        self._debian_data = None
        self._extended = None
        if args.no_debian:
            return
        tracker_dir = args.debian_tracker_dir
        if tracker_dir:
            repo = ensure_data_repo(
                tracker_dir, cfg['debian_tracker_url'],
                'Debian security-tracker',
                cfg.get('debian_tracker_branch'))
            if repo:
                cve_list = os.path.join(str(repo), 'data', 'CVE', 'list')
                self._debian_data = load_debian_tracker(cve_list)
                if args.download_patches:
                    dsa_list = os.path.join(str(repo), 'data', 'DSA', 'list')
                    self._extended = load_debian_tracker_extended(
                        cve_list, dsa_list)

    def is_enabled(self, args):
        return self._debian_data is not None

    def extract(self, cve_id, stats):
        return extract_from_debian_tracker(cve_id, self._debian_data, stats)

    def enrich(self, cve_id, result, metadata, args):
        '''Download commit patches and extract Debian source patches.'''
        if not args.download_patches:
            return

        if metadata['hashes']:
            paths = download_commit_patches(
                cve_id, metadata['hashes'], args.cache)
            if paths:
                result['downloaded_patches'] = paths

        if not (self._extended and cve_id in self._extended):
            return
        cve_ext = self._extended[cve_id]
        fix_info = cve_ext.get('fixes', {}).get(args.debian_release)
        if not fix_info:
            return
        from .utils import HASH_RE
        known_hashes = {h['hash'] if isinstance(h, dict) else h
                       for h in metadata.get('hashes', [])}
        for note in cve_ext.get('notes', []):
            for h in HASH_RE.findall(note):
                known_hashes.add(h)
        deb_patches = extract_debian_source_patches(
            cve_id, fix_info['pkg'], fix_info['version'],
            args.cache, known_hashes=known_hashes or None)
        if deb_patches:
            result['debian_source_patches'] = deb_patches


SOURCE_REGISTRY.append(DebianSource())
