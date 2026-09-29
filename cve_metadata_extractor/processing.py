# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
'''CVE processing and metadata aggregation.'''

from .oe_status import do_check_status
from .utils import deduplicate_metadata, merge_references, normalize_component_name


def deduce_component_name(cve_id, cache, sources):
    '''Try to deduce component name from active sources.'''
    for source in sources:
        name = source.deduce_component(cve_id, cache)
        if name:
            return name
    return ''


def extract_metadata_from_sources(cve_id, active_sources, stats):
    '''Extract hashes and patches from all active sources.

    Args:
        cve_id: CVE identifier string.
        active_sources: List of CveSource instances that are enabled.
        stats: Mutable stats dict.
    '''
    all_hashes, all_patches, all_series, all_references = [], [], [], []

    for source in active_sources:
        hashes, patches, series, references = source.extract(cve_id, stats)
        all_hashes.extend(hashes)
        all_patches.extend(patches)
        all_series.extend(series)
        all_references.extend(references)

    unique_hashes, unique_patches = deduplicate_metadata(
        all_hashes, all_patches)

    seen_series = set()
    unique_series = []
    for s in all_series:
        if s['pull_url'] not in seen_series:
            seen_series.add(s['pull_url'])
            unique_series.append(s)

    # Merge references by url. is_poc is sticky: once any source flags a
    # URL as a PoC/exploit reference, that carries through merges.
    unique_references = merge_references(all_references)

    return {'hashes': unique_hashes, 'patches': unique_patches,
            'series': unique_series, 'references': unique_references}


def process_cve(cve, idx, total, args, active_sources, stats, oe_token):
    '''Process a single CVE and return result.

    Args:
        args: Namespace with at minimum: cache, check_oe, oe_branch, repo_dir.
              Also passed through to source.enrich() (plugin contract).
    '''
    cve_id = cve['id']
    component_name = cve.get('name', '')

    print(f"[{idx}/{total}] Processing {cve_id}...")

    metadata = extract_metadata_from_sources(cve_id, active_sources, stats)

    if not component_name:
        component_name = deduce_component_name(
            cve_id, getattr(args, 'cache', ''), active_sources)

    component_name = normalize_component_name(component_name)

    result = {
        'name': component_name,
        'version': cve.get('version') or None,
        'cvss3_score': cve.get('cvss3 Score') or cve.get('scorev3'),
        'hashes': [h['hash'] for h in metadata['hashes']],
        'hash_details': metadata['hashes'],
        'patches': [p['url'] for p in metadata['patches']],
        'patch_details': metadata['patches'],
        'references': metadata.get('references', []),
    }

    if metadata.get('series'):
        result['series'] = metadata['series']

    if getattr(args, 'check_oe', False):
        result['upstream_status'] = {}
        for branch in getattr(args, 'oe_branch', []):
            try:
                status = do_check_status(
                    oe_token, getattr(args, 'repo_dir', ''), cve_id,
                    branch)
                result['upstream_status'][branch] = status
                print(f"  {branch}: {status}")
            except Exception as e:  # pylint: disable=broad-except
                result['upstream_status'][branch] = None
                print(f"  {branch} check failed: {e}")

    print(f"  Found {len(metadata['hashes'])} hashes, "
          f"{len(metadata['patches'])} patches")

    # Let each source enrich the result (download patches, etc.)
    for source in active_sources:
        source.enrich(cve_id, result, metadata, args)

    return result
