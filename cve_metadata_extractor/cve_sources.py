# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
'''Data loading functions for CVE metadata extraction.'''
import json

from .utils import normalize_component_name


def load_cves_from_sources(cve_id,
                           cve_name, cve_version, historical=False,
                           yocto_summary=None):
    '''Load CVEs from all provided sources'''
    cve_map = {}
    requested_ids = set(cve_id if isinstance(cve_id, list) else [cve_id]) if cve_id else set()

    if yocto_summary:
        with open(yocto_summary, encoding='utf-8') as f:
            yocto_data = json.load(f)
        print(f"Loading CVEs from {yocto_summary}...")
        for recipe in yocto_data.get('package', []):
            if 'issue' not in recipe:
                continue
            for issue in recipe['issue']:
                cve_id_key = issue.get('id')
                if not cve_id_key:
                    continue
                if (issue.get('status') == 'Unpatched'
                        or (historical
                            and issue.get('status') == 'Patched'
                            and issue.get('detail') == 'backported-patch')
                        or (cve_id_key in requested_ids and cve_id_key not in cve_map)):
                    cve_map[cve_id_key] = {
                        'id': cve_id_key,
                        'name': normalize_component_name(
                            recipe.get('name', '')),
                        'version': recipe.get('version', ''),
                        'cvss3 Score': issue.get('scorev3'),
                        'vex_status': 'known_affected'
                    }
        print(f"Loaded {len(cve_map)} CVEs from Yocto summary")

    if cve_id:
        cve_ids = cve_id if isinstance(cve_id, list) else [cve_id]
        for cid in cve_ids:
            if cid not in cve_map:
                cve_map[cid] = {
                    'id': cid,
                    'name': cve_name or '',
                    'version': cve_version or '',
                    'vex_status': 'known_affected'
                }

    result = list(cve_map.values())
    result = [cve for cve in result
              if cve.get('name') not in ('linux_kernel', 'linux_dummy')]
    result = [cve for cve in result
              if not cve.get('vex_flags') or cve.get('vex_flags') == 'N/A']

    return result
