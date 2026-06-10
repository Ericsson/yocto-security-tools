# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
'''CVE Metadata Extractor - Extract CVE metadata from multiple sources.'''
from .config import load_config
from .cve_sources import load_cves_from_sources
from .debian import extract_debian_source_patches, load_debian_tracker, load_debian_tracker_extended
from .mirrors import create_mirrors, ensure_data_repo
from .processing import extract_metadata_from_sources, process_cve
from .sources import SOURCE_REGISTRY, CveSource
from .utils import PR_CACHE, load_pr_cache

__all__ = [
    'load_config', 'SOURCE_REGISTRY', 'CveSource',
    'process_cve', 'extract_metadata_from_sources',
    'load_cves_from_sources', 'create_mirrors', 'ensure_data_repo',
    'load_pr_cache', 'PR_CACHE',
    'load_debian_tracker', 'load_debian_tracker_extended',
    'extract_debian_source_patches',
]
