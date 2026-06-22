# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
'''Configuration loading.

Loads config from (in priority order):
1. Path specified by CVE_EXTRACTOR_CONFIG environment variable
2. Package-bundled config.json (default)

Paths in config.json are resolved relative to XDG base directories
(see shared/paths.py) unless they are absolute.
'''
import json
import os
from pathlib import Path

from shared.paths import cache_dir, data_dir

_DEFAULT_CONFIG = Path(__file__).parent / 'config.json'
_cached_config = None


def load_config(config_path=None):
    '''Load configuration from JSON file.

    Args:
        config_path: Explicit path to config file. If None, uses
                     CVE_EXTRACTOR_CONFIG env var or the bundled default.

    Returns:
        Dict with all configuration values. Cached after first call.
    '''
    global _cached_config  # pylint: disable=global-statement
    if _cached_config is not None and config_path is None:
        return _cached_config

    if config_path is None:
        config_path = os.environ.get('CVE_EXTRACTOR_CONFIG',
                                     str(_DEFAULT_CONFIG))

    with open(config_path, encoding='utf-8') as f:
        cfg = json.load(f)

    # Resolve relative paths to XDG directories
    _data = str(data_dir())
    _shared_data = os.environ.get('CVE_TOOLS_DATA_DIR') or os.environ.get(
        'XDG_DATA_HOME', str(Path.home() / '.local' / 'share'))
    cfg.setdefault('cache_dir', str(cache_dir() / 'cves'))
    cfg.setdefault('pr_cache_file', f'{_data}/github-pulls.json')
    cfg.setdefault('repo_dir', f'{_data}/repos')
    cfg.setdefault('debian_tracker_dir', f'{_shared_data}/security-tracker')
    cfg.setdefault('cvelistv5_dir', f'{_shared_data}/cvelistV5')
    cfg.setdefault('nvd_dir', f'{_shared_data}/nvd')

    if config_path == str(_DEFAULT_CONFIG):
        _cached_config = cfg
    return cfg
