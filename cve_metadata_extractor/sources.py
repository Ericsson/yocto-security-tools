# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""CVE metadata source base class and plugin auto-discovery.

Adding a new source requires only dropping a .py file in the extra/ directory
(or the path specified by CVE_EXTRA_SOURCES_DIR). No existing files need modification.
"""
import importlib.util
import logging
import os
from pathlib import Path
from typing import Any

# Registry of all source instances, populated by each source module at import.
SOURCE_REGISTRY: list["CveSource"] = []


class CveSource:
    """Base class for a pluggable CVE metadata source.

    Subclasses define their own CLI args, setup logic, and extraction.
    Registering a source is done by appending an instance to SOURCE_REGISTRY.

    Attributes:
        name: Short identifier used in stats keys and log messages.
        cli_args: List of (flags, kwargs) tuples passed to argparse.
        is_input_source: If True, this source provides CVE input (not just
            enrichment). Used for input validation before setup() is called.
    """
    name = ''
    cli_args: Any = ()
    is_input_source: bool = False

    def setup(self, args, cfg) -> None:
        '''Prepare the source for extraction (auth, clone, load data).'''

    def is_enabled(self, args) -> bool:
        '''Return True if this source should be used for the current run.'''
        return True

    def extract(self, cve_id: str, stats: dict) -> tuple[list, list, list, list]:
        '''Extract metadata for a single CVE.

        Returns:
            Tuple of (hashes, patches, series, references).
        '''
        raise NotImplementedError

    def enrich(self, cve_id: str, result: dict, metadata: dict, args) -> None:
        '''Post-extraction enrichment of a CVE result.'''

    def deduce_component(self, cve_id: str, cache: str) -> 'str | None':
        '''Try to deduce component name from this source's data.'''
        return None


def _load_extra_sources():
    """Auto-discover and load source plugins from extra/ directory.

    Only loads from the project's own extra/ directory or a path explicitly
    set via CVE_EXTRA_SOURCES_DIR. Symlinks are resolved before validation.
    """
    project_root = Path(__file__).resolve().parent.parent
    extra_dir = os.environ.get('CVE_EXTRA_SOURCES_DIR',
                               str(project_root / 'extra'))
    extra_path = Path(extra_dir).resolve()
    if not extra_path.is_dir():
        return
    # Security: refuse to load plugins from world-writable directories
    # or directories not owned by the current user
    dir_stat = extra_path.stat()
    if dir_stat.st_mode & 0o002:
        logging.warning(
            "Plugin directory %s is world-writable, skipping plugin loading",
            extra_path)
        return
    if dir_stat.st_uid != os.getuid():
        logging.warning(
            "Plugin directory %s not owned by current user, skipping",
            extra_path)
        return
    for py_file in sorted(extra_path.glob('*.py')):
        if py_file.name.startswith('_'):
            continue
        try:
            spec = importlib.util.spec_from_file_location(
                f"extra.{py_file.stem}", py_file)
            if spec is None or spec.loader is None:
                continue
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
        except Exception as e:
            logging.warning("Failed to load extra source %s: %s",
                            py_file.name, e)


_load_extra_sources()
