<!-- SPDX-License-Identifier: MIT -->
# Plugin Development Guide

This directory is auto-discovered by `cve_metadata_extractor` at startup.
Drop a `.py` file here to add a new CVE data source — no existing files
need modification.

## Writing a CveSource Plugin

### Data enrichment source

Sources that enrich CVE results with additional metadata (hashes, patches).
These do not provide CVE input — they augment CVEs loaded from `--yocto-summary`
or `--cve-id`.

```python
# extra/my_source.py
from cve_metadata_extractor.sources import CveSource, SOURCE_REGISTRY


class MySource(CveSource):
    """Example custom CVE metadata source."""
    name = 'my_source'
    cli_args = [
        (['--my-source-url'], {'help': 'URL for my source API'}),
        (['--my-source-token'], {'help': 'API token'}),
    ]

    def setup(self, args, cfg):
        self._url = getattr(args, 'my_source_url', None)
        self._token = getattr(args, 'my_source_token', None)

    def is_enabled(self, args):
        return bool(getattr(args, 'my_source_url', None))

    def extract(self, cve_id, stats):
        # Return (hashes, patches, series, references)
        return [], [], [], []


SOURCE_REGISTRY.append(MySource())
```

### Input source plugin

Sources that provide CVE IDs to the extractor (like `--yocto-summary` or
`--cve-id` but from a plugin-defined flag). Set `is_input_source = True` so
the input validation recognizes the plugin before `setup()` is called.

**Important:** `is_enabled(args)` must work purely from the parsed args — do
not rely on state set during `setup()`.

```python
# extra/my_input.py
from cve_metadata_extractor.sources import CveSource, SOURCE_REGISTRY


class MyInputSource(CveSource):
    """Plugin that provides CVE input from a custom file format."""
    name = 'my_input'
    is_input_source = True
    cli_args = [
        (['--my-cve-file'], {'help': 'Path to custom CVE file'}),
    ]

    def setup(self, args, cfg):
        self._path = getattr(args, 'my_cve_file', None)

    def is_enabled(self, args):
        # Must work from args alone (called before setup)
        return bool(getattr(args, 'my_cve_file', None))

    def extract(self, cve_id, stats):
        return [], [], [], []


SOURCE_REGISTRY.append(MyInputSource())
```

## Writing an AI Backend Plugin

```python
# extra/my_backend.py
from cve_agent.backend import AIBackend, SessionResult, register_backend


class MyBackend(AIBackend):
    """Example custom AI backend."""
    name = "my_ai"

    def is_available(self):
        return True  # Check if your tool is installed

    def run_session(self, prompt, workspace_path, allowed_files,
                   model, timeout, interactive):
        # Implement your AI session logic here
        # Return SessionResult(resolved=True/False, duration=...)
        return SessionResult(resolved=False, duration=0.0)


register_backend(MyBackend())
```

## Environment Variable

Set `CVE_EXTRA_SOURCES_DIR` to override the default `extra/` location:

```bash
export CVE_EXTRA_SOURCES_DIR=/path/to/my/plugins
```

## Notes

- Files starting with `_` are skipped
- Errors in plugins are logged but don't crash the main tool
- Plugins in this directory are `.gitignore`'d (use symlinks from a private repo)

## Security Model

Plugins execute with the **full privileges of the host process**. There is no
sandboxing — a plugin can access the filesystem, network, and environment
variables available to the parent tool.

**Trust boundary:** Only load plugins you trust. The auto-discovery mechanism
(`importlib.util.spec_from_file_location`) executes arbitrary Python at import
time. A malicious plugin can:

- Read/write any file the process user can access
- Exfiltrate environment variables (including tokens)
- Make arbitrary network requests
- Modify in-memory state of the host tool

**Mitigations in place:**

- `extra/` is `.gitignore`'d — plugins are never committed to the repository
- `CVE_EXTRA_SOURCES_DIR` / `CVE_EXTRA_BACKENDS_DIR` must be explicitly set to
  load from non-default locations
- Files starting with `_` are skipped (convention for config helpers)
- Plugin load errors are caught and logged without crashing the host

**Recommendations for deployers:**

- Review all plugin source code before deployment
- Use symlinks from a version-controlled private repository
- Restrict filesystem permissions on the `extra/` directory
- In CI environments, do not set `CVE_EXTRA_SOURCES_DIR` unless plugins are
  pinned and audited
