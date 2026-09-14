<!-- SPDX-License-Identifier: MIT -->
# Configuration

## Storage (XDG compliant)

| Directory | Default | Override |
|-----------|---------|----------|
| Persistent data | `~/.local/share/yocto-security-tools/` | `CVE_TOOLS_DATA_DIR` |
| Cache (expendable) | `~/.cache/yocto-security-tools/` | `CVE_TOOLS_CACHE_DIR` |

Persistent data holds the source-tracker clones and the agent knowledge base.
The cache directory is safe to delete at any time.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `CVE_EXTRACTOR_CONFIG` | Override the extractor's `config.json` path |
| `CVE_TOOLS_DATA_DIR` | Override the XDG data directory |
| `CVE_TOOLS_CACHE_DIR` | Override the XDG cache directory |
| `GITHUB_TOKEN` | GitHub API access (required for pull request metadata) |
| `OPENEMBEDDED_TOKEN` | OpenEmbedded mailing list API |
| `BBPATH` | Required by `cve-corrector` and `cve-agent`; set by sourcing the Yocto build environment |
| `CVE_EXTRA_SOURCES_DIR` | Override the plugin directory for extractor sources |
| `CVE_EXTRA_BACKENDS_DIR` | Override the plugin directory for agent backends |
| `CVE_AGENT_OPENAI_*` | Configure the native OpenAI-compatible backend |
| `OPENAI_BASE_URL` | Standard fallback API root for the native backend |
| `OPENAI_API_KEY` | Default API key variable name for the native backend |

The full set of `CVE_AGENT_OPENAI_*` variables, and how they interact with CLI
flags and profile files, is documented in the
[native OpenAI-compatible backend guide](openai-compatible-backend.md).

## Extractor config file

`cve-metadata-extractor` reads `cve_metadata_extractor/config.json`, which
holds the public URLs of the data sources and the OE branches to check. See
[cve-metadata-extractor.md](cve-metadata-extractor.md#configuration) for the
key reference.
