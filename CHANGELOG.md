<!-- SPDX-License-Identifier: MIT -->
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **cve-agent**: `claude` backend that drives the Claude Code CLI directly, selectable with `--backend claude` (kiro remains the default). Model names are mapped to Claude aliases, and the backend passes through Anthropic/cloud auth environment variables.
- **tests**: integration test runner accepts `AGENT_BACKEND` / `AGENT_MODEL` environment variables so the agent test cases can run against any registered backend (e.g. `AGENT_BACKEND=claude`), plus opt-in live smoke tests (`CLAUDE_LIVE_TESTS=1 pytest -m live`) that verify the emitted CLI flags and a real conflict resolution against an installed `claude` binary.
- **tests**: CLI contract tests using a stub `claude` executable (argv/env/cwd recording, no API key needed) and guard-parity tests that fail if the Claude backend's tool allow/deny lists drift from the kiro agent manifest.

## [1.0.1] - 2026-07-03

### Fixed

- **cve-corrector**: Run meta-layer branch check at workflow start, failing fast on detached HEAD
- **cve-corrector**: Retry git fetch with alternate transport protocol (https↔git) when initial fetch fails
- **cve-corrector**: Always compare patch-deduced upstream URL against recipe SRC_URI to detect supply-chain mismatches

### Added

- **cve-corrector**: Fetch fix-commit repository as a secondary remote when fix commits live in a different repo than the recipe SRC_URI
- **cve-corrector**: Enrich commit messages with fix provenance references and source attribution
- **cve-metadata-extractor**: Deduce sourceware repository URLs from cgit-style commit links
- **ci**: Add GitHub attestations to the release workflow

## [1.0.0] - 2026-05-25

Initial release of standalone CVE management tools for Yocto/OpenEmbedded.

### Added

- **cve-metadata-extractor**: Find fix commits from multiple public sources (Debian, OSV, CVEList V5, Ubuntu)
- **cve-corrector**: Automate CVE backporting to Yocto recipes via devtool
- **cve-agent**: AI-assisted conflict resolution for CVE backports
- Plugin system for custom CVE sources and AI backends (`extra/` directory)
- XDG Base Directory compliant data/cache storage
- Minimal dependencies: only `requests` and `packaging`
- Python 3.10+ supported
- GitHub Actions CI (lint, type check, tests across Python 3.10–3.13)
- Automated publishing to PyPI via Trusted Publishing (OIDC)
- Pre-commit hooks (ruff, mypy)

[1.0.1]: https://github.com/Ericsson/yocto-security-tools/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Ericsson/yocto-security-tools/releases/tag/v1.0.0
