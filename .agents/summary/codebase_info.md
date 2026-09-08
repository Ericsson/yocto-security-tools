# Codebase Information

## Project Identity

- **Name**: yocto-security-tools
- **Version**: 1.2 (see `pyproject.toml`; patch version bumps automatically on every merge to `main`)
- **License**: MIT (Ericsson AB)
- **Repository**: https://github.com/Ericsson/yocto-security-tools
- **Language**: Python ≥3.10 (`requires-python`)
- **Build System**: setuptools (pyproject.toml)

## Purpose

Standalone CVE management tools for Yocto/OpenEmbedded Linux distributions. The toolchain automates the process of finding CVE fix commits, backporting them to stable Yocto recipes via devtool, and resolving conflicts with AI assistance.

## Package Structure

```mermaid
graph TB
    subgraph "Source Packages"
        shared["shared/"]
        extractor["cve_metadata_extractor/"]
        corrector["cve_corrector/"]
        agent["cve_agent/"]
    end
    subgraph "Support"
        extra["extra/ (plugins)"]
        tests["tests/"]
    end
    extractor --> shared
    corrector --> shared
    agent --> shared
    agent -.->|subprocess| corrector
    extra -.->|importlib| extractor
    extra -.->|importlib| agent
```

## CLI Entry Points

| Command | Module | Purpose |
|---------|--------|---------|
| `cve-metadata-extractor` | `cve_metadata_extractor.__main__:main` | Find fix commits from public sources |
| `cve-corrector` | `cve_corrector.__main__:main` | Apply CVE patches via devtool |
| `cve-agent` | `cve_agent.__main__:main` | AI-orchestrated conflict resolution |

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.10–3.14, plus experimental 3.15-dev in CI |
| Runtime deps | `requests` (HTTP), `packaging` (version parsing) |
| Dev deps | `pytest`, `pytest-cov`, `mypy`, `ruff` |
| Build | setuptools ≥68.0 |
| CI | GitHub Actions (matrix: 3.10–3.14 required, 3.15-dev experimental/`continue-on-error`) |
| Pre-commit | ruff (lint+format), mypy |
| Type checking | mypy (`python_version = "3.10"`, check_untyped_defs, ignore_missing_imports) |
| Linting | ruff (E, F, W, I, UP, B, SIM rules, 100 char line, E501 ignored) — note: `target-version = "py39"` in `pyproject.toml` is a legacy holdover even though `requires-python` is 3.10+ |

## Storage Model

XDG Base Directory compliant with environment variable overrides:

| Purpose | Default Path | Override |
|---------|-------------|----------|
| Persistent data | `~/.local/share/yocto-security-tools/` | `CVE_TOOLS_DATA_DIR` |
| Cache | `~/.cache/yocto-security-tools/` | `CVE_TOOLS_CACHE_DIR` |

## Test Organization

Tests mirror the source package structure:
- `tests/agent/` — cve_agent tests
- `tests/corrector/` — cve_corrector tests
- `tests/extractor/` — cve_metadata_extractor tests
- `tests/shared/` — shared module tests
- `tests/integration/` — end-to-end tests (shell + Python)
- `tests/benchmark/` — cve-agent model benchmark (fixed CVE roster x models, AI judge)

Coverage threshold: 65% (`fail_under = 65` in `pyproject.toml`, enforced in CI).
