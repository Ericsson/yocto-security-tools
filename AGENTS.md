<!-- SPDX-License-Identifier: MIT -->
# AGENTS.md

> AI assistant guide for yocto-security-tools. Start here to navigate the codebase.

## Directory Map

```
├── shared/                      # Leaf module — no upward deps
│   ├── exit_codes.py            # Exit codes 0–15 (single source of truth)
│   ├── paths.py                 # XDG Base Directory paths (data_dir, cache_dir)
│   ├── json_cache.py            # Gzip-compressed JSON cache (atomic writes)
│   └── url_parser.py            # URL → commit hash/PR extraction
├── cve_metadata_extractor/      # Tool 1: find fix commits
│   ├── sources.py               # CveSource base + SOURCE_REGISTRY + plugin loader
│   ├── cve_sources.py           # Input loading (cve-summary.json, VEX)
│   ├── oe_status.py             # Check CVE status in OE branches
│   ├── debian.py / osv.py / cvelistv5.py / ubuntu.py  # Data sources
│   └── config.json              # Public URLs (override via CVE_EXTRACTOR_CONFIG)
├── cve_corrector/               # Tool 2: apply patches via devtool
│   ├── workflow.py              # Main state machine (largest file)
│   ├── state.py                 # WorkflowState + exception hierarchy
│   ├── cherry_pick.py           # Cherry-pick strategies (single, series, least-conflict)
│   ├── blame.py                 # Vulnerability origin analysis
│   └── git_ops.py / bitbake_ops.py / recipe_ops.py / patch_ops.py
├── cve_agent/                   # Tool 3: AI orchestration
│   ├── orchestrator.py          # Resolution loop (run corrector → AI → retry)
│   ├── session.py               # Guarded sessions (file-scope enforcement)
│   ├── backend.py               # AIBackend interface + KiroBackend
│   └── context.py / knowledge.py / review.py
├── extra/                       # Plugin directory (.gitignore'd .py files)
└── tests/{agent,corrector,extractor,shared}/
```

## Key Abstractions

| Abstraction | File | Register Via |
|-------------|------|-------------|
| `CveSource` | `cve_metadata_extractor/sources.py` | `SOURCE_REGISTRY.append(instance)` |
| `AIBackend` | `cve_agent/backend.py` | `register_backend(instance)` |
| `WorkflowState` | `cve_corrector/state.py` | Created by `initialize_cve_workflow()` |
| Exit codes | `shared/exit_codes.py` | Import constants directly |

## Architecture Invariants

1. **Plugin = new file only** — drop `.py` in `extra/`, never modify existing code
2. **Process isolation** — agent invokes corrector via `subprocess.run([python, -m, cve_corrector])`
3. **Acyclic deps** — shared ← extractor, shared ← corrector, shared ← agent
4. **No internal deps** — only `requests` + `packaging` from PyPI
5. **Public URLs only** — config.json points to github.com, salsa.debian.org, api.osv.dev

## Tool Pipeline

```
cve-metadata-extractor → cve-corrector → cve-agent
(find fix commits)       (apply patches)   (resolve conflicts with AI)
```

Each tool works independently. Chain via `--cve-info cve-metadata.json`.

## Recoverable vs Unrecoverable Exit Codes

- **Recoverable** (agent retries with AI): 1 (conflict), 3 (ptest), 4 (build)
- **Unrecoverable** (immediate fail): 2, 5–12

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `CVE_EXTRA_SOURCES_DIR` | Override plugin dir for extractor |
| `CVE_EXTRA_BACKENDS_DIR` | Override plugin dir for agent backends |
| `CVE_EXTRACTOR_CONFIG` | Override config.json path |
| `CVE_TOOLS_DATA_DIR` | Override XDG data directory |
| `CVE_TOOLS_CACHE_DIR` | Override XDG cache directory |
| `GITHUB_TOKEN` | GitHub API (PR metadata) |
| `OPENEMBEDDED_TOKEN` | OE mailing list API |
| `BBPATH` | Required for corrector/agent (Yocto build env) |

## CI & Quality Gates

- **Pre-commit**: ruff (lint+format) + mypy
- **CI matrix**: Python 3.10–3.13 on ubuntu-latest
- **Pipeline**: ruff check → mypy → pytest --cov (threshold: 65%)
- **Ruff rules**: E, F, W, I, UP, B, SIM (line-length 100, E501 ignored)
- **Mypy config**: check_untyped_defs=true, ignore_missing_imports=true, target py3.10

### Run CI Locally Before Committing

Before creating or amending any commit, run the full CI pipeline locally:

```sh
ruff check .
mypy cve_agent cve_corrector cve_metadata_extractor shared
pytest --cov --cov-report=term-missing
```

All three must pass. Do not commit with lint errors, type errors, or failing tests.

## Detailed Documentation

See `.agents/summary/` for:
- [architecture.md](.agents/summary/architecture.md) — dependency graph, process isolation, plugin system
- [components.md](.agents/summary/components.md) — per-file responsibilities
- [interfaces.md](.agents/summary/interfaces.md) — plugin APIs, CLI flags, env vars
- [data_models.md](.agents/summary/data_models.md) — data structures, exit codes, JSON schemas
- [workflows.md](.agents/summary/workflows.md) — state machines, orchestration sequences

## Custom Instructions
<!-- This section is for human and agent-maintained operational knowledge.
     Add repo-specific conventions, gotchas, and workflow rules here.
     This section is preserved exactly as-is when re-running codebase-summary. -->

### Bug Fixes Require Tests

Every bug fix **must** include a pytest that:
1. Reproduces the bug (fails without the fix)
2. Passes with the fix applied

Place tests in `tests/<component>/` matching the module being fixed.

### Run CI Lint on Every Change

Before committing **any** change (new feature, bug fix, refactor), run:

```sh
ruff check .
mypy cve_agent cve_corrector cve_metadata_extractor shared
pytest --cov --cov-report=term-missing
```

All three commands must exit 0. Use `ruff check --fix .` to auto-fix import sorting
and formatting issues. Do not commit with lint errors, type errors, test failures,
or coverage below 65%.

### Minimize Dependencies

- Runtime deps are limited to `requests` and `packaging` — do not add more
  without explicit approval
- Use the Python standard library wherever possible
- Never add a dependency for something achievable in <20 lines of code
- Dev dependencies (`pytest`, `mypy`, `ruff`) are acceptable but keep them minimal
