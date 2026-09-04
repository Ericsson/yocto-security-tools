# Integration Tests

End-to-end tests that run `cve-corrector` and `cve-agent` against a real
Yocto/OE-Core checkout. These require a full build environment and are not
run in CI.

> **Comparison warning:** `test_cve_corrector.sh` is the historical
> `resume-compatible-legacy` runner. Its cumulative resume output must not be
> reported as a standalone backend/model comparison. New crossover,
> baseline-health, fallback-policy, and stability campaigns use
> `cve_agent.evaluation`; see
> [the evaluation guide](../../docs/evaluation-harness.md).

## Prerequisites

- A Yocto build environment (OE-Core checkout + `oe-init-build-env` sourced)
- Git mirror directory with upstream repos (for offline cherry-pick)
- `pip install -e .` (this project installed)

## Required Environment Variables

```bash
export OE_DIR=/path/to/openembedded-core    # OE-Core git checkout
export BUILD_DIR=/path/to/build             # Yocto build directory
export MIRROR_DIR=/path/to/upstream-git     # Git mirrors of upstream repos
```

Optional:
```bash
export BUILDTOOLS_ENV=/path/to/environment-setup-x86_64-pokysdk-linux
export AGENT_BACKEND=openai-qwen3.8-l40s  # backend or named native profile
export AGENT_MODEL=local-model            # optional model override
```

## Running

```bash
# All test cases
./test_cve_corrector_cases.sh

# Single test
./test_cve_corrector_cases.sh --test 2

# Agent cases (6, 7, 11, 13) with the Claude Code backend
# (requires an authenticated `claude` CLI on PATH)
AGENT_BACKEND=claude ./test_cve_corrector_cases.sh --test 6

# Bulk full-mode campaign with a named local OpenAI-compatible profile
CVE_METADATA="$PWD/test-cve-metadata-agent.json" \
AGENT_BACKEND=openai-qwen3.8-l40s \
./test_cve_corrector.sh --full-only
```

The agent test cases run whichever backend `AGENT_BACKEND` selects; any
backend registered with `cve_agent` works (`kiro`, `claude`, or a plugin
from `extra/`). `cve-agent` itself verifies the backend CLI is available
before starting and exits with a clear error if not.

The bulk runner invokes the selected backend only after `cve-corrector`
returns a recoverable conflict, build, ptest, or patch error. Clean automatic
backports do not invoke the agent. Its resume-compatible output is therefore
an end-to-end pipeline result rather than a pure model-capability score.

For live pytest smoke tests of the Claude backend that do **not** need a
Yocto build environment, see `tests/agent/test_claude_live.py`:

```bash
CLAUDE_LIVE_TESTS=1 pytest -m live -v
```

## Test Cases

| # | Scenario | CVE | Expected |
|---|----------|-----|----------|
| 1 | Multi-patch + removed subsequent | CVE-2024-12086 | exit 0 |
| 2 | Single patch (clean cherry-pick) | CVE-2025-5915 | exit 0 |
| 3 | Multiple patches (series) | CVE-2026-25210 | exit 0 |
| 4 | Conflict | CVE-2026-2903 | exit 1 |
| 5 | Single patch with ptest | CVE-2023-42363 | exit 0 |
| 6 | Agent conflict+ptest | CVE-2026-26157 | exit 14 (correct fix deviates from upstream; see script comment) |
| 7 | Agent build-fix | CVE-2024-0684 | exit 14 (clean corrector-only apply; workspace removed before semantic validation; see script comment) |
| 8 | Missing autotools files | CVE-2024-0684 | exit 0 |
| 9 | Monorepo subprojects strip | CVE-2024-47539 | exit 0 |
| 10 | Single-patch SRC_URI += removal | CVE-2024-39689 | exit 1 |
| 11 | Agent conflict + devtool finish recovery | CVE-2024-39894 | exit 14 (conflicting line is only an OpenBSD version stamp; see script comment) |
| 12 | Skip-build-ptest baseline | CVE-2024-44331 | exit 0 |
| 13 | Agent resolution | CVE-2024-44331 | exit 14 (workspace removed before semantic validation could run; see script comment) |
| 14 | Binutils underscore tag | CVE-2024-53589 | exit 0 |
| 15 | Cross-recipe shared patch removal | CVE-2025-32909 | exit 1 |
| 16 | Ignored untracked files cleanup | CVE-2025-46802 | exit 0 |
| 17 | Monorepo build verification | CVE-2024-47539 | exit 0 |

## Files

- `test_cve_corrector_cases.sh` — Main test runner
- `test_common.sh` — Shared helper functions
- `test_utils.py` — Python utilities (patch removal, comparison)
- `test-cve-metadata.json` — CVE metadata fixture for bulk test runs
- `test-cases-cve-metadata.json` — CVE metadata fixture for individual test cases
