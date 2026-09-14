<!-- SPDX-License-Identifier: MIT -->
# Documentation

Start with the tool you're using, then follow into the design docs as needed.

## Tools

| Doc | Covers |
|-----|--------|
| [cve-metadata-extractor](cve-metadata-extractor.md) | Inputs, data sources, output format, Ubuntu sources, extractor config keys |
| [cve-corrector](cve-corrector.md) | Workflow modes, dependent commit chains, build control, exit codes |
| [cve-agent](cve-agent.md) | AI backends, `--verify-backend`, session limits, security gate, agent exit codes |
| [Configuration](configuration.md) | XDG storage locations and environment variables |

## Design and internals

### Agent contracts

| Doc | Covers |
|-----|--------|
| [Result schema](result-schema.md) | Versioned workflow/build/security outcome format, including the `WORKFLOW_COMPLETED_UNVERIFIED` state before semantic validation accepts a result |
| [Agent artifacts](agent-artifacts.md) | Durable, redacted per-attempt artifact directories |
| [Agent preflight](agent-preflight.md) | Typed repository preflight checks before an AI backend starts |
| [Agent progress and budgets](agent-progress-and-budgets.md) | State-based progress accounting and bounded terminal budgets for native model sessions |

### Correctness boundaries

| Doc | Covers |
|-----|--------|
| [Corrector-to-agent handoff](corrector-agent-handoff.md) | Versioned repository-state boundary crossed after a recoverable corrector failure, including manifest and generated-file policy |
| [Safe patch transfer](safe-patch-transfer.md) | Deterministic patch-transfer plan for cross-layout changes, with content anchors, rollback, and path verification |
| [Semantic security validation](semantic-security-validation.md) | Host-owned gate that a completed build must pass before it's accepted for release |

### Backends and evaluation

| Doc | Covers |
|-----|--------|
| [Native OpenAI-compatible backend](openai-compatible-backend.md) | Ollama setup, API contract, configuration precedence, endpoint/key gates, and troubleshooting for the `openai` backend |
| [Evaluation harness](evaluation-harness.md) | Reproducible backend/model benchmarking with fresh snapshots, crossover cohorts, and semantic success metrics |
| [LLM backport capability suite](llm-backport-capability-suite.md) | Isolated scoring of a model's patch-adaptation ability, independent of Yocto/mirrors/corrector setup |
| [Adversarial release gate](adversarial-release-gate.md) | Deterministic tests for known false positives and hostile model/provider/repository cases before a controlled evaluation release |

## Elsewhere in the repository

- [extra/README.md](../extra/README.md) — plugin development guide for custom
  CVE sources and AI backends
- [CONTRIBUTING.md](../CONTRIBUTING.md) — development setup and contribution
  guidelines
- [AGENTS.md](../AGENTS.md) — codebase map for AI assistants
