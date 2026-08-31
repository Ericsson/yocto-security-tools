#!/bin/bash
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
# Run the fixed CVE benchmark with the native OpenAI-compatible agent backend.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUNNER="${SCRIPT_DIR}/run_benchmark.sh"
DEFAULT_BACKEND="${OPENAI_BENCHMARK_BACKEND:-openai}"
DEFAULT_JUDGE_BACKEND="${OPENAI_BENCHMARK_JUDGE_BACKEND:-kiro}"
DEFAULT_SESSION_TIMEOUT="${OPENAI_BENCHMARK_SESSION_TIMEOUT:-1800}"

usage() {
    cat <<'EOF'
Usage: run_openai_benchmark.sh [OpenAI options] [benchmark options]

Runs the fixed CVE benchmark with the native OpenAI-compatible backend. A
named profile supplies its endpoint, model, API-key variable, and provider
capabilities. The judge remains Kiro by default and is configured separately.

OpenAI agent options (handled by run_benchmark.sh):
  --backend <selector>       openai or openai-<profile>
                             (default: $OPENAI_BENCHMARK_BACKEND or openai)
  --model <model>            Optional model override. Omit for a named profile.
  --session-timeout <sec>    Agent session budget. Defaults to 1800 seconds or
                             $OPENAI_BENCHMARK_SESSION_TIMEOUT.

Judge options:
  --judge-backend <backend>  kiro (default), openai, or openai-<profile>
  --judge-model <model>      Default: claude-opus-4.8 for Kiro. Omit to use a
                             named OpenAI judge profile's configured model.
  --skip-judge               Disable the judge phase (and its Kiro dependency).

All other options are forwarded unchanged, including --run-case, --resume,
--retier, --dry-run, and --list-cases. The Kiro-only --models roster is not
valid for an OpenAI run; use the singular --model option.

Examples:
  ./run_openai_benchmark.sh \
      --backend openai-qwen3.8-l40s --run-case 1 --skip-judge

  ./run_openai_benchmark.sh \
      --backend openai-qwen3.8-l40s \
      --judge-backend openai-deepseek-v4-flash

For the plain 'openai' selector, configure CVE_AGENT_OPENAI_* (and the API-key
environment variable it names) before running.
EOF
}

for argument in "$@"; do
    case "$argument" in
        -h|--help)
            usage
            exit 0
            ;;
    esac
done

# The native Git runtime deliberately ignores global configuration.  Devtool's
# source workspace does not inherit the meta-layer checkout's local Git config,
# so pass that trusted operator identity explicitly when the caller did not
# already provide one.  GitToolRuntime uses it for new typed commits while
# preserving upstream authors on cherry-picks and amends.
if [[ -z "${GIT_COMMITTER_NAME:-}" || -z "${GIT_COMMITTER_EMAIL:-}" ]]; then
    if [[ -n "${OE_DIR:-}" && -d "${OE_DIR}/.git" ]]; then
        configured_name=$(git -C "$OE_DIR" config --get user.name 2>/dev/null || true)
        configured_email=$(git -C "$OE_DIR" config --get user.email 2>/dev/null || true)
        if [[ -n "$configured_name" && -n "$configured_email" ]]; then
            : "${GIT_COMMITTER_NAME:=$configured_name}"
            : "${GIT_COMMITTER_EMAIL:=$configured_email}"
            export GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL
        fi
    fi
fi

exec "$RUNNER" \
    --backend "$DEFAULT_BACKEND" \
    --judge-backend "$DEFAULT_JUDGE_BACKEND" \
    --session-timeout "$DEFAULT_SESSION_TIMEOUT" \
    "$@"
