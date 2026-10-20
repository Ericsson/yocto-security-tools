#!/bin/bash
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
# Bulk campaign settings for the slow local reasoning model: the medium-effort
# native profile, a long per-attempt agent timeout, and a whole-run timeout
# above it. test_cve_corrector.sh keeps its own defaults (kiro, no extra flags,
# 3600 s); this wrapper only supplies the values that differ, then hands over
# every argument unchanged:
#
#   ./run_qwen_campaign.sh --full-only --resume <results-dir>
#
# Each value can still be overridden from the caller's environment, and an
# empty AGENT_EXTRA_FLAGS passes no extra flags. The profile file itself is
# not in this repository: openai-qwen3.8-plain-32k-medium.cfg is found via
# CVE_AGENT_OPENAI_CONFIG_DIR. CVE_METADATA, OE_DIR, BUILD_DIR and MIRROR_DIR
# are still taken from the environment as usual.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export AGENT_BACKEND="${AGENT_BACKEND:-openai-qwen3.8-plain-32k-medium}"
# Unset-only expansion: AGENT_EXTRA_FLAGS= (empty) is an explicit opt-out.
export AGENT_EXTRA_FLAGS="${AGENT_EXTRA_FLAGS---session-timeout 1800}"
# The harness kills a whole agent run after this many seconds, so it must stay
# above the session timeout in AGENT_EXTRA_FLAGS.
export TEST_TIMEOUT="${TEST_TIMEOUT:-7200}"

exec "${SCRIPT_DIR}/test_cve_corrector.sh" "$@"
