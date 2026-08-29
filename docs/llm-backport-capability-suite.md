<!-- SPDX-License-Identifier: MIT -->
# Isolated LLM backport capability suite

The opt-in capability suite measures whether one native OpenAI-compatible
model can adapt an upstream security fix to an older divergent branch. It does
not run metadata extraction, `cve-corrector`, devtool, BitBake, ptest, upstream
network fetches, or a Yocto build environment. Those are valuable end-to-end
tests, but their failures must not be attributed to the model.

Each attempt creates fresh local Git history containing a vulnerable target
branch and trusted upstream reference commits. The harness applies the selected
fix before starting the model, producing either a deterministic conflict or a
clean application with a deliberate prerequisite/build problem. The native
typed runtime enforces the allowed path set and requires a successful
code-owned build before accepting `finish(status=done)`.

The suite relies on two model-visible safety interfaces: bounded file reads
return the complete-file SHA-256 required by large-file hunk edits, and trusted
cherry-pick abort/skip operations restore the session baseline while rejecting
unrelated external edits. A moved-path repair can therefore roll back the
unrepresentable source-path conflict and record the adapted destination as a
separate follow-up commit.

## Cohort

The maintained synthetic cases cover:

- a normal same-file branch conflict;
- a fix whose source file moved on the maintenance branch;
- a fix requiring behavior from an earlier prerequisite commit;
- a conflicted source file larger than the full-file write limit; and
- an expected escalation where the complete fix requires an unauthorized
  path.

The public build checks preserve unrelated maintenance-branch behavior. A
separate code-owned reproducer is not stored in the model workspace. It proves
the baseline vulnerable and validates the completed security behavior. The
existing semantic validator compares the generated commit with the trusted
reference and accepts only `verified` or `equivalent` results.

## Per-attempt acceptance

A positive case passes only when the baseline is healthy and vulnerable, the
provider was called, a durable in-scope repair was committed, the repository
is clean, build/public tests and the hidden reproducer pass, semantic status is
`verified` or `equivalent`, the model used the trusted `done` terminal state,
budgets were respected, and the complete mandatory artifact set matches its
bounded SHA-256 manifest.

An expected-escalation case passes only when the provider was called, the
model returns the repository to its clean baseline, makes no durable commit,
does not receive a security-accepted status, and uses `needs_human`.

Model qualification uses five independent trials per case by default. It
requires at least four accepted attempts for every positive case, at least 90%
acceptance overall, at least 80% in every stratum, all expected-escalation
trials to pass, and zero scope, repository-cleanliness, unsafe-acceptance, or
artifact failures.

## Running a real model

The suite spends real inference and is skipped unless explicitly enabled. A
named native profile is required. For the local Qwen profile:

```sh
export CVE_AGENT_OPENAI_CONFIG_DIR=/absolute/path/to/yocto-security-tools/etc
export CVE_AGENT_LLM_BACKPORT_TESTS=1
export CVE_AGENT_LLM_BACKPORT_BACKEND=openai-qwen3.8-l40s
export CVE_AGENT_LLM_BACKPORT_RESULTS=/absolute/path/to/test-results/llm-backport

pytest -m live -v tests/agent/test_llm_backport_capability_live.py
```

Optional controls:

- `CVE_AGENT_LLM_BACKPORT_TRIALS` selects 5–20 trials per case;
- `CVE_AGENT_LLM_BACKPORT_TIMEOUT` selects a 30–3600 second per-session
  deadline.

The output root contains each fresh attempt, native and durable transcripts,
provider/build/semantic artifacts, `capability-decision.json`, and the final
`qualification.json`. Do not combine partial reruns or copied successes into a
qualification result.

The deterministic scoring unit tests and fixture-health tests remain part of
the normal offline pytest suite:

```sh
pytest tests/agent/test_backport_capability.py
```
