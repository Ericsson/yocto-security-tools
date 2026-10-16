<!-- SPDX-License-Identifier: MIT -->
<!--
cve-agent result status overview — one slide per status.
Source of truth: cve_agent/result.py (schema v2) and docs/result-schema.md.
Compatible with Marp / reveal.js / pandoc slide renderers (--- separates slides).
-->

# cve-agent Result Status

Schema v2 outcomes: three independent dimensions
(`workflow_status`, `build_status`, `security_status`)
plus a `failure_class` taxonomy and a derived `summary_state` label.

---

## WorkflowStatus · `completed`

The corrector's host-driven workflow ran to completion and produced a current
successful build — `build_status` must be `passed` for this status to be
valid. It says nothing about security: a freshly completed workflow starts
with `security_status = not_evaluated`, since a passing build is not proof
the backport preserves the fix.

---

## WorkflowStatus · `skipped`

A trusted host decision determined no backport was needed, with no build or
security evidence attached (`build_status = not_run`,
`security_status = not_evaluated`). This covers corrector outcomes like
vulnerable code being absent, an existing `CVE_STATUS`, an already-applied
change, or a pre-existing build failure unrelated to the fix.

---

## WorkflowStatus · `escalated`

The run needs a human decision rather than being accepted automatically — for
example a `needs_human` or `not_applicable` finish from the model. These
carry `security_status = plausible_needs_review` because a model's claim
alone never establishes security applicability or equivalence.

---

## WorkflowStatus · `failed`

The workflow did not complete and no backport was produced. It pairs with a
`failure_class` (and optional bounded `failure_code`) that pinpoints where it
broke — e.g. build, provider timeout, or policy rejection — so failures are
diagnosable rather than opaque.

---

## BuildStatus · `passed`

The most recent source mutation was followed by a successful build. This is
the only build state compatible with `workflow_status = completed`, and it
only certifies compilation/build success, not that the security fix is
correctly or completely applied.

---

## BuildStatus · `failed`

The build was attempted after a source change and did not succeed. It is the
expected build state for a `failed` workflow whose `failure_class` is
`BUILD`, and it blocks any claim of workflow completion.

---

## BuildStatus · `not_run`

No build was attempted for this outcome — expected for `skipped` runs (no
backport needed) and for `escalated` runs where human review happens before
a build is attempted. Absence of a build result, not evidence of one either
way.

---

## BuildStatus · `stale`

A build succeeded at some point, but a later source mutation invalidated
that result without a fresh build to confirm it. This exists to prevent an
old passing build from being silently reused as proof after the tree changed
underneath it.

---

## SecurityStatus · `verified`

The strongest security claim: independent confirmation that the backport
closes the vulnerability (e.g. a reproducer or test that fails before the
patch and passes after). This is the only status that satisfies a
`--require-security-status verified` resume gate on its own.

---

## SecurityStatus · `equivalent`

The backport has been shown to be semantically equivalent to the upstream
fix even though it was not independently exploit-tested — typically via the
offline semantic-equivalence gate. It satisfies an `equivalent` resume
requirement and is treated as acceptable alongside `verified`.

---

## SecurityStatus · `plausible_needs_review`

The fix looks reasonable but has not been machine-verified — the default for
escalations (`needs_human`, `not_applicable`) and for legacy data without
durable build evidence. It is a flag for a human reviewer, not an accepted
outcome.

---

## SecurityStatus · `divergent`

Validation found the backport differs meaningfully from the upstream fix in
a way that could leave the vulnerability only partially addressed. Along
with `rejected`, this status drives the `SECURITY_REJECTED` summary label
and should block release acceptance.

---

## SecurityStatus · `rejected`

The backport was explicitly judged to not fix the vulnerability, or to
reintroduce/retain the vulnerable behavior. This is a hard stop: it is
treated the same as `divergent` for release-gating purposes and must not be
promoted.

---

## SecurityStatus · `not_evaluated`

No security assessment has been performed yet — the default for a freshly
completed, build-passing workflow and for skipped runs. It explicitly means
"unknown," not "safe," so downstream gates must not treat it as a pass.

---

## FailureClass taxonomy

When `workflow_status = failed`, a `failure_class` pinpoints the cause:
`host_initialization`, `corrector_handoff`, `patch_transfer`,
`provider_protocol`/`provider_timeout`, `model_no_progress`/`model_budget`,
`build`, `semantic_validation`, `policy_rejection`, `operator_denial`, or
`unknown`. An optional bounded `failure_code` (1–128 printable characters)
adds machine-readable detail for a specific tool or check.

---

## Derived `summary_state`

A single human/machine label computed centrally from the three dimensions —
e.g. `SECURITY_VERIFIED`, `SECURITY_REJECTED`, `SECURITY_REVIEW_REQUIRED`,
`WORKFLOW_COMPLETED_UNVERIFIED`, `SKIPPED`, or `WORKFLOW_FAILED`. It exists so
every output format (CSV, JSON, console text) reports the exact same
precedence-ordered conclusion instead of each caller re-deriving its own.
