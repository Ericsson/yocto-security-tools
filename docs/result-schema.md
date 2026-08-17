<!-- SPDX-License-Identifier: MIT -->
# CVE agent result schema

Machine-readable CVE agent outcomes use schema version 2. A result has three
independent host-owned dimensions:

- `workflow_status`: `completed`, `skipped`, `escalated`, or `failed`;
- `build_status`: `passed`, `failed`, `not_run`, or `stale`;
- `security_status`: `verified`, `equivalent`, `plausible_needs_review`,
  `divergent`, `rejected`, or `not_evaluated`.

A completed tool workflow requires a successful build after the latest source
mutation. It initially has `security_status = not_evaluated`; build success is
not proof that the backport preserves the security fix. The `needs_human` and
`not_applicable` finish outcomes are escalations with
`plausible_needs_review`, because model claims do not establish security
applicability or equivalence.

A trusted host decision that no backport is required uses
`workflow_status = skipped`, `build_status = not_run`, and
`security_status = not_evaluated`. This covers fixed corrector outcomes such
as vulnerable code being absent, an existing `CVE_STATUS`, an already-applied
change, or a pre-existing build failure. It is a successful command outcome,
not semantic evidence about a generated patch. Legacy skip strings remain
review-required because they do not preserve enough provenance to establish
that the decision came from the trusted host path.

Failures use a separate `failure_class` enum and optional bounded
`failure_code`. The classes cover host initialization, corrector handoff,
patch transfer, provider protocol and timeout failures, model progress and
budget limits, build failures, semantic validation, policy rejection,
operator denial, and unknown failures.

The compatibility-only `legacy_status` field remains available to older
callers. Legacy `AGENT_RESOLVED` data is never upgraded to `verified` or
`equivalent`. It becomes a completed, built, but unverified outcome only when
the reader has durable evidence that the old build path completed; otherwise
it is review-required. Unknown schema versions and enum values fail closed.

The integration CSV includes the schema fields and can migrate old CSV files.
Use `--require-security-status verified` when resuming an integration run to
ensure that an old or merely workflow-completed case is run again. Text output
uses a derived summary such as `WORKFLOW_COMPLETED_UNVERIFIED` or
`SECURITY_VERIFIED`; those labels and every serialization format come from the
same typed outcome mapping.
