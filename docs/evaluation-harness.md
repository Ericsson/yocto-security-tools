<!-- SPDX-License-Identifier: MIT -->
# Reproducible CVE agent evaluation

`cve_agent.evaluation` is the security-first campaign layer for backend/model
comparisons. It is deliberately separate from the historical cumulative shell
runner. The module owns cohort enumeration, immutable campaign identity,
fresh-snapshot checks, resume rules, decomposed metrics, and deterministic
reports. Environment-specific Yocto setup and provider execution are injected
as snapshot, baseline, and backend callbacks, which keeps the default suite
offline and makes the comparison rules testable.

## Run modes

- `baseline-health-only` runs only setup/build/ptest health checks.
- `single-backend-full` runs every testable selected case with one backend.
- `crossover` runs every testable selected case independently with every
  selected backend. It never copies a success row from another backend.
- `fallback-policy` evaluates one explicitly marked cascade as a policy; its
  rows are not labeled as standalone primary- or fallback-model runs.
- `stability-subset` repeats each selected case and records acceptance and
  duration variance. The report warns when the seven maintained strata are not
  all represented.
- `resume-compatible-legacy` imports old CSV data as unverified. It cannot run
  backends or support a valid model comparison.

The maintained stability strata are clean backport, branch conflict,
prerequisite commit, large-file hunk edit, merge commit, deterministic host
failure, and expected escalation/negative case. A seed is optional because
many providers cannot make generation deterministic. The manifest always
records attempt order, configured temperature, model/profile metadata, and a
seed when one is meaningful.

## Manifests and clean snapshots

`CampaignManifest.create()` hashes the complete comparison design into an
immutable campaign ID. It records the repository commit and dirty-state
digest, implementation version, metadata hash, corrector/validator versions,
limits and timeouts, a small secret-free host platform summary, selected case
IDs, resolved backend configuration digests, trial count, and optional seed.

Every execution also gets a mode-`0600` `manifest.json` containing its profile,
model identifier/digest, source/download/cache identities, expected snapshot
digest, unique clean-worktree identity, trial, and attempt order. A runner
rejects a source snapshot mismatch or reuse of a worktree identity. Every
backend in a crossover therefore receives an independent worktree derived
from the same per-case snapshot. Resume accepts rows only from the exact same
campaign ID and execution key; it cannot synthesize or import an unrun backend
result.

The dirty-state digest covers bounded porcelain state, the tracked binary
diff, and content-sensitive hashes of untracked regular files and symlink
targets. It does not retain their source bytes. Git output is read
incrementally under fixed stdout, stderr, and time limits; an oversized or
racing repository is rejected instead of being captured without bounds.

The harness does not prescribe how a site provisions worktrees or shared
download caches. The injected snapshot callback must create the clean isolated
workspace and return its verified identities. Cache identity is provenance,
not permission to share mutable workspace state.

## Baseline health and denominators

Pre-existing infrastructure failures use distinct states:

```text
BASELINE_BUILD_BROKEN
BASELINE_PTEST_BROKEN
BASELINE_SETUP_BROKEN
BACKEND_NOT_EVALUATED
```

Their logs remain attached to the case and reports cluster them by recipe.
They count toward the metadata denominator and coverage gap, but are excluded
from the backend denominator. Unexpected failures are not automatically added
to a skip list. There is currently no maintained known-baseline-failure policy;
adding one requires an explicit, versioned repository policy.

## Metrics and primary outcome

`EvaluationMetrics.from_artifact()` consumes the trusted `telemetry.json`
without deriving inference time from wall-clock totals. The evaluation schema
keeps baseline build, corrector, workspace setup, provider wait, typed-tool
execution, build, ptest, semantic validation, patch transfer, cleanup, and
total time separate. It also retains model turns, mutually exclusive tool-call
classes, duplicate calls, build and session attempts, provider retries, and
nullable input/output token counts.

Release reporting defaults to security-accepted (verified or equivalent)
fixes over testable backend executions. Callers can explicitly select workflow
completion or build-passed as a different primary metric, while reports always
show all three. They also show security status counts, rejected/known-false-
positive rate, deterministic host/corrector failure rate, model-addressable
success rate, review workload, per-backend results, and median/p90/p95 provider
wait and total duration. Cost per accepted fix is produced only when both
token prices are explicitly supplied and all relevant token counts exist.

## Invalid-comparison guards and output

`build_comparison_report(..., strict=True)` refuses a comparison when a
backend lacks part of the selected testable cohort, campaign IDs or resolved
configuration versions are mixed, snapshots differ, worktrees are reused,
semantic validation is unavailable, mandatory manifest/transcript/result
artifacts are missing, or legacy rows are present. Non-strict mode labels the
report invalid and lists the same reasons; it never silently upgrades the
data.

`write_reports()` atomically writes deterministic `evaluation.json`,
`evaluation.csv`, and `evaluation.md`. Each contains campaign provenance,
denominators, exclusions, limitations, and security-first outcomes. The JSON
retains each full execution manifest and artifact map.

## Legacy shell runner

`tests/integration/test_cve_corrector.sh` remains available for its historical
single-environment workflow and resume compatibility. Its cumulative resume
rows are not a crossover: old `AGENT_RESOLVED` means neither semantic
verification nor standalone model success. Use its output for debugging or
import it through `import_legacy_csv()`; do not combine copied successes and
partial reruns into a model score.

The maintained hostile-input matrix and release commands are documented in
the [adversarial release gate](adversarial-release-gate.md).
