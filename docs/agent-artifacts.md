<!-- SPDX-License-Identifier: MIT -->
# CVE agent durable artifacts

Every CVE attempt creates a unique mode-`0700` result directory below the
configured tool data directory before repository preflight begins. Sensitive
files are mode `0600`. The directory is independent of the temporary devtool
workspace, so cleanup and later cases cannot remove the only audit copy.

Each attempt contains:

- `run-manifest.json`, with schema version, run ID, CVE, canonical backend,
  profile, model, and creation time;
- `preflight.json`, `provider-summary.json`, and `build-summary.json`. For the
  native backend the last also records the latest build's exit status, whether
  it timed out and its log path; a failed build adds the final 3 KiB of its
  output, the only copy once the workspace is gone. Each `build_completed`
  event carries the same facts, so earlier failed builds are kept too;
- `agent-transcript.jsonl`, opened before preflight and flushed at privileged
  boundaries;
- `corrector-handoff.json` once the corrector handoff validates, and
  `corrector-handoff-refreshed.json` after an unresolved session reissues it
  (both are overwritten by the next attempt in the same run);
- `handoff-failure.json` when validating or refreshing the handoff fails: the
  phase, the failure code, the manifest as it stood, and the facts the failing
  check computed (for `HANDOFF_REFERENCE_DRIFT`, the paths the reference and the
  manifest disagree on; for `HANDOFF_RETRY_SCOPE_DRIFT`, the unauthorized
  paths). Path lists are bounded to a count plus a sorted sample. The
  workspace is deleted when the CVE ends, so this is the only copy;
- `result.json` using the versioned outcome schema;
- `telemetry.json`, with separate bounded counters and durations;
- `artifact-manifest.sha256`, covering every finalized retained file.

Transcript schema version 1 gives every event a monotonically increasing
sequence, UTC timestamp, monotonic elapsed time, and attempt number. Native
OpenAI provider, tool, mutation, build, and finish events are mirrored into
the durable lifecycle transcript in execution order. Kiro and Claude retain
the same lifecycle envelope and provider-session summary while their existing
session logs remain compatible.

Structured fields are redacted before JSON serialization. Exact configured
secrets, bearer values, obvious API-key forms, and URL userinfo are removed.
Large values become bounded excerpts plus byte counts and SHA-256 digests.
Provider bodies, child environments, authorization headers, and unrestricted
source/build output are not retained. A failed provider response keeps a bounded
excerpt and digest, plus the facts that say why it failed: the server's
`finish_reason` (kept only as a short printable string), the prompt, completion
and total token counts (kept only as nonnegative integers), and the response size
in bytes. They appear in `provider-primary.json` and in the `http_failure`
transcript event, and tell a reply that ran out of output budget
(`finish_reason: length`) from one that stopped on its own with no tool call.
For a reply that carries a reasoning field it also keeps three facts about that
field, never its text: its length, whether it contains tool-call markup such as
`<tool_call>` (a tool call the parser left inside the thinking), and whether it
ends in a repeating loop. Hidden provider reasoning is not stored;
only assistant content returned through the supported chat contract is
eligible for the same bounded transcript treatment.

A final exact-secret scan covers retained artifacts. A hit is recorded as a
safe audit failure, the offending content is overwritten with a redaction
marker, and the run is not allowed to succeed. Transcript creation/write or
flush failure is likewise fatal; privileged operations never continue with
auditing silently disabled. Unexpected primary exceptions are re-raised after
best-effort result finalization, and cleanup errors do not replace the primary
diagnostic.
