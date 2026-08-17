<!-- SPDX-License-Identifier: MIT -->
# CVE agent durable artifacts

Every CVE attempt creates a unique mode-`0700` result directory below the
configured tool data directory before repository preflight begins. Sensitive
files are mode `0600`. The directory is independent of the temporary devtool
workspace, so cleanup and later cases cannot remove the only audit copy.

Each attempt contains:

- `run-manifest.json`, with schema version, run ID, CVE, canonical backend,
  profile, model, and creation time;
- `preflight.json`, `provider-summary.json`, and `build-summary.json`;
- `agent-transcript.jsonl`, opened before preflight and flushed at privileged
  boundaries;
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
source/build output are not retained. Hidden provider reasoning is not stored;
only assistant content returned through the supported chat contract is
eligible for the same bounded transcript treatment.

A final exact-secret scan covers retained artifacts. A hit is recorded as a
safe audit failure, the offending content is overwritten with a redaction
marker, and the run is not allowed to succeed. Transcript creation/write or
flush failure is likewise fatal; privileged operations never continue with
auditing silently disabled. Unexpected primary exceptions are re-raised after
best-effort result finalization, and cleanup errors do not replace the primary
diagnostic.
