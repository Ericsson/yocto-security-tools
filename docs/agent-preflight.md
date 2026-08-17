<!-- SPDX-License-Identifier: MIT -->
# Native repository preflight

Before any backend receives a prompt, the shared guarded session performs a
typed, read-only repository preflight. The result is written to
`preflight.json` and the durable lifecycle transcript.

The preflight records the canonical workspace, HEAD and tree identities,
branch or detached state, Git operation markers, index and porcelain-v2
worktree state, a digest of the normalized allowed paths, bounded counts and
samples, known generated-file classifications, out-of-scope tracked changes,
and a state fingerprint. A second capture immediately before backend handoff
must match, so a concurrent index/worktree/HEAD change fails before a model or
HTTP client can run.

Git filenames are consumed from NUL-delimited output. Policy decisions use the
complete captured set while artifacts retain at most 32 sample paths. Status
and index capture have an 8 MiB hard bound and 100,000-path policy bound;
crossing either produces `INIT_BASELINE_CAPTURE_LIMIT` rather than an opaque
exception or a decision based on truncated data.

Stable failures distinguish unavailable repositories, Git-status errors,
unsupported merge/rebase/revert state, invalid or empty scope, disallowed
dirty state, baseline failure or resource limits, path-policy or transcript
failure, and workspace races. Cherry-pick conflict state remains supported.
Pre-existing tracked generated changes are captured and fingerprinted rather
than broadly cleaned; the model receives no authority over them.

The reproduced initialization failure was a size-bound mismatch: a Vim-like
set of long tracked generated modifications/deletions exceeds the model-facing
256 KiB Git-status limit and previously collapsed into a generic initialization
error. The dedicated preflight uses its separate bounded capture ceiling and
retains counts, a small sample, and a precise code. The Go-style and libpcap
fixtures additionally cover long trees and supported cherry-pick conflicts.
