<!-- SPDX-License-Identifier: MIT -->
# Corrector-to-agent repository handoff

Recoverable corrector failures produce a versioned JSON manifest beside the
corrector resume state. The agent validates this manifest before any provider
is invoked. A validation failure is reported as `corrector_handoff` with a
stable `HANDOFF_*` code and the provider call count remains zero.

The schema binds the CVE and canonical workspace to baseline/current commit
and tree identities, selected reference commits, the explicit merge mainline
(when applicable), Git operation/conflict state, allowed and known-generated
paths, tracked out-of-scope paths, and index/worktree fingerprints. A SHA-256
digest covers every security-critical field. The validated manifest and its
digest are copied to the per-attempt artifacts and recorded in the transcript.
During the provider call, that validated digest is bound through session-local
host state and recorded as the native runtime's initial trust source. A later
attempt therefore receives an amended commit as a baseline only after the
corrector has emitted and the agent has fully validated a new handoff; the
runtime never silently promotes an arbitrary current HEAD.

Allowed paths are the exact net change of the selected commit against its
parent. Renames retain both source and destination; deletions and file-type
changes remain in scope. A merge commit requires `--mainline-parent N`, or a
positive `mainline_parent` in that CVE's metadata. The parent must be a direct
parent. The corrector never guesses parent 1, and rejects empty net changes.

Build-generated tracked changes are classified from the deterministic
before/after build status. Before handoff, the corrector may restore only that
explicit set. Paths also touched by the security reference remain source scope,
not generated scope. Any other tracked out-of-scope change fails handoff; the
model is never granted restore or edit authority for generated paths.
