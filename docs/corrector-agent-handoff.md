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

## Series sequence paths

A conflicting fix series leaves the remaining commits in Git's sequencer todo,
and one `git cherry-pick --continue` applies all of them without a further model
action. Those commits routinely touch files the selected commit does not — test
files, for example — so the manifest declares them separately as
`sequence_paths`: the union of the remaining reference commits' net changes,
minus the allowed paths. A remaining commit whose reference diff cannot be
described contributes nothing, which leaves the sequence unauthorized rather
than silently trusted.

`sequence_paths` never grants the model write authority. They are excluded from
the session's `allowed_files`, from the pre-commit scope hook, and from the file
tools; they authorize only the commits Git itself creates for the rest of the
series, and the host validates the whole first-parent chain against them before
recording a new trusted head. A rejected chain is undone — the branch returns to
the recorded trusted head — so a refusal stays retryable instead of stranding
the session on a HEAD no typed operation will accept. The post-session cleanup
treats them as in-scope for the same reason, and when it must squash, it keeps
the earliest commit's message rather than relabeling the fix with a follow-up
commit's subject.

Build-generated tracked changes are classified from the deterministic
before/after build status. Before handoff, the corrector may restore only that
explicit set. Paths also touched by the security reference remain source scope,
not generated scope. Any other tracked out-of-scope change fails handoff; the
model is never granted restore or edit authority for generated paths.
