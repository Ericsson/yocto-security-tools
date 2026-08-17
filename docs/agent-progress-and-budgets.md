<!-- SPDX-License-Identifier: MIT -->
# Agent progress, targeted context, and budgets

The native OpenAI-compatible loop decides progress only from validated tool
arguments and trusted host results. Each call is fingerprinted from its
canonical tool name, normalized JSON arguments, mutation generation, and a
bounded result digest. Tool-call IDs and assistant prose never establish
progress.

New file/range or Git evidence counts once per repository generation. An
authorized mutation, conflict-count reduction, trusted commit/amend, new build
generation/result, accepted terminal state, or new host-verified terminal
blocker also counts. Re-reading an identical range, repeating unchanged Git
status/diff, retrying an identical build for the same generation, provider
retries, and differently worded model explanations do not.

Before every provider request, the host updates one bounded state message. It
contains conflict and changed-path counts when observed, mutation and validated
build generations, content-free evidence digests, no-information count,
separate turn/tool/mutation/build/retry counters, remaining deadline, and the
required next action classes. The model cannot override this message; paths,
source, secrets, and full logs are omitted.

The first no-information turn receives a structured warning and remaining
budget. The second requires a different action class or explicit escalation.
At the configured threshold the attempt ends with the classified
`model_no_progress` outcome. Configure the bounded 1–10 threshold with
`--openai-max-consecutive-no-progress`, the matching environment variable, or
`max_consecutive_no_progress` in a named profile. The default is three.

Model turns, total tool calls, mutations, builds, provider retries, request and
response bounds, and the single monotonic session deadline are accounted
separately. Neither a retry nor a warning resets the deadline. A build-relevant
mutation is rejected when fewer than two calls would remain, preserving a
deterministic reserve for build plus finish/escalation instead of leaving an
unvalidated late edit.

Generated `context.md` is split into independently hashed, bounded sections.
The CVE/reference summary, allowed/conflict inventory, phase-specific details,
trusted prerequisite symbols/commits/tests/reproducer, and exact typed-tool
constraints remain targeted. Oversized detail is compacted with its original
SHA-256 and must be inspected through typed range/hunk tools; the model is not
repeatedly given an unbounded full repository diff or build log.
