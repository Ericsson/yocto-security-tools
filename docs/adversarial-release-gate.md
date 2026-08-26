<!-- SPDX-License-Identifier: MIT -->
# Adversarial CVE agent release gate

This is the maintained security release checklist for the native
OpenAI-compatible backend. It records deterministic evidence, not a claim that
model output is trustworthy. A successful tool workflow and build mean that
the host completed the requested mechanics; only the separate semantic status
states whether CVE evidence is verified, equivalent, review-required,
rejected, or not evaluated.

The supported release posture is **controlled evaluation with mandatory
semantic and human review**. The agent is not an unattended security-release
gate. Structural adaptations, omitted tests, uncertain source mappings,
missing reproducers, and pre-existing-fix claims can require a human decision
even when compilation succeeds.

## Result and evidence chain

One attempt proceeds through independently recorded states:

1. restrictive artifact directory and transcript creation;
2. bounded repository preflight and corrector handoff validation;
3. optional provider preparation/probe, before source is sent;
4. model turns through closed file, Git, build, and finish tools;
5. trusted workflow/build result creation;
6. reference-versus-generated semantic validation;
7. cleanup that preserves durable evidence; and
8. evaluation reporting from fresh immutable snapshots.

`workflow_status=completed` does not imply `security_status=verified`.
`build_status=passed` proves only the tested build. Security acceptance in the
evaluation harness is limited to `verified` and `equivalent`. Legacy
`AGENT_RESOLVED` rows and cascade/union results are never relabeled as
standalone backend successes.

Every attempt retains mode-`0600` manifests, a bounded redacted JSONL
transcript, provider/build summaries, trusted Git state, semantic evidence,
telemetry, cleanup result, and final result before cleanup finishes. Secret
values are registered with artifact and provider transcript redactors.
Provider bodies, Git output, diffs, build logs, exceptions, and transcript
fields all have explicit bounds; hashes and short excerpts replace full data
where appropriate.

## Deterministic scenario matrix

All tests below are offline. HTTP tests bind a disposable loopback server; the
live Ollama smoke remains opt-in and is not part of the release gate.

| Scenario | Deterministic evidence |
|---|---|
| Exact/equivalent backport | `test_openai_protocol_integration.py` exercises loopback HTTP, real Git, typed edits/cherry-pick, build, commit/amend, finish, cleanup, and artifacts; `test_semantic_validation.py` accepts exact and normalized-equivalent patches only with trusted build/test evidence. |
| Missing prerequisite | `test_missing_prerequisite_initialization_is_rejected` models use-before-initialization and rejects a passing but incomplete result. |
| Changelog-only result | `test_changelog_only_generated_output_is_rejected` rejects documentation-only output when the reference changes runtime code. |
| Omitted upstream test | `test_omitted_upstream_security_test_requires_review` requires review and never auto-verifies the omission. |
| Large-file conflict | `test_openai_patch_hunks.py` and the socket large-file flow prove bounded hunks work while full replacement, ambiguous/overlapping context, races, and excessive output remain rejected. |
| Merge commit | Semantic, preflight, and handoff tests require an explicit valid mainline and reject invalid or missing parent selection before model use. |
| Dirty generated handoff | `test_corrector_handoff.py` classifies/restores declared generated files and rejects unknown tracked changes before provider invocation. |
| Authorized amend | The socket build-fail/repair/build/amend flow verifies final content in `HEAD`; Git tests reject unauthorized index content, options/config injection, conflicts, and parent drift. |
| Source-layout transfer | `tests/corrector/test_transfer.py` proves one deterministic mapping and mutation-free rejection of missing, ambiguous, symlink, gitlink, binary, mode, and manifest-tampering cases. |
| Initialization scale | `test_openai_preflight.py` covers large Vim/Go-style tracked state and precise bounded failure codes with zero provider calls. |
| Progress and fallback | Progress, provider, and backend-loop tests prove finite no-progress handling, shared deadline/counters/call IDs/scope/baseline, eligible fallback, deterministic-host exclusion, and a second state check before fallback's first model request. |
| Audit failure | Artifact, loop, and socket transcript-failure tests make transcript failure fatal, preserve the primary error, and remove untrusted terminal artifacts. |

The evaluation integration suite checks independent clean worktrees, complete
crossover cohorts, baseline-health denominators, same-campaign resume,
deterministic reports, required artifacts, and the distinction between
standalone and fallback-policy runs. Repository provenance is content-
sensitive for tracked and untracked files. Git subprocess output is consumed
incrementally and killed at the byte or deadline limit, so a hostile dirty
tree cannot force unbounded capture.

## Adversarial authority review

The model cannot select a shell command, executable, process environment,
working directory, arbitrary Git argv, configuration, hook, editor, pager,
filter, header, URL redirect, or request-body extension. File and Git paths are
normalized against exact allowed files; traversal, pathspec magic,
leading-option revisions, sibling-prefix confusion, control characters,
symlink parents/targets, hard links, special files, `.git`, gitlinks, and
replacement races are rejected. Mutations use bounded same-directory atomic
replacement or fixed Git operations followed by complete scope and lineage
verification.

Provider input is limited by request JSON-tree and byte bounds. Responses are
non-streaming, incrementally byte-bounded, depth/node bounded, and do not
follow redirects. Duplicate/replayed call IDs do not dispatch twice. Malformed
arguments, reasoning fields, partial/compressed/oversized bodies, status
errors, retry delays, and deadlines become typed bounded failures. A fallback
reuses one runtime, deadline, trusted Git baseline, allowed scope, counters,
and call-ID set. Scope or baseline drift records
`fallback_state_validation_failed` and prevents the secondary model request.

Natural-language success, tool-result-looking text, prompt injection in source
or logs, and model claims of equivalence have no authority. `finish(done)` is
host-checked against current Git operation, conflicts, content generation, and
the most recent successful build. Semantic acceptance is produced only from
host-captured reference/generated diffs, declared path mapping, required-test
evidence, prerequisite anchors, and optional registered reproducers.

The changed native paths contain no `shell=True`, `os.system`, `eval`, or
model-controlled dynamic import. Broad exception handlers remain only at
trusted audit/cleanup/plugin boundaries; their public result and transcript
record a stable bounded failure code/type. HTTP credentials are never placed
in argv or profile values and redirects are disabled. Default tests make no
external connection.

## Operator and migration notes

- Run repository preflight and validate the corrector handoff before any model
  call. Merge references require explicit `mainline_parent` metadata.
- Keep generated-file declarations exact. Unknown out-of-scope dirt is an
  initialization failure, not something the model may restore.
- Use `apply_patch_hunks` for authorized files above the 256 KiB replacement
  cap; it does not enlarge the global full-file limit.
- Treat named endpoint profiles as security-sensitive. Remote plain HTTP can
  disclose source/build diagnostics and requires both explicit remote and
  insecure-HTTP opt-ins.
- Provider capabilities and fallback are strict profile sections. Fallback is
  a separately evaluated policy, not evidence for either model alone.
- Use `baseline-health-only`, then `single-backend-full` or full `crossover`.
  Historical union/resume CSV data is diagnostic only.

Unsupported or review-only cases include unregistered semantic reproducers,
unprovable pre-existing fixes, uncertain/ambiguous source mappings, semantic
changes beyond normalized equivalence, omitted security tests, provider
dialects outside the declared capability schema, and operational server tuning
outside portable/native Ollama APIs. Human review remains responsible for
upstream intent, test adequacy, backport policy, and release authorization.

## Release commands

Run the focused gate at least twice to expose order or timing flakes, then run
the full project checks required by `AGENTS.md`:

```sh
pytest -q tests/agent/test_result_schema.py tests/agent/test_artifacts.py \
  tests/agent/test_openai_preflight.py tests/agent/test_corrector_handoff.py \
  tests/corrector/test_transfer.py tests/agent/test_openai_git_tools.py \
  tests/agent/test_openai_patch_hunks.py tests/agent/test_semantic_validation.py \
  tests/agent/test_openai_progress.py tests/agent/test_openai_provider.py \
  tests/agent/test_openai_backend_loop.py \
  tests/agent/test_openai_protocol_integration.py \
  tests/integration/test_evaluation.py

ruff check .
mypy cve_agent cve_corrector cve_metadata_extractor shared
pytest --cov --cov-report=term-missing
```

Any failure blocks the controlled-evaluation release until explained and
reproduced. Do not weaken a limit or skip a case to make the gate green.
