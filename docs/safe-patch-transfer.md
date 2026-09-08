<!-- SPDX-License-Identifier: MIT -->
# Safe patch transfer across source layouts

The corrector transfers selected CVE commits onto the `devtool` target through
a versioned host-generated plan. It does not expose patch flags, Git arguments,
shell commands, or path rewriting to a model.

For every source entry, mapping tries an exact path, one configured
`source_root_prefix`, an explicit one-to-one `path_map`, then a unique suffix
or basename candidate whose file mode and complete old-content SHA-256 anchor
match. There is no fuzzy matching. Metadata is scoped to the CVE entry:

```json
{
  "transfer": {
    "source_root_prefix": "upstream",
    "path_map": {"upstream/tests/a.py": "Lib/tests/a.py"}
  }
}
```

Text changes are applied by a bounded host parser. Exact source content is a
strong anchor; an older-branch adaptation is accepted only when each changed
region has one unique content/context position. Renames and deletes are
supported when their old content maps uniquely. Creations require an exact,
configured-prefix, or explicit destination. Binary files, symlinks, gitlinks,
mode/type changes, ambiguous candidates, missing anchors, and unsafe paths are
rejected.

The operation starts from a clean target and records its original commit. Each
commit is staged with explicit paths after `--`, the staged and committed path
sets are checked against the plan, and the final net path set is checked again.
Any failure resets to the original target and removes only planned creations.
The retained manifest records source/parent and target commits, mapping method,
file modes, content anchors, exact final paths, verification, and a bounded
`TRANSFER_*` failure code. A verified transfer's target paths become the
corrector-to-agent handoff scope and the manifest is copied into run artifacts.

## Branch-preparation prerequisite

Anchoring only works when the CVE branch reproduces the target's content for
the files the fix touches. That branch is the upstream release tag plus a replay
of the recipe's own `SRC_URI` patches, so a recipe patch that cannot be replayed
silently changes what the fix is written against.

A conflicting recipe patch is therefore no longer dropped whole. Its conflicted
paths are reset to the CVE branch's state and the rest of the patch is kept, so
a patch that conflicts only in a regenerated packaging file (a release tarball's
`setup.cfg`, for example) still contributes the source context the fix needs.
When a conflicted path is one the fix itself changes, preparation stops with
`PREP_BASE_MISMATCH` and exit code 17 before any build or model session, since
no resolution produced on that base could be transferred. The replay outcome —
partially applied patches, dropped paths, patches not replayed — is recorded in
`<build>/workspace/cve_corrector/prep/<recipe>.json` and appended to
`TRANSFER_*` failure messages as diagnostic context.
