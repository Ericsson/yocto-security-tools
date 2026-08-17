<!-- SPDX-License-Identifier: MIT -->
# Semantic security validation

A successful agent session and build prove workflow completion, not that a CVE
fix retained its security behavior. Before provider execution, the host builds
`reference-manifest.json` from local Git objects and CVE metadata. It records
the selected reference and parent basis, explicit prerequisites, path/status
sets, deterministic runtime/test/docs/build classifications, path mappings,
required anchors and tests, optional pre-existing-fix proof, and bounded patch
fingerprints. Unknown metadata keys and unsafe paths fail closed.

The optional `semantic_validation` metadata object supports these keys:

- `reference_commits` and `prerequisite_commits`;
- `path_map`, `runtime_paths`, `test_paths`, `docs_paths`, and `build_paths`;
- `expected_symbols`, `required_tests`, and `equivalent_tests`;
- `preexisting_fix_symbols` and `prerequisite_symbols`;
- `initialization_checks`, each with `symbol`, `initialize_anchor`, and
  `use_anchor`; and
- `reproducer`, a bounded registered host-runner name, never executable or
  argument text.

Absent explicit classification, conventional test, documentation, and build
paths are classified deterministically. Unusual extensions are recorded as
uncertain rather than treated as runtime proof. The default reference is the
first fix commit, or the declared dependent series. A merge reference needs the
already trusted top-level `mainline_parent`; the validator records that exact
parent and does not guess one.

After the agent finishes but before `devtool finish` removes the workspace, the
host captures the final commit, exact path/status set, bounded changed-line
fingerprints, and bounded searchable runtime text. After the authoritative
corrector build/ptest result is known, the validation ladder assigns one of:
`verified`, `equivalent`, `plausible_needs_review`, `divergent`, `rejected`, or
`not_evaluated`.

The ladder first checks exact path/status and patch fingerprints, then a
documented whitespace-only normalization. It next checks mapped runtime paths,
required symbols, explicit prerequisite initialization order, retained or
declared-equivalent tests, pre-existing-fix anchors, and an optional registered
deterministic reproducer. Reproducer names resolve only through the immutable
host-code registry; adding a runner requires a reviewed source change. Metadata
cannot supply an executable, arguments, environment, or shell fragment. A
model explanation is never an input.

Conservative rules reject a result when the reference changes runtime code but
the generated result changes no corresponding mapped runtime path, unless
trusted baseline anchors prove the fix was already present. Missing required
tests require review. Deterministically missing prerequisite behavior or
use-before-initialization is rejected. Large adaptations are review-required,
not rejected merely because of line count. Failed, stale, or absent build
evidence can never produce a verified status.

Each decision writes bounded `semantic-validation.json` and
`semantic-validation.txt` artifacts containing the reason code, path/status
comparison, prerequisite and test evidence, diff metrics, limitations, and
human-review items. Source content and model assertions are not retained.

`--security-gate equivalent` is the default release gate and accepts
`equivalent` or `verified`; `--security-gate verified` requires the stronger
status. A completed build that does not satisfy the configured gate exits as a
release failure while retaining its independent workflow-completed outcome.

Limitations remain deliberately visible. Structural equivalence cannot be
proven from path overlap and symbols alone, so a non-identical adaptation needs
a registered deterministic reproducer or human review. Test-path retention
does not by itself prove coverage; use an explicit reproducer or required test
runner where practical.
