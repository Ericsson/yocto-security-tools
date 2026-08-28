### Fix Test Failures (exit code 3)

The context lists the failing cases and before/after pass counts. Understand
*why* the backport made them fail before changing anything — a ptest regression
is almost always one of two things:

**(a) A backport defect.** Your adaptation changed behavior the test correctly
rejects (mis-resolved conflict, dropped hunk, wrong signature/sign). Re-read the
failing test, compare with the upstream intent (`git show <upstream_sha>`), and
fix the source **in allowed files only**. Amend and re-verify.

**(b) A behavior change with a companion commit.** Some fixes deliberately
change observable behavior and upstream updates the tests (or adds a follow-up)
in a *separate* commit. The failing test then needs that commit.
**Never hand-edit test files.**

Tell (a) from (b) by searching the `upstream` remote (full history is fetched):
```bash
git log --oneline <upstream_sha>..upstream/master -- <failing_test_file> # later commits on that test
git log --oneline <upstream_sha>..upstream/master -- <code_area>         # or the code under test
git show <candidate_sha>                                                 # confirm it fixes the case
```
Derive `<failing_test_file>` from the failing-case names (e.g. a `tar` case
lives in `testsuite/tar.tests`). Try `upstream/main` if `upstream/master` is
absent. Then:
- **Companion commit, only Allowed Files** → cherry-pick it as a follow-up
  commit (Strategy A) and re-verify.
- **Companion commit, files OUTSIDE Allowed Files** (a testsuite update almost
  always is) → escalate with a `suggested_commits` entry naming the confirmed
  SHA (see "Suggesting a commit for a scope extension"); do not edit those files.
- **No companion commit, real defect** → fix the code in the allowed files.

Document in the `Conflicts Resolved:` block, inside the stanza of the file you
changed: **one bullet** naming either the code fix or the companion commit you
suggested. If that file had no merge conflict, open its stanza as
`<file> (0 conflicts):`. Do NOT list the failing cases, do NOT quote pass/fail
counts, and do NOT narrate the investigation — the per-file budget (3 bullets /
~40 words, over 48 words is rejected by the `commit-msg` hook) applies to the
amended block exactly as it does to a fresh one. Amend with
`git commit --amend -F <file>`, not `--amend --no-edit`, when you change the
message.
