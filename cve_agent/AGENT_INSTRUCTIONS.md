<!-- SPDX-License-Identifier: MIT -->
# CVE Backport Agent Instructions

## Scope Rules

You may ONLY modify files listed in the **Allowed Files** section of the context header.
A git pre-commit hook enforces this — commits with unauthorized files will be rejected.

**NEVER do any of these:**
- `git add .` or `git add -A`
- `git commit --no-verify` or `git cherry-pick --no-verify`
- Create, delete, or rename files
- Modify `.gitignore`, test cases, test data, or test fixtures
- Run `cve_corrector.py` (the agent handles workflow progression)
- Read files outside the workspace directory
- Use the `glob` tool

**Files not in the baseline**: If the upstream commit touches a file that does
not exist in the stable branch (i.e. `git cat-file -e original-version:<file>`
fails), **skip that file entirely**. Do not create it, do not attempt to apply
its changes. Mention it in the commit message as:
`<file>: omitted (not in branch)`

## Workflow

### 1. Analyse (always)
```bash
git log original-version..HEAD --oneline   # what was applied
git show HEAD                               # understand the fix
```
If the patch is incompatible with the stable base, adapt it.

If the CVE fix is **not applicable** to this version (e.g. the vulnerable code
path, function, struct, or feature does not exist in the stable branch), do NOT
make any code changes. Instead, write a conclusion file:

```bash
cat > "<agent_dir>/conclusion.json" <<'EOF'
{"not_applicable": true, "reason": "<one-line explanation of why the CVE does not apply>"}
EOF
```

Replace `<agent_dir>` with the actual agent dir path from the context header.
The reason should be specific — mention the missing function, struct, code path,
or feature and the version. Example:
`"PBMAC1 infrastructure (PBMAC1PARAM, PBMAC1_get1_pbkdf2_param) does not exist in 3.2.6; CVE-2025-11187 is not applicable to this version"`

After writing the conclusion file, **stop — do not make any other changes.**

### 2. Resolve Conflicts (exit code 1)
```bash
git status && git diff                      # examine conflicts
git show <upstream_sha>                     # upstream fix intent
git log --oneline -20 -- <file>             # file history for context
```
Resolve conflicts, then:
```bash
git add <resolved_files>                    # ONLY allowed files
git cherry-pick --no-edit --continue
```

### 3. Fix Build Errors (exit code 4)
Read the last 50 lines of the build log. If the failing task belongs to a
**different recipe** than the one being patched, **abort immediately** — do not
attempt to fix it. This indicates a pre-existing or environmental issue.
Otherwise, fix the code and amend the commit.

### 4. Fix Test Failures (exit code 3)
Fix the **backported code in the allowed files only**, not the tests.
If the fix requires changing a file not in the allowed list, stop and
flag for human review. Document which tests failed and what code change
fixed them in the commit message.

### 5. Build Verification (mandatory after every change)
```bash
BUILD_LOG="<agent_dir>/build_$$.log"
devtool build <recipe> > "$BUILD_LOG" 2>&1
echo "Exit code: $?"
```
On failure: `tail -50 "$BUILD_LOG"`, fix, `git commit --amend --no-edit`, retry.
If `devtool build` logs are insufficient, check Yocto task logs at:
`<yocto_tmp>/work/<arch>/<recipe>/*/temp/log.do_compile`
(paths are in the context header).
On success: **stop — your work is done.**

For cross-compilation: use `bitbake -c devshell <recipe>`, never run
make/cmake/gcc directly.

## Resolution Principles

- **Minimal changes only** — smallest adaptation to make the fix work on stable
- **Preserve upstream intent** — adapt APIs/signatures, never change fix logic
- **Check dependencies** — look for `Link:` in commit, prerequisite patches
- **If uncertain, stop** — flag for human review rather than guess

## Common Conflict Patterns

| Pattern | Resolution | Commit Note |
|---|---|---|
| Function signature changed | Keep fix logic, adapt to stable signature | `Adapted foo_v2() to foo_v1() API` |
| Struct member renamed | Use stable member name with upstream logic | `Member renamed netdev→ndev in original patch` |
| Function moved to different file | Apply fix where function lives in stable | `Function in old_file.c in original patch` |
| Missing helper function | Inline it or use stable equivalent | `Inlined helper_foo() (not in stable)` |

## Commit Message Format

Only add notes if you adapted the patch. Use EXACTLY this markdown format — no
alternative headers like "Conflict resolution notes:" or "Backport changes:".

```
Backport Resolution: <One or two sentences explaining what the upstream commit does — the functional
change, not the conflict details.>

Conflicts Resolved:

<file> (<N> conflict[s]):
- <What was changed and why, referencing stable vs upstream differences.>

<file> (<N> conflict[s]):
- <What was changed and why.>
```

Rules:
- Start with a summary of the upstream fix's purpose (what it changes, why)
- List ONLY files that had conflicts or required adaptation — skip clean files
- For each file, state the conflict count and describe each adaptation
- Mention specific function names, types, APIs, and why the stable branch differs
- Omitted files: `<file>: omitted (not in branch)`
- Do NOT add a "Changes from upstream" section (the agent generates that)
- If you adapted the patch (not a verbatim cherry-pick), add a trailer line
  after a blank line at the end of the commit message:
  `Assisted-by: Claude:<model>` where `<model>` is the **Model** value from
  the context header (e.g. `Assisted-by: Claude:claude-sonnet-4-20250514`)
