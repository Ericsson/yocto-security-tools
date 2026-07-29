<!-- SPDX-License-Identifier: MIT -->
# CVE Backport Agent Instructions

## Available Tools

You have file read/inspection tools and a bash-equivalent command runner —
the exact tool names depend on your runtime and are described in the
preamble that precedes these instructions. The rules below apply regardless
of tool names:

- Use your file/directory inspection tool for ALL file and directory
  inspection — reading `context.md`, checking whether a file exists,
  listing a directory, viewing build logs, etc. Do NOT shell out to `ls`,
  `find`, or `cat` for this; it is already fully trusted and works for
  every path you need.
- Your bash-equivalent runner is restricted to a fixed allow-list (git
  plumbing, `devtool build`, log tailing, and `tee`/`echo` for build-log
  capture). Commands not on that list
  are rejected outright with no prompt — there is no fallback, so don't
  try variations or guess at alternate commands. If a task seems to
  require something outside the allow-list below, stop and flag it
  rather than probing for a workaround.
- Run each command **bare and exactly as listed**. Your shell already runs
  inside the workspace, so do NOT prefix `cd <path>`: `git status` is
  accepted, but `cd /path && git status` is rejected because `cd` is not on
  the list.
- **File redirection (`>`, `>>`) is rejected unconditionally**, no matter
  what the allow-list says. To capture output to a file, pipe into `tee`
  instead: `<cmd> 2>&1 | tee <agent_dir>/<name>.log`. Merging stderr with
  `2>&1` is fine; only the `>`/`>>` file-write form is refused.
- **Never write files outside the agent dir or the Yocto build dir** — the
  only two locations you have any reason to write to are `<agent_dir>`
  (given in the context header, for logs like `build.log`) and paths under
  the Yocto build dir (also given in the context header, e.g. its `tmp/`
  or `tmp-glibc/` task-log tree). Do not `tee` to `/tmp`, your home
  directory, or any other path outside those two locations — even if a
  command superficially matches the allow-list's shape, writing outside
  these locations is never an intended use and must not be attempted.
- Chaining with `;` or `|` is accepted **only when every command in the
  chain is individually on the allow-list** — each part is checked
  separately. `devtool build jq 2>&1 | tee <agent_dir>/build.log` works
  because both `devtool build *` and `tee` are allowed; `git status | grep x`
  does not, because `grep` is not.

Bash commands you CAN run:

- Inspect: `git status`, `git status --porcelain`, `git diff[ *]`, `git log *`,
  `git show *`, `git rev-parse *`, `git merge-base *`, `git ls-files[ *]`
  (`git ls-files -u` lists the unmerged stage entries of a conflict directly),
  `git submodule status[ *]` (diagnoses a gitlink recorded upstream that does
  not exist in a tarball-sourced workspace), `cat *`, `head *`, `tail *`,
  `wc *`.
- Stage / unstage: `git add *`, `git rm [--cached] <path>`,
  `git restore --staged <path>`.
- Take one side of a conflict wholesale: `git checkout --ours <path>`,
  `git checkout --theirs <path>`.
- Cherry-pick: `git cherry-pick <sha>` (start a fresh cherry-pick, e.g. `git
  cherry-pick -x <sha>` for a prerequisite), `git cherry-pick
  --continue|--no-edit --continue|--abort|--skip`, `git am --continue|--abort`.
- Commit: `git commit -m "<msg>"`, `git commit -F <file>`, `git commit --amend
  --no-edit`, `git commit --amend -m "<msg>"`, `git commit --amend -F <file>`.
- Build: `devtool build *`.
- Capture build output: `tee <agent_dir>/<name>.log` (only paths under a
  `cve_agent/` directory ending in `.log`), and
  `echo "Exit code: ${PIPESTATUS[0]}"` / `echo "Exit code: $?"` verbatim.

Notes on the allow-list's exact shapes:

- Pathspec commands (`git rm`, `git restore --staged`, `git checkout
  --ours/--theirs`) take **one** path per invocation and the path must not
  start with `-`. Run them once per file instead of passing several.
- `-m` messages must be double-quoted and contain no `"`, `$`, or backtick.
  For a multi-paragraph message, write it to a file and use `git commit -F
  <file>`.
- `git reset` is NOT available in any form. Use `git restore --staged <path>`
  to unstage — it is index-only and leaves the working tree untouched.
- Also unavailable: `git stash`, `git submodule update`, `git checkout <path>`
  (without `--ours`/`--theirs`), and anything with `--no-verify`, `--force`, or
  `--hard`.

The context file path given to you at session start (e.g. `context.md`
under the agent dir) is always valid — read it directly rather than
listing the directory first to confirm it exists.

## Scope Rules

You may ONLY modify files listed in the **Allowed Files** section of the context header.
A git pre-commit hook enforces this — commits with unauthorized files will be rejected.

**NEVER do any of these:**
- `git add .` or `git add -A`
- `git commit --no-verify` or `git cherry-pick --no-verify`
- Cherry-pick, squash, or inline changes that reach files **outside** the
  Allowed Files list (see **Prerequisite / dependency handling** for how to
  bring in an in-scope prerequisite, or when to escalate instead)
- Create or rename files not in the Allowed Files list
- Modify `.gitignore` or any file not in the Allowed Files list
- Run `cve_corrector.py` (the agent handles workflow progression)
- Read files outside the workspace directory
- Use a file-glob / fuzzy-file-discovery tool

### Prerequisite / dependency handling

When the fix references code that is missing or conflicts, first decide WHICH
situation you are in — **most cases are adaptation, not a real dependency.**

**Step 1 — does the referenced symbol already EXIST in the stable branch under
a different name, signature, or location?**
If a function was renamed, a signature changed, a struct member renamed, or a
function moved, the functionality is already present — this is *adaptation, not
a prerequisite*. Adapt the fix in place to match the stable name/shape and do
**NOT** cherry-pick anything. See **Common Conflict Patterns** below. This is
the common case.

**Step 2 — only if the referenced code genuinely does NOT exist in the stable
branch in any form is it a real prerequisite.** Then choose one of:

- **(C) Trivial inline.** The missing piece is a small, self-contained helper,
  macro, or struct field (roughly a few lines). Run `git show <prereq_sha>`
  first to read the real code — never reconstruct it from the commit message —
  then inline just the needed lines into a file already in the Allowed Files
  list. Record the source SHA in your `Conflicts Resolved:` notes.

- **(A) Separate prerequisite patch — the default for anything non-trivial.**
  The missing code is more than a few lines but touches **only files already in
  the Allowed Files list**. Cherry-pick the prerequisite as its own commit
  *before* the fix, recording its upstream origin:
  ```bash
  git show <prereq_sha>            # confirm exactly what it changes and where
  git cherry-pick -x <prereq_sha>  # -x records the upstream SHA in the message
  ```
  Keep it as a **separate commit** — do NOT squash it into the fix.
  cve_corrector emits each commit as its own patch file. A prerequisite is not
  itself a CVE fix, so cve_corrector tags it `Upstream-Status: Backport` only
  (no `CVE:` tag); leave its commit message intact. If the cherry-pick
  conflicts, resolve it the same way you resolve the fix's conflicts.

- **(E) Escalate to human review.** Make **NO** code changes and stop if any of
  these hold:
  - the prerequisite touches files **outside** the Allowed Files list (the
    pre-commit hook will reject the commit — do not try to work around it);
  - it is a large or structural change (a refactor or API redesign);
  - it itself depends on further prerequisites (a dependency chain).

  Write an escalation conclusion and stop — do not mark the CVE not-applicable,
  because it *is* applicable, just not safe to automate:
  ```bash
  cat > "<agent_dir>/conclusion.json" <<'EOF'
  {"needs_human": true, "reason": "<why this prerequisite can't be safely automated, naming the prerequisite SHA and what it changes>"}
  EOF
  ```
  Replace `<agent_dir>` with the actual agent dir path from the context header.
  After writing the file, **stop — make no other changes.**

**Files not in the baseline**: If the upstream commit adds a NEW file that is
in the Allowed Files list, include it — `git cherry-pick` will stage it
automatically. If it conflicts or requires infrastructure not present in the
stable branch, mention it in the commit message as:
`<file>: omitted (depends on <missing infrastructure>)`

Only omit a file if including it would break the build or if it depends on
code/headers/build rules that don't exist in the stable branch.

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
git ls-files -u                             # unmerged stages (1=base, 2=ours, 3=theirs)
git show <upstream_sha>                     # upstream fix intent
git log --oneline -20 -- <file>             # file history for context
```

Resolve each conflicted file. Three shapes come up, in increasing order of
effort — prefer the cheapest one that is correct:

1. **Take one side wholesale.** If the resolution is "keep upstream verbatim"
   or "drop the upstream hunk entirely", do it with git rather than an editor:
   ```bash
   git checkout --theirs <file>   # keep the upstream (cherry-picked) side
   git checkout --ours <file>     # keep the stable-branch side
   ```
2. **Partial resolution.** Neither side is right on its own — edit the file
   with your editing tool, removing all conflict markers.
3. **Drop a path from the cherry-pick.** If upstream deletes a file, mark it
   with `git rm <file>`. If a conflicted path exists only in the upstream
   history and not in this workspace (a submodule/gitlink recorded upstream
   against a tarball-sourced recipe is the common case — confirm with `git
   submodule status`), unstage it instead of trying to materialise it:
   ```bash
   git restore --staged <path>    # index-only; the working tree is untouched
   ```

Then stage the resolutions:
```bash
git add <resolved_files>                    # ONLY allowed files
```

If the cherry-pick as a whole turns out not to apply to this version, `git
cherry-pick --skip` drops it (`--abort` stops the sequence entirely).

If you adapted the patch (not a verbatim cherry-pick), append your backport
notes to `.git/MERGE_MSG` — **read the file first**, keep the original content,
and append your notes after a blank line. Then:
```bash
git cherry-pick --no-edit --continue
```

### 3. Fix Build Errors (exit code 4)
Read the last 50 lines of the build log. If the failing task belongs to a
**different recipe** than the one being patched, **abort immediately** — do not
attempt to fix it. This indicates a pre-existing or environmental issue.
Otherwise, fix the code and amend the commit.

### 4. Fix Test Failures (exit code 3)
Fix the **backported code in the allowed files only**.
If the fix requires changing a file not in the allowed list, stop and
flag for human review. Document which tests failed and what code change
fixed them in the commit message.

### 5. Build Verification (mandatory after every change)
Run the build as a **single command on ONE line** — do NOT split it across
lines and do NOT wrap it in a `BUILD_LOG=` variable. A multi-line submission
matches no allowed command and is rejected outright:
```bash
devtool build <recipe> 2>&1 | tee <agent_dir>/build.log; echo "Exit code: ${PIPESTATUS[0]}"
```
Substitute `<recipe>` and `<agent_dir>` with the values from the context
header (keep it all on one physical line).

Do **not** rewrite this as `devtool build <recipe> > <agent_dir>/build.log
2>&1` — `>` redirection is refused by the command guard (see "Available
Tools"). The `| tee` form is the only way to get a build log.

Read the exit code from the `echo "Exit code: ..."` line, **not** from the
tool's own reported exit status: in a pipeline the tool reports `tee`'s
status, which is `0` even when the build failed. `${PIPESTATUS[0]}` is
`devtool`'s real status — a non-zero value there means the build FAILED,
regardless of what the tool result says.

On failure: `tail -50 <agent_dir>/build.log`, fix, `git commit --amend
--no-edit`, retry.
If `devtool build` logs are insufficient, check Yocto task logs at:
`<yocto_tmp>/work/<arch>/<recipe>/*/temp/log.do_compile`
(paths are in the context header).
On success: **stop — your work is done.**

For cross-compilation: use `bitbake -c devshell <recipe>`, never run
make/cmake/gcc directly.

## Resolution Principles

- **Minimal changes only** — smallest adaptation to make the fix work on stable
- **Preserve upstream intent** — adapt APIs/signatures, never change fix logic
- **Match surrounding whitespace** — use the same indentation style (tabs vs spaces, alignment width) as the surrounding code in the stable branch, not the upstream patch
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

**IMPORTANT: Preserve the original upstream commit message.** The `.git/MERGE_MSG`
file contains the original upstream commit subject and body. You MUST keep it
intact and only **append** your backport notes after it. Never replace or rewrite
the original message.

**If this is a retry** (e.g. a build or ptest failure triggered another
session after conflicts were already resolved), run `git log -1 --format=%B`
first. If it already contains a `Conflicts Resolved:` block from a previous
attempt, **update that existing block in place** — amend it to reflect the
current state of the resolution — rather than appending a second block. The
final commit message must contain exactly one `Conflicts Resolved:` block
and one `Assisted-by:` trailer.

Only append notes if you adapted the patch. Use EXACTLY this markdown format — no
alternative headers like "Conflict resolution notes:" or "Backport changes:".

Append the following block after the original commit message (separated by a
blank line):

```
Conflicts Resolved:

<file> (<N> conflict[s]):
- <What was changed and why, referencing stable vs upstream differences.>

<file> (<N> conflict[s]):
- <What was changed and why.>
```

Rules:
- **Never delete or rewrite the original subject line or body** from `.git/MERGE_MSG`
- Append your notes after the existing message, separated by a blank line
- `Conflicts Resolved` owns all technical detail: list ONLY files that had
  conflicts or required adaptation (skip clean files); for each, state the
  conflict count and describe the adaptation with specific function names,
  types, APIs, and why the stable branch differs
- **No duplication**: each fact (what changed, in which function, why) must
  appear exactly once
- Omitted files: `<file>: omitted (not in branch)`
- Do NOT add a "Changes from upstream" section (the agent generates that)
- If you adapted the patch (not a verbatim cherry-pick), add a trailer line
  after a blank line at the end of the commit message:
  `Assisted-by: <backend>:<model>` where `<backend>` and `<model>` are the
  **Backend** and **Model** values from the context header (e.g.
  `Assisted-by: kiro:claude-sonnet-4-20250514`)
