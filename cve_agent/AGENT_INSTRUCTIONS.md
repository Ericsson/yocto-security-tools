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
- **Creating or editing any file goes through your file-writing/editing
  tool — never the shell.** The command runner's only file-writing power is
  capturing build output to a `.log` file via `tee` (above). Everything else
  you need to write or change — `conclusion.json`, source-file edits, and
  appending your notes to `.git/MERGE_MSG` — must use your file-writing/editing
  tool (its name is in the preamble that precedes these instructions). Do NOT
  use `cat > file`, a heredoc (`<< 'EOF'`), or `tee` to write these: `>`/`>>`
  are refused outright and `tee` is limited to `.log` capture, so those forms
  will fail and leave the file unwritten.
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

- Inspect: `git status`, `git status --porcelain`,
  `git status --porcelain -- <path>...`,
  `git diff[ *]`, `git log *`,
  `git show *`, `git rev-parse *`, `git merge-base *`, `git ls-files[ *]`
  (`git ls-files -u` lists the unmerged stage entries of a conflict directly),
  `git submodule status[ *]` (diagnoses a gitlink recorded upstream that does
  not exist in a tarball-sourced workspace), `cat *`, `head *`, `tail *`,
  `wc *`, `sed -n '<start>,<end>p' [<path>]` (print one line range — the only
  `sed` form allowed; `sed -i` and `s///` are rejected).
- Inspect refs and objects (all read-only): `git branch`, `git branch -a`,
  `git branch [-a|-r] --contains <sha>` (which branches hold a commit),
  `git describe [--tags] <rev>`, `git show-ref`, `git ls-tree *`,
  `git cat-file -t|-s|-p <sha>` (confirm an object exists before using it),
  `git grep *`. The mutating forms — `git branch -f/-d/-D/-m`,
  `git update-ref` — are NOT available.
- Read a file **as committed** rather than as it sits in the working tree:
  `git show HEAD:<path>` (or `git show <sha>:<path>` for any other commit) —
  e.g. to see the file exactly as your own resolution committed it, or its
  pre-conflict content at `original-version`. Use your file-reading tool for
  the working-tree copy; use this when the committed content is what matters.
- Stage / unstage: `git add *`, `git rm [--cached] <path>`,
  `git restore --staged <path>...`.
- Take one side of a conflict wholesale: `git checkout --ours <path>...`,
  `git checkout --theirs <path>...`.
- Cherry-pick: `git cherry-pick <sha>` (start a fresh cherry-pick, e.g. `git
  cherry-pick -x <sha>` for a prerequisite), `git cherry-pick
  --continue|--no-edit --continue|--abort|--skip`, `git am --continue|--abort`.
- Commit: `git commit -m "<msg>"`, `git commit -F <file>`, `git commit --amend
  --no-edit`, `git commit --amend -m "<msg>"`, `git commit --amend -F <file>`.
- Build: `devtool build *`.
- Recover stale build state (see the Build Error phase instructions in
  `context.md`): `bitbake -c cleansstate <recipe>` — a
  single recipe name, no chaining. Forces the recipe's tasks to re-run from
  scratch (e.g. so `do_configure` regenerates files a stale sstate restore
  left missing). No other `bitbake` subcommand is permitted.
- Capture build output: `tee <agent_dir>/<name>.log` (only paths under a
  `cve_agent/` directory ending in `.log`), and an `echo` whose double-quoted
  message ends in `$?` or `${PIPESTATUS[0]}` — e.g.
  `echo "Exit code: ${PIPESTATUS[0]}"`. `echo` with any other content is
  rejected; it exists only to surface an exit code.

Notes on the allow-list's exact shapes:

- Pathspec commands accept **several** paths in one call
  (`git restore --staged a.c b.c`, `git checkout --theirs a.c b.c`,
  `git status --porcelain -- a.c b.c`), but every path must be
  whitespace-separated and must not start with `-`. `git rm` remains one path
  per invocation. A trailing flag such as `git restore --staged a.c --worktree`
  is therefore rejected — it is read as a path starting with `-`.
- `-m` messages must be double-quoted and contain no `"`, `$`, or backtick.
  For a multi-paragraph message, write it to a file and use `git commit -F
  <file>`.
- `git reset` is NOT available in any form. Use `git restore --staged <path>`
  to unstage — it is index-only and leaves the working tree untouched. To back
  out a cherry-pick, see **Undoing a Bad Cherry-Pick**.
- Also unavailable: `git stash`, `git submodule update`, `git checkout <path>`
  (without `--ours`/`--theirs`), `git revert`, `git update-ref`,
  `git branch -f`, and anything with `--no-verify`, `--force`, or `--hard`.

The context file path given to you at session start (e.g. `context.md`
under the agent dir) is always valid — read it directly rather than
listing the directory first to confirm it exists.

## Scope Rules

You may ONLY modify files listed in the **Allowed Files** section of the context header.
A git pre-commit hook enforces this — commits with unauthorized files will be rejected.

Two hooks guard your commits, and they fail for different reasons — read the
rejection message before reacting:

| Hook | Rejects when | Fix |
|---|---|---|
| `pre-commit` | a staged file is outside **Allowed Files** | unstage it (`git restore --staged <path>`), or escalate — never widen your scope |
| `commit-msg` | a `Conflicts Resolved:` file stanza is over the length budget | shorten the notes, rewrite the message file, re-run the same command — never `--amend --no-edit` (see **Commit Message Format**) |

**Untracked files from tarball extraction:** The workspace will contain many
untracked files (configure, Makefile.in, m4/*.m4, aclocal.m4, etc.) copied
from the devtool branch. These are generated autotools/build files from the
release tarball that don't exist in the upstream git history. **Ignore them** —
do not stage, commit, or worry about them. They are intentionally untracked
and exist only so `devtool build` succeeds.

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
**NOT** cherry-pick anything. See **Common Conflict Patterns** in the
conflict-resolution instructions. This is
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
  because it *is* applicable, just not safe to automate. Create
  `<agent_dir>/conclusion.json` **with your file-writing tool** (not the shell —
  see Available Tools) with these contents:
  ```json
  {"needs_human": true, "reason": "<why this prerequisite can't be safely automated, naming the prerequisite SHA and what it changes>"}
  ```
  Replace `<agent_dir>` with the actual agent dir path from the context header.
  After writing the file, **stop — make no other changes.**

  **Suggesting a commit for a scope extension.** When the blocker is a specific
  companion or prerequisite commit that touches files **outside** your Allowed
  Files list — for example, a follow-up that updates a testsuite/ file to match
  new behavior, or a prerequisite you may not cherry-pick because its files are
  out of scope — name it in a `suggested_commits` array. A human (or `--trust`)
  can then accept it, and the backport re-runs with that commit added to the
  fix chain and your allowed-files scope widened to include its files. Create
  `<agent_dir>/conclusion.json` **with your file-writing tool** with these
  contents:
  ```json
  {"needs_human": true,
   "reason": "ptest regresses because upstream <sha> updates testsuite/tar.tests to match the new hardlink-stripping behavior, but that file is outside my Allowed Files",
   "suggested_commits": ["<sha>"]}
  ```
  Each entry is a **full commit SHA** (preferred) or a full commit **URL** in
  the same repository as the fix. List them in application order (earliest
  prerequisite first). Only suggest commits you have confirmed exist and are
  relevant — verify with `git show <sha>` first. If you cannot name a concrete
  commit, omit `suggested_commits` and escalate with the reason alone.
  After writing the file, **stop — make no other changes.**

**Files not in the baseline**: If the upstream commit adds a NEW file that is
in the Allowed Files list, include it — `git cherry-pick` will stage it
automatically. If it conflicts or requires infrastructure not present in the
stable branch, mention it in the commit message with the omitted-file form from
**Commit Message Format**:
`<file>: omitted (depends on <missing infrastructure>)`

Only omit a file if including it would break the build or if it depends on
code/headers/build rules that don't exist in the stable branch.

## Undoing a Bad Cherry-Pick

`git reset`, `git revert`, `git update-ref`, `git branch -f` and
`git checkout <commit>` are all unavailable — **you cannot move `HEAD` or
rewrite history, and no variation of those commands will work.** Do not spend
turns probing for one. Identify which case you are in and follow it.

**Case 1 — the cherry-pick is still in progress.** Confirm with `git status`
(it reports "You are currently cherry-picking"), then:
```bash
git cherry-pick --abort     # discard this cherry-pick entirely
git cherry-pick --skip      # drop just this commit, continue the sequence
```
This is a true, complete undo. Always prefer it while a cherry-pick is in
progress.

**Case 2 — already committed, but only the content is wrong.** You do not need
to undo the commit. Correct the tree and amend in place:
```bash
git status --porcelain      # what is staged / modified
git show --stat HEAD        # what the commit currently contains
```
Fix the file with your file-editing tool, then `git add <path>...` and
`git commit --amend --no-edit`. The commit keeps its message and position;
only its content changes. This covers almost every "the cherry-pick brought in
too much" situation, because the fix is to *delete* the unwanted hunks.

**Case 3 — you need a file back exactly as it was before the cherry-pick.**
Its pre-cherry-pick content is at the `original-version` tag. Capture it to a
log in the agent dir, read that with your file-reading tool, and write the
needed parts back with your file-editing tool:
```bash
git show original-version:<path> | tee <agent_dir>/pre-image.log
```
Then `git add <path>` and `git commit --amend --no-edit`. Use targeted
replacements against the pre-image rather than retyping a large file. `git
restore <path>` (without `--staged`) is not available, so this `tee` +
file-tool route is the sanctioned way to recover committed content.

**Case 4 — the wrong commit was cherry-picked altogether** (wrong SHA, or a
commit vastly larger than the upstream fix). Confirm the mismatch first:
```bash
git log original-version..HEAD --oneline   # what actually got applied
git show --stat HEAD                       # size of what was applied
git show --stat <upstream_sha>              # size of the intended fix
```
If the applied commit is a different change rather than an adaptable version of
the intended fix, do **NOT** try to reconstruct the tree by hand — that
produces a large, unreviewable diff. Stop and escalate: write
`<agent_dir>/conclusion.json` **with your file-writing tool** —
```json
{"needs_human": true, "reason": "cherry-picked <applied_sha> (<N> lines / <M> files) instead of the intended fix <upstream_sha> (<n> lines); a committed cherry-pick cannot be undone with the available commands"}
```
— then **stop and make no other changes.** Escalating here is the correct
outcome, not a failure.

## Workflow

### 1. Analyse (always)
```bash
git log original-version..HEAD --oneline   # what was applied
git show HEAD                               # understand the fix
```
If the patch is incompatible with the stable base, adapt it.

If the CVE fix is **not applicable** to this version (e.g. the vulnerable code
path, function, struct, or feature does not exist in the stable branch), do NOT
make any code changes. Instead, write a conclusion file **with your
file-writing tool** (not the shell — see Available Tools) at
`<agent_dir>/conclusion.json` with these contents:

```json
{"not_applicable": true, "reason": "<one-line explanation of why the CVE does not apply>"}
```

Replace `<agent_dir>` with the actual agent dir path from the context header.
The reason should be specific — mention the missing function, struct, code path,
or feature and the version. Example:
`"PBMAC1 infrastructure (PBMAC1PARAM, PBMAC1_get1_pbkdf2_param) does not exist in 3.2.6; CVE-2025-11187 is not applicable to this version"`

After writing the conclusion file, **stop — do not make any other changes.**

> The phase-specific steps for the current run — resolving conflicts (exit 1),
> fixing build errors (exit 4), or fixing ptest regressions (exit 3) — are
> provided in the `context.md` for this session, under its "Instructions"
> section. Follow those together with the always-applicable rules here.

### 5. Build Verification (mandatory after every change)
**You MUST verify the build passes before finishing.** Do not declare success
without confirming `devtool build` exits with code 0. This is a hard
requirement — the orchestrator will reject your session if the build still
fails.

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

**Handling the output:** The command will produce hundreds of lines of
bitbake progress output (NOTE: Starting bitbake server, Parsing recipes,
Sstate summary, etc.). **Ignore all of this.** Do NOT read or process the
tool's stdout — it pollutes your context for no benefit. The only line that
matters is the **last line**: `Exit code: <N>`.

Read the exit code from the `echo "Exit code: ..."` line, **not** from the
tool's own reported exit status: in a pipeline the tool reports `tee`'s
status, which is `0` even when the build failed. `${PIPESTATUS[0]}` is
`devtool`'s real status — a non-zero value there means the build FAILED,
regardless of what the tool result says.

**After running the build:**
- **Exit code 0**: the build passed. **Stop — your work is done.** Do not
  read or tail the log file.
- **Exit code non-zero**: the build failed. Read ONLY the error:
  `tail -50 <agent_dir>/build.log`. Fix the code, `git commit --amend
  --no-edit`, and re-run the build.
  (`--amend --no-edit` is right here — you are fixing *code*, not the message.
  Never use it to recover from a `commit-msg` note-budget rejection: it
  resubmits the same rejected message. See **Commit Message Format**.)
  If `devtool build` logs are insufficient, check Yocto task logs at:
  `<yocto_tmp>/work/<arch>/<recipe>/*/temp/log.do_compile`
  (paths are in the context header).

For cross-compilation: use `bitbake -c devshell <recipe>`, never run
make/cmake/gcc directly.

## Resolution Principles

- **Minimal changes only** — smallest adaptation to make the fix work on stable
- **Preserve upstream intent** — adapt APIs/signatures, never change fix logic
- **Match surrounding whitespace** — use the same indentation style (tabs vs spaces, alignment width) as the surrounding code in the stable branch, not the upstream patch
- **Check dependencies** — look for `Link:` in commit, prerequisite patches
- **If uncertain, stop** — flag for human review rather than guess

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
and one `Assisted-by:` trailer. The length budget below applies to the updated
block exactly as it does to a fresh one — an amend is re-checked by the hook.

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
- **Be succinct — enforced hard limit**: at most 3 bullet points and ~40 words
  per file. A `commit-msg` hook counts them: more than 3 bullets, or more than
  48 words, and **your commit is rejected**. Wrapping is not penalised — a
  bullet that spans several physical lines still counts as one bullet. State
  only the *adaptation*: what changed and the stable-vs-upstream reason. Do NOT
  include the investigation that led you there — no "checked upstream history",
  no "no companion commit exists", no describing how unrelated code paths handle
  the case, no test-run counts or step-by-step narration. If you cherry-picked
  or suggested a companion commit, name it in one clause. The `Commit Note`
  column of **Common Conflict Patterns** (in the conflict-resolution
  instructions) shows the target length: one short clause per adaptation.
- **Every line inside the block must sit under a `<file> (<N> conflict[s]):`
  header.** Text under no header is charged to the whole block and rejected as
  `(notes outside any file stanza)`. For a file you changed that had **no merge
  conflict** — e.g. a build or ptest fix — open its stanza with
  `<file> (0 conflicts):`.
- **If the hook rejects your commit**: nothing was lost — the cherry-pick is
  still in progress and `.git/MERGE_MSG` is untouched. Shorten the notes in
  `.git/MERGE_MSG` (or in your `-F` message file) with your file-writing tool,
  then re-run the same command (`git cherry-pick --no-edit --continue`, or
  `git commit --amend -F <file>`). Do **NOT** run `git commit --amend
  --no-edit` to recover — it resubmits the identical rejected message and the
  hook will reject it again, forever. Do **NOT** run `git cherry-pick --abort`
  or `--skip`, and do not try to bypass the hook.
- Omitted files: `<file>: omitted (<why>)` — e.g.
  `<file>: omitted (not in branch)` or
  `<file>: omitted (depends on <missing infrastructure>)`. These one-liners are
  exempt from the length budget.
- Do NOT add a "Changes from upstream" section (the agent generates that)
- If you adapted the patch (not a verbatim cherry-pick), add a trailer line
  after a blank line at the end of the commit message:
  `Assisted-by: <backend>:<model>` where `<backend>` and `<model>` are the
  **Backend** and **Model** values from the context header (e.g.
  `Assisted-by: kiro:claude-sonnet-4-20250514`)
