### Resolve Conflicts (exit code 1)
```bash
git status && git diff                      # examine conflicts
git ls-files -u                             # unmerged stages (1=base, 2=ours, 3=theirs)
git show <upstream_sha>                     # upstream fix intent
git log --oneline -20 -- <file>             # file history for context
```

Resolve each conflicted file. Three shapes come up, cheapest-correct first:

1. **Take one side wholesale** — "keep upstream verbatim" or "drop the upstream
   hunk": use git, not an editor:
   ```bash
   git checkout --theirs <file>   # keep the upstream (cherry-picked) side
   git checkout --ours <file>     # keep the stable-branch side
   ```
   Beware `--theirs` on a file that diverged heavily: it imports upstream's
   *whole* file, which may reference APIs this stable branch does not have, and
   the build then fails on hundreds of unrelated errors. If that happens,
   `git checkout original-version -- <file>` puts the stable file back, and you
   can port just the fix's own hunks onto it.
2. **Partial resolution** — neither side is right alone: edit the file with your
   editing tool, removing all conflict markers.
3. **Drop a path** — if upstream deletes a file, `git rm <file>`. If a conflicted
   path exists only in upstream history, not this workspace (a submodule/gitlink
   recorded upstream against a tarball-sourced recipe — confirm with `git
   submodule status`), unstage it rather than materialise it:
   ```bash
   git restore --staged <path>    # index-only; working tree untouched
   ```

Then stage ONLY allowed files (`git add <resolved_files>`). If the cherry-pick
as a whole does not apply, `git cherry-pick --skip` drops it (`--abort` stops
the sequence). If the cherry-pick has **already been committed** and you need to
back it out, do not reach for `git reset`/`git revert` — they are not available.
See **Undoing a Bad Cherry-Pick** in the core instructions for the four cases
and the sanctioned recovery for each.

If you adapted the patch, append backport notes to `.git/MERGE_MSG` (preserve
the original message — see Commit Message Format), then:
```bash
git cherry-pick --no-edit --continue
```
Keep each file's stanza inside the enforced budget — at most 3 bullets and ~40
words, one short clause per adaptation, in the style of the `Commit Note` column
below. A `commit-msg` hook rejects the commit past 3 bullets or 48 words; if that
happens, shorten `.git/MERGE_MSG` and re-run `--continue` (never `--abort` or
`--skip`).

### Common Conflict Patterns

| Pattern | Resolution | Commit Note |
|---|---|---|
| Function signature changed | Keep fix logic, adapt to stable signature | `Adapted foo_v2() to foo_v1() API` |
| Struct member renamed | Use stable member name with upstream logic | `Member renamed netdev→ndev in original patch` |
| Function moved to different file | Apply fix where function lives in stable | `Function in old_file.c in original patch` |
| Missing helper function | Inline it or use stable equivalent | `Inlined helper_foo() (not in stable)` |
