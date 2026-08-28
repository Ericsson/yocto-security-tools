### Fix Build Errors (exit code 4)

Reproduce and read the failure with the Build Verification command and log
handling from the core instructions. Two build-specific cases:

**Stale build state — recover, do NOT escalate.** If the build fails because an
sstate-restored/skipped task left a file it should have generated missing, the
recipe's cached state is stale — not a defect in your patch. Signatures: `cp:
cannot stat '.config.orig'` (or any "No such file or directory" for a
configure-generated file); or a log showing only `do_compile` ran while
`do_configure` was skipped. Recover before concluding it is environmental:
```bash
bitbake -c cleansstate <recipe>
```

**Different recipe.** If the failing task belongs to a recipe other than the one
being patched, **abort immediately** — it is pre-existing/environmental.

Otherwise fix the code, amend the commit, and re-run the build. If you also need
to mention the fix in the `Conflicts Resolved:` block, keep it to one bullet in
that file's stanza (`<file> (0 conflicts):` if the file had no merge conflict) —
the per-file budget applies to the amended block too.
