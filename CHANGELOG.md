<!-- SPDX-License-Identifier: MIT -->
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.5] - 2026-08-13

### Added

- **cve-corrector**: `--sign-off` flag (default off) to opt in to a
  local `Signed-off-by` trailer on generated patches/commits. Previously
  `get_git_user_info()` was called unconditionally, stamping every patch
  with whatever git identity resolved in the invoking shell regardless of
  review — a fabricated DCO certification, especially in unattended
  (`--yes`/`--skip-ptest`/`--skip-build`) runs. A signoff already present
  in the upstream commit being backported is preserved either way.
- **cve-agent**: `--sign-off`, forwarded to the `cve-corrector` subprocess
  across the normal, `--continue`, and `--mark-not-applicable` paths.
  Rejected in combination with `--trust`, since auto-approving AI changes
  and certifying a DCO nobody reviewed is the same problem this flag fixes.
- **cve-corrector**: `--premirror` option to fetch upstream history from a
  bitbake-style git mirror (host/path joined by dots, `.git` suffix
  stripped) before falling back to the original upstream URL.
- **cve-corrector**: Preserve the test-modified `local.conf` as
  `local.conf.ptest-debug` when ptest/testimage fails, instead of
  silently restoring the original and discarding the debug state.
- **cve-corrector**: Print build-failure instructions (workspace path,
  `devtool build` command, git amend workflow, `--continue` hint) when a
  build or ptest step fails.
- **cve-corrector**: Detect and remove upstream git-only files that act as
  `configure.ac` sentinels enabling extra test dependencies absent from
  the release tarball (e.g. gnutls's `full_test_suite`), avoiding spurious
  build failures from a git-vs-tarball dependency mismatch.
- **cve-corrector**: Honour the `cpe:` scope in `CVE_STATUS` values, so a
  distro-wide scoped entry (e.g. oe-core's `cve-extra-exclusions.inc`) no
  longer silently marks a CVE Ignored/Patched for every recipe in the
  build — only for recipes whose `CVE_PRODUCT` matches the scope.
- **cve-agent**: Escalate an accepted scope extension (a companion commit
  outside the session's allowed files, e.g. a testsuite update) by
  appending it to the `--fix-url` chain and re-running, auto-accepted
  under `--trust` or prompted when interactive.
- **cve-agent**: Report per-session kiro-cli credit cost, parsed from the
  `Credits: X • Time: Y` summary line, aggregated per CVE and surfaced in
  the single-CVE summary, batch per-CVE lines, batch grand total, agent
  log, and saved results file. Only the kiro backend populates this.

### Changed

- **cve-agent**: Split the monolithic `AGENT_INSTRUCTIONS.md` into a
  phase-independent core plus per-phase fragments (conflict/build/ptest)
  under `cve_agent/instructions/`, embedding only the fragment matching
  the corrector's exit code into the AI context instead of the whole
  manual.
- **cve-agent**: Check out the CVE branch (not the throwaway devtool
  branch) before starting an AI session, and restore devtool-tracked
  tarball files, so AI fixes land where the workflow expects instead of
  being silently discarded on the next resume.
- **cve-agent**: Skip the human-approval prompt for a build/ptest AI
  session that made no changes (unchanged `HEAD`), instead of asking for
  approval twice on the same fix.
- **cve-agent**: Allow scoped `git status --porcelain -- <path>` and a
  single-recipe `bitbake -c cleansstate <recipe>` (no chaining), so the
  agent can recover stale sstate-restored build state without widening
  the command surface for `-c clean` or arbitrary bitbake targets.
- **cve-corrector**: Reset the devtool branch to its patched base before
  re-transferring CVE commits on a build/ptest resume, so an AI-amended
  fix is re-applied cleanly instead of being treated as already applied.
- **cve-corrector**: Pair workspace `git clean -fdx` with
  `bitbake -c cleansstate` before a build, so a stale `do_configure`
  sstate restore no longer leaves regenerated run-time artifacts missing.
- **bump-version.yml**: Bump the minor version component instead of the
  patch component for post-release changes, since they now include
  features as well as fixes.
- Routine dependency bump: `step-security/harden-runner` and
  `github/codeql-action/*` GitHub Actions.

### Fixed

- **cve-corrector**: Fix `create_layer_commit` staging a new CVE patch
  without its recipe `.bb` file when the recipe's directory isn't named
  after the recipe (e.g. acl under `recipes-support/attr/`), and when the
  `.bb`/`.inc` file had no prior `file://` entry to match against.
- **cve-corrector**: Don't rename a pre-existing wildcard bbappend
  (`{recipe}_%.bbappend`) into a version-pinned one when devtool merges a
  new patch into it in place; only rename bbappends devtool just created.
- **cve-corrector**: Fix `_append_src_uri_entries` selecting a trailing
  scoped `SRC_URI:append:class-*` override as the merge target instead of
  the recipe's real `SRC_URI` block, which produced invalid bitbake syntax
  and broke parsing for the whole build.
- **recipe_ops**: Skip CVE patches already listed in `SRC_URI`, fixing a
  duplicate entry when `restore_bbappend_extras` had already merged the
  same patch earlier in the same run.
- **cve-corrector**: Insert CVE patches into the unscoped `SRC_URI:append`
  form (falling back to a sibling `.inc` file, then a new
  `SRC_URI:append` line) instead of a scoped
  `SRC_URI:append:class-nativesdk` override, which previously scoped the
  patch to a single class in recipes like binutils.
- **cve-corrector**: Map version-based not-applicable reasons to
  `fixed-version` instead of `not-applicable-config`, and filter
  non-release git tags (branchpoint, rc, alpha, beta, dev, snapshot,
  nightly, start, base, root, fork, merge) from blame analysis.
- **cve-corrector**: Match mixed-separator version tags (e.g.
  `binutils-2_46.1` against version `2.46.1`) in `find_exact_tag`.
- **url-parser**: Fix gitweb URL deduction for sourceware links that omit
  the `;a=` action parameter, which previously fell through to a
  path-based handler and extracted `gitweb.cgi` instead of the real repo.
- **cve-corrector**: Fail soft (return `None`) instead of crashing with an
  uncaught `FileNotFoundError` when `_git_commit_subject()` runs after
  the devtool workspace has already been removed by `--bbappend` mode's
  reset step.
- **shared**: Keep TLS trust store environment variables
  (`GIT_SSL_CAINFO` and equivalents) in the git env allowlist, fixing
  upstream fetch failures when git comes from a relocatable SDK such as
  Yocto buildtools-extended.
- **cve-corrector**: Log git's stderr when an upstream fetch fails with no
  alternate protocol to retry, instead of losing the actual cause and
  surfacing only a generic "bad object" / conflict error much later.
- **cve-corrector**: Fix ptest log glob and STOP-marker detection to match
  the real timestamped `ptest_log.*` / `ptest-runner.log` layout, and
  handle a truncated pre-patch ptest with zero results as an unusable
  baseline instead of blocking the workflow.
- **cve-agent**: Fix `_find_state_file` reading the corrector state one
  directory too high, which silently dropped ptest before/after results
  from the AI context.

## [1.0.4] - 2026-08-03

### Added

- **cve-corrector** / **cve-agent**: `--fix-url` is now repeatable; two or
  more URLs are merged into one ordered, dependent commit chain that must
  apply in full (no falling back to a single commit or the least-conflicting
  one). Use this for CVEs fixed by a short series of follow-up commits, e.g.
  acl's CVE-2026-XXXXX.
- **cve-agent**: Allow the git commands the documented backport workflow needs:
  `git restore --staged <path>` (index-only unstage), `git checkout
  --ours/--theirs <path>`, `git rm [--cached] <path>`, `git commit -m/-F` and
  `git commit --amend --no-edit/-m/-F`, `git cherry-pick --skip`, plus the
  read-only diagnostics `git ls-files` and `git submodule status`.
- **cve-metadata-extractor**: Checkpoint completed results periodically and
  on interruption (Ctrl-C, exceptions), writing atomically so a failed or
  interrupted save can't truncate prior output. Controlled by
  `--checkpoint-interval` (default 60s; 0 disables periodic saves).

### Changed

- **cve-agent**: Narrow the `fs_write` deny rule `**/tests/**` to this
  project's own test directories, so a recipe's regression tests (e.g. jq's
  `tests/jq.test`) can be edited when they are in the session's Allowed Files
  list. `git reset`, `git stash`, `git submodule update`, `git checkout
  <path>`, and any `--no-verify`/`--force`/`--hard` form remain rejected.
- **cve-agent**: Disable the session timeout in `-i`/`--interactive` mode,
  since a human decides when an interactive session ends. Non-interactive
  (CI) runs still enforce `--session-timeout`.

### Fixed

- **cve-corrector**: Fix Savannah URL deduction to use the `https.git.` host
  and cover `nongnu.org`, so cgit links like
  `cgit.git.savannah.nongnu.org` resolve to a fetchable repo URL instead of
  a redirect-only host.
- **cve-corrector**: Don't clobber `HEAD` symlinks when copying files missing
  from the devtool branch — release tarballs dereference symlinks into real
  directories, and copying those out of devtool previously overwrote the
  symlink with a real directory and stalled every subsequent cherry-pick.
- **cve-corrector**: Initialize git submodules before cherry-picking when a
  recipe is built from a tarball but the upstream repo has submodules (e.g.
  jq's `oniguruma`), preventing a dirty working tree from blocking
  cherry-pick.
- **cve-corrector**: Fix ptest result parsing to match the real
  `PASS:`/`FAIL:`/`SKIP:` (single-colon) log format instead of a
  `PASSED:`/`FAILED:`/`SKIPPED:` format that never matched, which made every
  run report "no regression" regardless of actual results. Also detect tests
  aborted by a per-test timeout and flag incomplete/unreliable runs.
- **cve-agent**: Fix the mandatory build-verification command being rejected
  by the kiro-cli command guard (file redirection is refused unconditionally,
  and compound commands are matched part-by-part); switch to a `tee`-based
  form and read the exit code from `PIPESTATUS[0]`.
- **cve-agent**: Escalate `git checkout` to a forced checkout/reset/clean
  sequence when the devtool workspace is dirty (e.g. regenerated autotools
  files, modified submodule content), instead of silently failing to revert
  unauthorized changes.
- **shared**: Use replace-on-decode (`errors='replace'`) instead of strict
  UTF-8 for external subprocess/file text (git diffs, commit messages, ptest
  logs), so a single non-UTF-8 byte no longer aborts the whole run.
- **shared**: Restrict commit-hash extraction to URLs that structurally
  denote a commit object, eliminating false positives from advisory UUIDs,
  vendor doc IDs, Gerrit change IDs, and repository names that happened to
  look like a hex hash.
- **shared**: Downgrade `git blame` "no such path" warnings to debug level
  for files newly added by the fix commit itself, rather than logging them
  as blame failures.
- **readme**: Replace dead Kiro-cli links.

## [1.0.3] - 2026-07-27

### Added

- **cve-corrector**: Skip CVE if `CVE_STATUS` marks it Ignored or Patched.
- **cve-corrector**: Fail fast when CVE patch is already present in `SRC_URI`.
- **cve-corrector**: `--skip-source` flag to ignore fix commits by source.
- **cve-corrector**: Tag exported patches with release corename.
- **cve-agent**: `-i` short flag for `--interactive`.
- **cve-agent**: Harden and generalize non-interactive backend invocation.
- **cve-agent**: Optional interdiff review of upstream vs backport adaptation.
- **cve-agent**: Record interdiff reproduction artifacts in review diff.
- **cve-agent**: Escalate applicable-but-unsafe backports to human review.

### Changed

- **cve-agent**: Set `claude-sonnet-5` as the default model for the Claude backend.
- **security**: Adopt Ericsson OSPO `SECURITY.md` template with explicit scope.
- **ci**: Pin `publish.yml` build deps by hash for OpenSSF Scorecard compliance.

### Fixed

- **cve-corrector**: Derive devtool commit list from `git cherry`, not a count.
- **cve-corrector**: Skip meta-layer deduction when CVE is already applied.
- **cve-corrector**: Omit CVE tag on prerequisite patches.
- **cve-agent**: Silence expected "workspace not found" message.
- **cve-agent**: Dedupe repeated backport-note blocks and standardize format.
- **shared**: Handle non-UTF-8 recipe files during meta-layer scans.

## [1.0.2] - 2026-07-20

### Added

- **cve-agent**: `claude` backend that drives the Claude Code CLI directly, selectable with `--backend claude` (kiro remains the default). Model names are mapped to Claude aliases, and the backend passes through Anthropic/cloud auth environment variables.
- **tests**: integration test runner accepts `AGENT_BACKEND` / `AGENT_MODEL` environment variables so the agent test cases can run against any registered backend (e.g. `AGENT_BACKEND=claude`), plus opt-in live smoke tests (`CLAUDE_LIVE_TESTS=1 pytest -m live`) that verify the emitted CLI flags and a real conflict resolution against an installed `claude` binary.
- **tests**: CLI contract tests using a stub `claude` executable (argv/env/cwd recording, no API key needed) and guard-parity tests that fail if the Claude backend's tool allow/deny lists drift from the kiro agent manifest.
- **docs**: CI, OpenSSF Best Practices, OpenSSF Scorecard, PyPI, Downloads, Ruff, and mypy status badges added to the README.

### Changed

- **security**: `SECURITY.md` now directs reporters to GitHub's "Report a vulnerability" button instead of email.

### Fixed

- **cve-agent**: don't credit a killed Claude session as resolved.
- **cve-agent**: register the Claude backend lazily to break a circular import.

## [1.0.1] - 2026-07-03

### Fixed

- **cve-corrector**: Run meta-layer branch check at workflow start, failing fast on detached HEAD
- **cve-corrector**: Retry git fetch with alternate transport protocol (https↔git) when initial fetch fails
- **cve-corrector**: Always compare patch-deduced upstream URL against recipe SRC_URI to detect supply-chain mismatches

### Added

- **cve-corrector**: Fetch fix-commit repository as a secondary remote when fix commits live in a different repo than the recipe SRC_URI
- **cve-corrector**: Enrich commit messages with fix provenance references and source attribution
- **cve-metadata-extractor**: Deduce sourceware repository URLs from cgit-style commit links
- **ci**: Add GitHub attestations to the release workflow

## [1.0.0] - 2026-05-25

Initial release of standalone CVE management tools for Yocto/OpenEmbedded.

### Added

- **cve-metadata-extractor**: Find fix commits from multiple public sources (Debian, OSV, CVEList V5, Ubuntu)
- **cve-corrector**: Automate CVE backporting to Yocto recipes via devtool
- **cve-agent**: AI-assisted conflict resolution for CVE backports
- Plugin system for custom CVE sources and AI backends (`extra/` directory)
- XDG Base Directory compliant data/cache storage
- Minimal dependencies: only `requests` and `packaging`
- Python 3.10+ supported
- GitHub Actions CI (lint, type check, tests across Python 3.10–3.13)
- Automated publishing to PyPI via Trusted Publishing (OIDC)
- Pre-commit hooks (ruff, mypy)

[1.0.5]: https://github.com/Ericsson/yocto-security-tools/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/Ericsson/yocto-security-tools/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/Ericsson/yocto-security-tools/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/Ericsson/yocto-security-tools/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Ericsson/yocto-security-tools/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Ericsson/yocto-security-tools/releases/tag/v1.0.0
