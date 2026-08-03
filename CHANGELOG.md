<!-- SPDX-License-Identifier: MIT -->
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[1.0.4]: https://github.com/Ericsson/yocto-security-tools/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/Ericsson/yocto-security-tools/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/Ericsson/yocto-security-tools/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Ericsson/yocto-security-tools/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Ericsson/yocto-security-tools/releases/tag/v1.0.0
