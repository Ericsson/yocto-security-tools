<!-- SPDX-License-Identifier: MIT -->
# Security Policy

If you believe you have found a security vulnerability in an Ericsson-managed
repository, please report it to us as described below.

## Reporting a vulnerability

**Please do not open a public issue, pull request, or discussion for a security
problem.**

Instead, use the "Report a vulnerability" button on this repository's Security
tab, or go directly to:

<https://github.com/Ericsson/yocto-security-tools/security/advisories/new>

This keeps the report private, lets us collaborate with you on a draft
advisory, and supports private patch development.

We aim to acknowledge reports within 5 business days and to coordinate a
disclosure timeline with you, targeting remediation within 90 days.

### What to include

* Affected project, component, and version(s)
* Environment (OS, architecture, platform, configuration)
* Reproduction steps; proof-of-concept or screenshots if available
* Impact and how the issue could be exploited
* Any embargo/disclosure timing you would like us to honor
* Whether and how you wish to be credited

## Supported Versions

Only the **latest released version** of `yocto-security-tools` (as published
on [PyPI](https://pypi.org/project/yocto-security-tools/)) is supported with
security updates. Older releases do not receive backported patches.

Archived repositories are not supported and do not receive security updates
anymore.

## Scope

This policy covers the `yocto-security-tools` repository itself.

**Out of scope:**

* **Vulnerabilities in `requests` or `packaging`** (the only two runtime
  dependencies) — please report these to their respective upstream
  maintainers.
* **Malicious or untrusted plugins** loaded from `extra/` or via
  `CVE_EXTRA_SOURCES_DIR` / `CVE_EXTRA_BACKENDS_DIR`. Plugins execute with
  the full privileges of the host process by design — there is no
  sandboxing. This is a documented trust boundary (see
  [extra/README.md](extra/README.md)); we do not accept reports describing
  what a deliberately installed, untrusted plugin can do.
