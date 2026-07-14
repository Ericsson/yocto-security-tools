<!-- SPDX-License-Identifier: MIT -->
# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it
responsibly. **Do not open a public GitHub issue.**

### How to Report

Please use the "Report a vulnerability" button on this repository's Security
tab.

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Potential impact

### What to Expect

- Acknowledgment within 5 business days
- Status update within 15 business days
- We will coordinate disclosure timing with you

### Scope

This policy covers the `yocto-security-tools` repository. Vulnerabilities in
upstream dependencies (requests, packaging) should be reported to their
respective maintainers.

### Plugin Security

Plugins loaded from `extra/` or via `CVE_EXTRA_SOURCES_DIR` execute with full
process privileges. See [extra/README.md](extra/README.md) for the security
model. We do not accept vulnerability reports for malicious plugins that a user
explicitly installed.
