<!-- SPDX-License-Identifier: MIT -->
# Contributing

## Development Setup

```bash
git clone https://github.com/Ericsson/yocto-security-tools.git
cd yocto-security-tools
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
pre-commit install  # optional: enables ruff + mypy on commit
```

## Running Tests

```bash
pytest                              # all tests
pytest tests/corrector/ -v          # specific component
pytest -m "not integration"         # skip integration tests
pytest --cov --cov-report=term      # with coverage
```

## Code Quality

```bash
ruff check .                        # lint
ruff check --fix .                  # auto-fix
mypy cve_agent cve_corrector cve_metadata_extractor shared
```

## Project Structure

```
├── shared/                  # Shared utilities (leaf module, no upward deps)
├── cve_metadata_extractor/  # Tool 1: find fix commits
├── cve_corrector/           # Tool 2: apply patches via devtool
├── cve_agent/               # Tool 3: AI-assisted conflict resolution
├── extra/                   # Plugin directory (private, .gitignore'd)
└── tests/                   # Mirrors source package structure
```

## Adding a New CVE Source

1. Create a file in `extra/` (for private sources) or in `cve_metadata_extractor/` (for upstream)
2. Subclass `CveSource` from `cve_metadata_extractor.sources`
3. Implement `extract()`, `is_enabled()`, and optionally `setup()`, `enrich()`
4. Append an instance to `SOURCE_REGISTRY`

See [extra/README.md](extra/README.md) for a complete example.

## Adding a New AI Backend

1. Create a file in `extra/`
2. Subclass `AIBackend` from `cve_agent.backend`
3. Implement `run_session()` and `is_available()`
4. Call `register_backend(YourBackend())`

The built-in backends are `kiro` (`KiroBackend`) and `claude` (`ClaudeBackend`),
both in `cve_agent/`. `cve_agent/claude_backend.py` is a good reference for a
first-class backend that shells out to a CLI: it is registered on first use by
`_ensure_builtin_backends()` in `cve_agent/backend.py` (whereas `extra/` plugins
are auto-discovered at runtime).

## Commit Messages

Use conventional format:
```
component: short description

Longer explanation if needed.

Signed-off-by: Your Name <email>
```

Components: `extractor`, `corrector`, `agent`, `shared`, `tests`, `docs`

## Pull Requests

- One logical change per PR
- Tests required for new functionality
- **Bug fixes must include a pytest that reproduces the bug and verifies the fix**
- All existing tests must pass
- No internal/proprietary references

## Dependencies

This project intentionally keeps external dependencies minimal (only `requests`
and `packaging` at runtime). Before adding a new dependency:

- Check if the standard library already provides the functionality
- Prefer vendoring small utilities over adding a PyPI package
- New runtime dependencies require maintainer approval
- Use bounded version ranges in `pyproject.toml` to avoid supply-chain risk

## AI Context Files

The `.agents/summary/` directory contains structured context files that help AI
assistants understand the codebase. When making significant changes, update the
relevant summary file:

- `architecture.md` — package layout and dependency rules
- `components.md` — per-package descriptions and key classes
- `data_models.md` — dataclasses, enums, and serialization formats
- `interfaces.md` — plugin interfaces and registration patterns
- `workflows.md` — end-to-end processing pipelines
- `dependencies.md` — external dependencies and version constraints
- `review_notes.md` — known issues and improvement areas

These files are not consumed at runtime — they exist solely to provide AI
assistants with accurate, up-to-date context about the project.

## License

All contributions are licensed under MIT. By submitting a PR, you agree that
your contribution is licensed under the project's MIT license.

Copyright remains with Ericsson AB.

## Acceptance of AI Generated Code

This project follows the guidance of the Linux Foundation regarding the use of
generative AI tools. See:
https://www.linuxfoundation.org/legal/generative-ai

All existing guidelines in this document are expected to be followed when
contributing AI-generated changes, with these additional requirements:

### Signed-off-by and Developer Certificate of Origin

AI agents MUST NOT add `Signed-off-by` tags. Only humans can legally certify
the Developer Certificate of Origin (DCO). The human submitter is responsible
for:

- Reviewing all AI-generated code
- Ensuring compliance with licensing requirements
- Adding their own `Signed-off-by` tag to certify the DCO
- Taking full responsibility for the contribution

### Attribution

When AI tools contribute to development, proper attribution helps track the
evolving role of AI in the development process. Contributions should include an
`Assisted-by` tag in the commit message in the following format:

```
Assisted-by: AGENT_NAME:MODEL_VERSION [TOOL1] [TOOL2]
```

Where:

- `AGENT_NAME` is the name of the AI tool or framework
- `MODEL_VERSION` is the specific model version used
- `[TOOL1] [TOOL2]` are optional specialized analysis tools used
  (e.g., coccinelle, sparse, smatch, clang-tidy)

Basic development tools (git, gcc, make, editors) should not be listed.

### Example commit message

```
component: Add the ability to ...

Assisted-by: Kiro:claude-opus-4.6

Signed-off-by: Your Name <your.name@domain>
```

As a reminder, when contributing a change, your `Signed-off-by` line is
required and the stipulations in the
[Developer's Statement of Origin 1.1](https://developercertificate.org/) still
apply.

## Releasing

Releases are published to [PyPI](https://pypi.org/project/yocto-security-tools/) automatically when a GitHub Release is created. The patch version is also bumped automatically after every merge to `main`.

### One-time setup (first release only)

**1. Register a trusted publisher on PyPI**

On [pypi.org](https://pypi.org): Your projects → yocto-security-tools → Publishing → Add a new publisher.

| Field | Value |
|---|---|
| Owner | `Ericsson` |
| Repository | `yocto-security-tools` |
| Workflow | `publish.yml` |
| Environment | *(leave blank)* |

No API token is needed. PyPI will accept the OIDC token issued by GitHub Actions.

**2. Enable branch protection (recommended)**

Settings → Branches → Add rule for `main`: require the `CI / test` status check to pass before merging. This ensures every release tag points to a commit that passed CI.

### Release process

1. The bump-version workflow increments the patch version automatically after each PR merge. For a minor or major bump, edit `pyproject.toml` directly in the PR.
2. Update `CHANGELOG.md` with the changes for the release.
3. Create a GitHub Release with a tag matching `v{version}` (e.g., `v1.0.5` if `pyproject.toml` says `1.0.5`). The publish workflow will fail fast if the tag and version don't match.
4. The `publish.yml` workflow runs automatically and uploads the wheel and sdist to PyPI.
