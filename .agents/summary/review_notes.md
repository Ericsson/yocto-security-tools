# Review Notes

_Last verified against source: `pyproject.toml` (version 1.2, `requires-python>=3.10`,
coverage `fail_under=65`), `.github/workflows/ci.yml` (Python 3.10–3.14 + 3.15-dev
experimental), and `cve_metadata_extractor/{uct,ubuntu}.py`._

## Consistency Check

### ✅ Passed

| Check | Status |
|-------|--------|
| Exit codes consistent across data_models.md, interfaces.md, workflows.md | ✅ All reference shared/exit_codes.py as source of truth |
| Package dependency direction consistent (architecture.md ↔ components.md) | ✅ Both show shared←extractor, shared←corrector, shared←agent |
| CLI flags in interfaces.md match actual argparse in __main__.py modules | ✅ Verified against source |
| Plugin registration patterns consistent (interfaces.md ↔ architecture.md) | ✅ SOURCE_REGISTRY.append() and register_backend() documented identically |
| File format schemas (interfaces.md ↔ data_models.md) | ✅ No contradictions |
| Environment variables listed consistently across files | ✅ Same set in interfaces.md and codebase_info.md |
| Version, Python support, coverage threshold, CI matrix | ✅ Fixed this pass — see "Corrected This Pass" below |
| Ubuntu CVE source description (uct.py vs ubuntu.py) | ✅ Fixed this pass — see below |

### Corrected This Pass

The following factual drift was found against source and corrected in
`codebase_info.md`, `dependencies.md`, `components.md`, `interfaces.md`,
`architecture.md`, and `workflows.md`:

| Item | Was | Now |
|------|-----|-----|
| Project version | 1.0.0 | 1.2 (`pyproject.toml`) |
| Python support | 3.9+ | `>=3.10` (`requires-python`) |
| CI matrix | 3.9–3.12 | 3.10–3.14 required, 3.15-dev experimental (`continue-on-error`) |
| Coverage threshold | 75% | 65% (`fail_under = 65`) |
| `cve_metadata_extractor/uct.py` | Undocumented | Added — default-on Ubuntu CVE Tracker local clone (`is_enabled` returns `not args.no_uct`) |
| `cve_metadata_extractor/ubuntu.py` | Implied always-available | Corrected — deprecated, disabled by default, opt-in via `--ubuntu-api` |
| `--no-uct` / `--ubuntu-api` / `--no-ubuntu` flags | Missing from interfaces.md | Added |

### ⚠️ Minor Notes

| Item | Note |
|------|------|
| `_AttemptOutcome` enum in orchestrator.py | Internal enum not documented in data_models.md (intentional — private implementation detail) |
| `Version` class in cve_corrector/version.py | Custom PEP 440 implementation not detailed in data_models.md (simple utility, not a domain model) |
| `[tool.ruff] target-version = "py39"` | Stale relative to `requires-python = ">=3.10"`; noted as a quirk in codebase_info.md and dependencies.md rather than silently "corrected", since it's a real repo inconsistency worth a maintainer's attention |

## Completeness Check

### ✅ Well-Covered Areas

- All 4 source packages documented with per-file responsibilities, including all `cve_metadata_extractor` sources (debian, osv, cvelistv5/NVD, uct, ubuntu)
- Plugin interfaces fully specified with registration patterns
- State machine and orchestration loop documented with diagrams
- Exit code semantics and categorization (recoverable vs unrecoverable)
- Security model (env filtering, plugin ownership checks, scope hooks)
- JSON schemas for all inter-process data formats
- CI/CD pipeline and pre-commit configuration
- Native OpenAI-compatible backend (`openai_*` modules) — configuration, HTTP client, typed tools, host runtime, transcript/audit, evaluation harness

### ⚠️ Areas With Limited Detail

| Area | Gap | Recommendation |
|------|-----|----------------|
| Integration tests | Shell-based tests (`test_cve_corrector.sh`) not documented in detail | Add section to workflows.md if integration test authoring becomes common |
| Debian source extraction | Complex multi-step process (tar download, patch matching, DSA parsing) | Consider expanding components.md entry for debian.py |
| Monorepo detection | `detect_monorepo_subproject()` logic not explained | Add to workflows.md if monorepo support questions arise |
| Agent instruction prompt | AGENT_INSTRUCTIONS.md content not summarized | Intentional — the file is self-documenting and consumed directly by AI |
| Error recovery paths | Specific retry behavior per exit code not fully enumerated | Could add a table to workflows.md mapping exit code → agent behavior |
| `extra/` symlink workflow | How to set up private plugin repos via symlinks | Covered in extra/README.md; could cross-reference from interfaces.md |
| Dependent commit chain (`--fix-url` repeatable) | Documented in root README.md quickstart but not in interfaces.md CLI section | Consider adding to interfaces.md's cve-corrector/cve-agent CLI tables |
| `--verify-backend` | Documented in root README.md but not in interfaces.md | Consider adding as a corrector/agent CLI option |

### 🔍 Language/Framework Gaps

| Gap | Reason |
|-----|--------|
| No API documentation (Sphinx/autodoc) | Project uses docstrings but no generated API docs |
| No architecture decision records (ADRs) | Design decisions are implicit in code structure |
| No changelog automation for content (version bump is automated, but changelog text is manual) | CHANGELOG.md exists but appears manually maintained |

## Recommendations

1. **High priority**: None — documentation now reflects verified current facts (version, Python support, coverage, CI, all CVE sources) for all critical paths.
2. **Medium priority** (status: addressed/investigated this pass):
   - ✅ Added an exit-code → agent-action → retry-behavior table to `workflows.md` (verified against `cve_agent/orchestrator.py`: `_run_cve_pipeline`, `_resolution_loop`, `_run_single_resolution_attempt`, `_handle_escalation`).
   - ⚠️ Investigated aligning `[tool.ruff] target-version` with `requires-python` (`py39` → `py310`). **Not applied** — confirmed via `ruff check .` that this newly activates `UP045` (`Optional[X]` → `X | None`, 323 occurrences) and `B905` (`zip()` missing `strict=`, 19 occurrences), a 344-line mechanical change spanning most of the codebase. This is real and worth doing, but it is a separate, reviewable change from documentation and needs explicit maintainer sign-off (and likely its own PR) rather than being silently bundled here.
3. **Low priority**: Document the Debian extraction pipeline in more detail if contributors work on that module.
4. **Optional**: Consider generating Sphinx API docs from docstrings for public interfaces.
