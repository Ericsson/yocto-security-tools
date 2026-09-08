# Documentation Index

> **For AI Assistants**: This file is your primary entry point. Read this first to understand what documentation is available and which file to consult for specific questions.

## Project Summary

**yocto-security-tools** is a Python 3.9+ toolchain for automated CVE management in Yocto/OpenEmbedded. It consists of three CLI tools forming a pipeline: metadata extraction → patch application → AI-assisted conflict resolution. The codebase has four Python packages (`shared`, `cve_metadata_extractor`, `cve_corrector`, `cve_agent`) with a strict acyclic dependency graph and a plugin system for extensibility.

## Documentation Files

| File | Purpose | Consult When... |
|------|---------|-----------------|
| [codebase_info.md](codebase_info.md) | Project identity, tech stack, entry points, storage model | You need basic project facts, Python version, build system, or test structure |
| [architecture.md](architecture.md) | System design, dependency rules, process isolation, security | You need to understand how packages relate, why subprocess isolation exists, or plugin security |
| [components.md](components.md) | Per-file responsibilities for every module | You need to find which file implements a specific feature or understand a module's role |
| [interfaces.md](interfaces.md) | Plugin APIs, CLI flags, env vars, file formats | You need to write a plugin, understand CLI options, or parse/produce JSON data |
| [data_models.md](data_models.md) | Dataclasses, enums, exceptions, JSON schemas | You need field definitions, exit code meanings, exception types, or JSON structure |
| [workflows.md](workflows.md) | State machines, orchestration sequences, batch processing | You need to understand the execution flow, retry logic, or resume behavior |
| [dependencies.md](dependencies.md) | Runtime/dev/system deps, external services, CI | You need version constraints, what external tools are required, or CI configuration |

## Quick Reference

### Architecture Rules
- `shared` is a leaf module — never imports from sibling packages
- Agent invokes corrector only via `subprocess.run()` (process isolation)
- Plugins are discovered via `importlib` from `extra/` directory
- Only 2 runtime PyPI dependencies: `requests` and `packaging`

### Key Entry Points
- `cve_metadata_extractor/__main__.py:main()` — extractor CLI
- `cve_corrector/__main__.py:main()` — corrector CLI
- `cve_agent/__main__.py:main()` — agent CLI
- `cve_corrector/workflow.py:initialize_cve_workflow()` — corrector state machine entry
- `cve_agent/orchestrator.py:process_single_cve()` — agent orchestration entry

### Exit Code Quick Reference
- **0**: Success | **1**: Conflict (recoverable) | **3**: Ptest fail (recoverable) | **4**: Build fail (recoverable)
- **2, 5–12, 16, 17**: Unrecoverable errors | **13–15**: Agent-specific errors

### File Format Quick Reference
- `cve-metadata.json`: Dict keyed by CVE ID → `{name, hashes, hash_details, series, patches}`
- `<state_dir>/<recipe>.json`: Serialized `WorkflowState` for resume
- `knowledge.json`: Array of `ResolutionPattern` objects
- `conclusion.json`: AI output when CVE not applicable

## How to Use This Documentation

### Finding Implementation Details
1. Start with **components.md** to locate the relevant file
2. Check **interfaces.md** for the API contract
3. Refer to **data_models.md** for data structure definitions

### Understanding Behavior
1. Start with **workflows.md** for the execution flow
2. Check **architecture.md** for design constraints
3. Refer to **data_models.md** for exit codes and state transitions

### Adding Features
1. Check **architecture.md** for dependency rules and invariants
2. Review **interfaces.md** for plugin patterns
3. Consult **dependencies.md** before adding new packages

### Debugging Issues
1. Check **data_models.md** for exit code meanings
2. Review **workflows.md** for the state machine and retry logic
3. Check **components.md** to find the relevant source file

## Cross-References

| Topic | Primary File | Related Files |
|-------|-------------|---------------|
| Plugin development | interfaces.md | architecture.md (security), components.md (source files) |
| Exit codes | data_models.md | workflows.md (how they're used), interfaces.md (inter-process) |
| State persistence | data_models.md | workflows.md (resume flow), architecture.md (atomic writes) |
| AI sessions | workflows.md | interfaces.md (backend API), components.md (session.py) |
| Security model | architecture.md | interfaces.md (env vars), dependencies.md (system tools) |
