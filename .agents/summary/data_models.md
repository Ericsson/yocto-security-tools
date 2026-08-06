# Data Models

## Core Dataclasses

### WorkflowState (cve_corrector/state.py)

Serializable state for the corrector's workflow, enabling resume after interruption.

```mermaid
classDiagram
    class WorkflowState {
        +Path workspace_path
        +str cve_id
        +str recipe
        +str commit_hash
        +list hash_details
        +Optional~Path~ meta_layer
        +bool skip_build
        +bool skip_ptest
        +Optional~str~ ptest_before
        +Optional~str~ ptest_after
        +Optional~dict~ series_state
        +Optional~str~ current_step
        +bool skip_confirm
        +Optional~str~ subproject
        +bool bbappend
        +Optional~str~ version
        +bool sign_off
        +to_dict() dict
        +from_dict(data) WorkflowState
    }
```

**Persistence**: JSON file at `<state_dir>/<recipe>.json`, written atomically via `tempfile` + `os.replace`.

### AgentConfig (cve_agent/__init__.py)

Configuration for a single CVE agent run.

```mermaid
classDiagram
    class AgentConfig {
        +str cve_id
        +Optional~Path~ cve_info_path
        +bool trust_mode
        +int max_retries
        +int max_total_attempts
        +Optional~Path~ mirror_dir
        +Optional~Path~ meta_layer
        +bool skip_ptest
        +bool clean
        +str model
        +int session_timeout
        +bool interactive
        +bool bbappend
        +bool skip_cve_applicability
        +Optional~str~ fix_url
        +Optional~str~ recipe
        +str backend
        +bool sign_off
    }
```

### CveResult (cve_agent/__init__.py)

Outcome of processing a single CVE.

```mermaid
classDiagram
    class CveResult {
        +str cve_id
        +ResultStatus status
        +int retries
        +float duration
        +str resolution_summary
    }
    class ResultStatus {
        <<enumeration>>
        SUCCESS
        CONFLICT_RESOLVED
        FAILED
        ESCALATED
        SKIPPED
    }
    CveResult --> ResultStatus
```

### ResolutionPattern (cve_agent/knowledge.py)

A recorded conflict resolution pattern for the knowledge base.

```mermaid
classDiagram
    class ResolutionPattern {
        +str conflict_type
        +str recipe
        +str file_pattern
        +str resolution_summary
        +str cve_id
        +str timestamp
        +str upstream_sha
        +list~str~ affected_files
        +dict~str,str~ per_file_changes
        +str diff_stat
        +str commit_message
    }
```

### SessionResult (cve_agent/backend.py)

```mermaid
classDiagram
    class SessionResult {
        +bool resolved
        +float duration
        +Optional~Path~ transcript_path
    }
```

### WorkflowConfig (cve_corrector/workflow.py)

```mermaid
classDiagram
    class WorkflowConfig {
        +str cve_id
        +Path cve_info_path
        +Optional~str~ recipe
        +Optional~Path~ mirror_dir
        +Optional~Path~ meta_layer
        +bool skip_build
        +bool skip_ptest
        +bool skip_confirm
        +bool bbappend
        +bool skip_cve_applicability
        +Optional~str~ fix_url
        +bool sign_off
    }
```

## Enumerations

### ResultStatus (cve_agent/__init__.py)

| Value | Meaning |
|-------|---------|
| `SUCCESS` | CVE fixed on first attempt (clean cherry-pick) |
| `CONFLICT_RESOLVED` | Fixed after AI-assisted conflict resolution |
| `FAILED` | All retries exhausted |
| `ESCALATED` | Unrecoverable error, requires human intervention |
| `SKIPPED` | CVE already applied or not applicable |

### Exit Codes (shared/exit_codes.py)

| Code | Constant | Category | Meaning |
|------|----------|----------|---------|
| 0 | `EXIT_SUCCESS` | Success | Workflow completed |
| 1 | `EXIT_CONFLICT` | Recoverable | Cherry-pick conflict |
| 2 | `EXIT_CHECKOUT_ERROR` | Unrecoverable | Version checkout failed |
| 3 | `EXIT_PTEST_ERROR` | Recoverable | Post-patch ptest failure |
| 4 | `EXIT_BUILD_ERROR` | Recoverable | Post-patch build failure |
| 5 | `EXIT_PATCH_ERROR` | Unrecoverable | Patch generation error |
| 6 | `EXIT_METADATA_ERROR` | Unrecoverable | Bad metadata/config |
| 7 | `EXIT_GIT_ERROR` | Unrecoverable | Git operation failed |
| 8 | `EXIT_PTEST_PREEXISTING` | Unrecoverable | Ptest already failing |
| 9 | `EXIT_DEVTOOL_ERROR` | Unrecoverable | Devtool operation failed |
| 10 | `EXIT_BUILD_PREEXISTING` | Unrecoverable | Build already failing |
| 11 | `EXIT_ALREADY_APPLIED` | Unrecoverable | Fix already present |
| 12 | `EXIT_NOT_APPLICABLE` | Unrecoverable | Vulnerable code absent |
| 13 | `EXIT_TRUST_DECLINED` | Agent | User declined trust mode |
| 14 | `EXIT_AGENT_ERROR` | Agent | Internal agent error |
| 15 | `EXIT_AI_TIMEOUT` | Agent | AI session timed out |
| 16 | `EXIT_IGNORED_BY_STATUS` | Unrecoverable | Recipe's CVE_STATUS marks CVE as Ignored/Patched |

## Exception Hierarchy

```mermaid
classDiagram
    Exception <|-- WorkflowError
    WorkflowError <|-- ConflictError
    WorkflowError <|-- PtestError
    WorkflowError <|-- BuildError
    WorkflowError <|-- PatchError
    WorkflowError <|-- MetadataError
    WorkflowError <|-- GitError
    WorkflowError <|-- DevtoolError
    WorkflowError <|-- PtestPreexistingError
    WorkflowError <|-- BuildPreexistingError
    WorkflowError <|-- AlreadyAppliedError
    WorkflowError <|-- NotApplicableError
    class WorkflowError {
        +int exit_code
    }
```

Each exception maps to a specific exit code. The corrector's `__main__.py` catches `WorkflowError` and returns `e.exit_code`.

## JSON Schemas

### cve-metadata.json

Top-level dict keyed by CVE ID:

```json
{
  "CVE-YYYY-NNNN": {
    "name": "string (component/recipe name)",
    "hashes": ["string (commit SHA)"],
    "hash_details": [
      {"hash": "string", "url": "string", "source": "string"}
    ],
    "series": [
      {"pull_url": "string", "commits": ["string"]}
    ],
    "patches": [
      {"url": "string", "tags": "string"}
    ],
    "references": ["string (URL)"],
    "oe_status": "string (optional, e.g. 'fixed-in-scarthgap')"
  }
}
```

### knowledge.json

Array of `ResolutionPattern` objects (see dataclass above). File-locked with `fcntl.flock` for concurrent access safety.

### conclusion.json (AI Output)

Written by AI when CVE is not applicable:

```json
{
  "not_applicable": true,
  "reason": "string (specific explanation)"
}
```

### config.json (Extractor Configuration)

```json
{
  "cvelistv5_url": "string (git URL)",
  "cvelistv5_branch": "string",
  "debian_release": "string",
  "debian_tracker_url": "string (git URL)",
  "debian_tracker_branch": "string",
  "nvd_url": "string (git URL)",
  "nvd_branch": "string",
  "oe_branches": ["string"],
  "osv_api": "string (base URL)",
  "ubuntu_api": "string (base URL)",
  "snapshot_api": "string (base URL)"
}
```
