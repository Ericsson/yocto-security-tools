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
        +str failure_reason
    }
```

### OpenAIConfig (cve_agent/openai_backend.py)

Immutable, validated configuration for the native OpenAI-compatible backend.
It stores the name of an API-key environment variable, never the key value.

```mermaid
classDiagram
class OpenAIConfig {
        +str base_url
        +str model
        +str api_key_env
        +int max_steps
        +int max_tool_calls
        +int max_output_tokens
        +int connect_timeout
        +int request_timeout
        +bool allow_remote_endpoint
        +bool allow_insecure_remote_http
        +chat_completions_url str
        +is_loopback bool
    }
```

### FileToolLimits and ToolResult (cve_agent/openai_tools.py)

`FileToolLimits` is an immutable per-session set of size/count limits capped
by module-level hard maxima. `ToolResult` is the bounded JSON-serializable
outcome of a host-side tool call; `terminal` is always false until a later
model-loop stage calls the host runtime's verified `finish` tool.

```mermaid
classDiagram
    class ToolResult {
        +bool success
        +dict payload
        +bool mutated
        +bool terminal
        +Optional~str~ error_kind
        +ToolAudit audit
    }
    class ToolAudit {
        +str tool
        +bool success
        +bool mutated
        +int generation
        +Optional~str~ error_kind
        +Optional~str~ path
        +tuple~str~ paths
        +Optional~str~ revision
    }
    ToolResult --> ToolAudit
```

The internal `_ExecutionResult.advances_generation` flag defaults true for
durable source/index mutations. Typed commit/amend results remain
`mutated=True` for audit and loop-progress purposes but set it false because
they only record source content validated by the preceding build.

### GitToolLimits and RepositorySnapshot (cve_agent/openai_git_tools.py)

`GitToolLimits` caps revisions, path counts, parsed log/status entries,
subprocess output, diagnostics, resolution notes, and per-command duration;
typed replacement/follow-up commit messages have a separate 16 KiB byte cap.
`RepositorySnapshot` retains the session-start commit and operation markers
for later terminal-state checks without changing `guarded_session()`.

```mermaid
classDiagram
    class RepositorySnapshot {
        +str head
        +Mapping~str,bool~ operations
    }
    class GitCommandResult {
        +int returncode
        +str stdout
        +str stderr
        +bool stdout_truncated
        +bool stderr_truncated
        +bool timed_out
    }
```

### Native host runtime models (cve_agent/openai_deadline.py, openai_host_tools.py)

`SessionDeadline` stores one absolute monotonic expiry shared by Git, build,
approval, terminal checks, and the future HTTP loop. `BuildCommandResult`
keeps only a bounded output tail in memory while naming the bounded trusted
log. `ApprovalDecision` is closed to `approve_once`, `approve_class`, `deny`,
and `timeout`.

```mermaid
classDiagram
    class SessionDeadline {
        +float expires_at
        +remaining() float
        +expired bool
        +require(operation) float
    }
    class BuildCommandResult {
        +int returncode
        +float duration
        +bool timed_out
        +str tail
        +bool truncated
        +int total_output_bytes
        +Path log_path
        +bool log_truncated
        +successful bool
    }
    class ApprovalRequest {
        +str category
        +str operation
        +str summary
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

### Native Chat Completions models (cve_agent/openai_client.py)

The single-exchange client returns only immutable validated response data.
Function arguments remain bounded JSON text for the later dispatcher; an
`arguments_were_object` flag records the Ollama-style object compatibility
accommodation. `OpenAIClientLimits` caps 128 messages, 64 tools/calls, a 1 MiB
request, a 1 MiB decoded response, 128/64 KiB response headers, depth 32, and
20,000 JSON nodes by default.

```mermaid
classDiagram
    class AssistantResponse {
        +Optional~str~ content
        +tuple~FunctionToolCall~ tool_calls
        +Optional~str~ finish_reason
        +Optional~TokenUsage~ usage
    }
    class FunctionToolCall {
        +str id
        +str name
        +str arguments
        +bool arguments_were_object
    }
    class TokenUsage {
        +Optional~int~ prompt_tokens
        +Optional~int~ completion_tokens
        +Optional~int~ total_tokens
    }
    AssistantResponse --> FunctionToolCall
    AssistantResponse --> TokenUsage
```

### Native agent loop models (cve_agent/openai_loop.py)

`AgentLoopLimits` independently caps model turns, total calls, calls per
assistant response (16 by default), and consecutive nonprogress responses
(three by default). `JSONLTranscript` is a mandatory mode-`0600` audit stream;
`TranscriptError` fails the session closed. The loop continues to return the
existing `SessionResult`, setting `resolved` only from the trusted runtime's
accepted terminal state and always returning the transcript path when it was
created. Unresolved native results also return a stable, credential-free
`failure_reason` suitable for CLI display; resolved results leave it empty.

```mermaid
stateDiagram-v2
    [*] --> ModelRequest
    ModelRequest --> Unresolved: deadline / client / protocol / bounds
    ModelRequest --> CorrectOnce: text only
    CorrectOnce --> Unresolved: second text-only stop
    CorrectOnce --> ModelRequest: typed calls
    ModelRequest --> ToolBatch: validated calls
    ToolBatch --> ModelRequest: nonterminal results
    ToolBatch --> Resolved: host-verified finish
    ToolBatch --> Unresolved: repeated nonprogress / call bounds
```

### knowledge.json

Array of `ResolutionPattern` objects (see dataclass above). File-locked with `fcntl.flock` for concurrent access safety.

### conclusion.json (Agent Outcome)

Legacy CLI backends write this outcome under their existing permissions. The
native OpenAI host runtime denies generic file-tool access and writes the file
atomically only after `finish` verifies a clean baseline state. The two exact
orchestrator-compatible forms are:

```json
{
  "not_applicable": true,
  "reason": "string (specific explanation)"
}
```

```json
{
  "needs_human": true,
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
