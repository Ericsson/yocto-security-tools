# Interfaces

## Plugin Interfaces

### CveSource (Extractor Plugin)

```python
class CveSource:
    name: str = ''
    cli_args: list[tuple[list[str], dict]] = ()

    def setup(self, args, cfg) -> None: ...
    def is_enabled(self, args) -> bool: ...
    def extract(self, cve_id: str, stats: dict) -> tuple[list, list, list, list]: ...
    def enrich(self, cve_id: str, result: dict, metadata: dict, args) -> None: ...
    def deduce_component(self, cve_id: str, cache: str) -> str | None: ...
```

**Registration**: `SOURCE_REGISTRY.append(MySource())`

**Return format for `extract()`**:
- `hashes`: `[{'hash': str, 'url': str, 'source': str}]`
- `patches`: `[{'url': str, 'tags': str}]`
- `series`: `[{'pull_url': str, 'commits': [str]}]`
- `references`: `[str]`

### AIBackend (Agent Plugin)

```python
class AIBackend:
    name: str = ""
    default_model: str | None = "claude-sonnet-5"

    def run_session(self, prompt: str, workspace_path: Path,
                   allowed_files: set, model: str,
                   timeout: int, interactive: bool) -> SessionResult: ...
    def is_available(self) -> bool: ...
    def setup(self, **kwargs) -> None: ...
    def configure(self, options: Mapping[str, object],
                  environ: Mapping[str, str] | None = None) -> None: ...
    def resolve_model(self, requested: str | None,
                      environ: Mapping[str, str] | None = None) -> str: ...
    def tool_preamble(self) -> str: ...
    def assembled_instructions(self) -> str: ...
```

**Registration**: `register_backend(MyBackend())`

**SessionResult**:
```python
@dataclass
class SessionResult:
    resolved: bool
    duration: float
    transcript_path: Optional[Path] = None
    failure_reason: str = ""
```

`assembled_instructions()` always prepends one backend-specific tool preamble
to the packaged backend-neutral instructions. It does not consume the stable
Kiro-prefixed XDG prompt copy.

### Native OpenAI filesystem tools

`cve_agent.openai_tools.openai_tool_schemas()` generates OpenAI-compatible
function schemas from the same `TOOL_CONTRACTS` used by
`FileToolRuntime.dispatch()`. Available tools are:

- `list_directory`
- `read_file`
- `search_text` (literal search over an explicit path list)
- `replace_in_file`
- `write_file` (`create_only` or `replace_only`)
- `delete_file`

Workspace reads are generic but bounded. Absolute reads are accepted only
under the configured agent/context root. Mutations require an exact normalized
match in the session `allowed_files` set. There are no command, argv, shell,
glob, regex, subprocess, or Python-expression fields.

### Native OpenAI Git tools

`cve_agent.openai_git_tools.native_openai_tool_schemas()` combines the file
contracts with the closed Git contracts used by `GitToolRuntime.dispatch()`.
The Git tools are:

- inspection: `git_status`, `git_diff`, `git_show`, `git_log`,
  `git_unmerged_files`, and `git_submodule_status`;
- exact-path mutation: `git_stage`, `git_unstage`, `git_remove`, and
  `git_restore_conflict`;
- lifecycle: `git_cherry_pick_start`, `git_cherry_pick_continue`,
  `git_cherry_pick_abort`, and `git_cherry_pick_skip`.

The dispatcher has no generic `git`, command, flags, config, environment,
executable, hook, shell, or pathspec field. Revisions resolve to immutable
commits before use. Cherry-pick start examines a raw root-aware tree diff and
refuses out-of-scope paths, gitlinks, and merge commits before mutation.

### Native OpenAI host tools

`cve_agent.openai_host_tools.complete_openai_tool_schemas()` adds two closed
host operations to the file and Git contracts:

- `build_recipe` takes no arguments. Host code validates/derives the recipe
  and executes exactly `devtool build <recipe>` in the workspace.
- `finish` accepts `status` from `done`, `not_applicable`, or `needs_human`, a
  bounded reason, and an optional bounded `done` summary. Host checks decide
  whether the result becomes terminal.

All native operations share one `SessionDeadline`. In interactive mode,
inspection is prompt-free while file/Git mutations, build, and terminal
creation pass through the injectable approval gate. Approval decisions are
`approve_once`, `approve_class`, `deny`, or `timeout`; non-TTY and EOF deny.
Generic file mutation rejects `conclusion.json` even when it appears in
`allowed_files`.

Native Git/build children omit proxy, Git SSH, SSH-agent, and unrelated secret
variables, force the C locale, and drop PATH entries below model-readable or
model-writable session roots.

### Native OpenAI Chat Completions client

`OpenAIChatCompletionsClient.complete(messages, tools)` performs exactly one
non-streaming exchange and does not execute returned tools. The request fields
are `model`, `messages`, `stream: false`, and `max_tokens`; nonempty tool lists
add `tools` and `tool_choice: auto`. The client supplies `Content-Type` and an
optional bearer credential from the configured environment-variable name.
Callers cannot supply headers, URLs, or optional provider extensions.

The first response choice must contain an assistant message with string/null
content and/or a bounded list of uniquely identified function calls. String
arguments are preserved without semantic JSON validation. Object arguments
from Ollama-compatible servers are accepted and converted to compact JSON.
Content arrays and other response representations are rejected.

Loopback HTTP explicitly disables ambient proxies. Opted-in remote endpoints
retain `requests` proxy-environment behavior. Automatic redirects are always
disabled.

The portable endpoint contract is `POST <api-root>/chat/completions`,
non-streaming JSON, `messages`, function `tools`, assistant `tool_calls`, and
stable call IDs echoed in later `role: tool` messages. `/models`, Responses API
state, streaming, provider reasoning extensions, multimodal input, and
arbitrary custom tools are not part of this interface.

Default client bounds are 128 messages, 64 tool schemas/calls, 256 KiB per
message, 64 KiB per schema, 1 MiB serialized request, 1 MiB decoded response,
128/64 KiB response headers, 512 KiB assistant content, 256 KiB function
arguments, JSON depth 32, and 20,000 JSON nodes. The default retry policy makes at most three attempts and
retries only connection failures, 429, 502, 503, and 504. Transport timeouts,
HTTP 500, other 4xx, malformed JSON, protocol errors, and policy errors do not
retry. Numeric `Retry-After` and exponential backoff are capped at two seconds
by default and may not consume the remaining shared deadline.

### Native OpenAI multi-turn session

`OpenAICompatibleBackend.run_session()` constructs one shared deadline, a
mandatory protected transcript, `OpenAIHostToolRuntime`, and
`OpenAIAgentLoop`. The first messages are the native preamble plus shared agent
instructions as `system`, followed by the existing guarded-session prompt as
`user`. The generated context remains readable only through the explicitly
authorized agent-directory root.

For every assistant response the loop appends the complete assistant message,
then one compact JSON `role: tool` result per call with its exact
`tool_call_id`. Results contain `success`, `mutated`, `terminal`, mutation
`generation`, and an explicit `recoverable` value; successful results use
`data`, while failures add `error` and `policy_category`. Calls execute in
response order. A successful `finish` is the only resolved path.

Default loop-only limits are 16 calls per response and three consecutive
nonprogress responses; configured `max_steps` and `max_tool_calls` supply the
turn and total-call bounds. One corrective message is allowed after a
text-only stop. A second stop, `length`, `content_filter`, an unsupported
finish reason, deadline expiry, client/protocol exhaustion, or audit failure
returns an unresolved `SessionResult`.

Native transcripts use
`<agent_dir>/openai-<sanitized-model>-<pid>-<time_ns>.jsonl`, mode `0600`.
They store bounded metadata and truncated assistant text, never request
headers, raw credentials, full environments, or file/build result content.
Credential values and bearer-token forms are redacted defensively.
Unresolved results carry a stable `failure_reason` for user display; raw server
bodies and transport exception details remain below the UI boundary.

Configuration precedence is field-specific:

- model: `--model`, `CVE_AGENT_OPENAI_MODEL`; no default and no
  `OPENAI_MODEL` fallback;
- API root: `--openai-base-url`, `CVE_AGENT_OPENAI_BASE_URL`,
  `OPENAI_BASE_URL`, local Ollama default;
- key-variable name: `--openai-api-key-env`,
  `CVE_AGENT_OPENAI_API_KEY_ENV`, then `OPENAI_API_KEY` as the default name;
- limits and opt-ins: their CLI option, corresponding
  `CVE_AGENT_OPENAI_*` variable, then the documented default.

Loopback HTTP requires no opt-in or key. Non-loopback endpoints require
`--openai-allow-remote`/`CVE_AGENT_OPENAI_ALLOW_REMOTE`; non-loopback HTTP also
requires the separate insecure-transport opt-in.

## CLI Interfaces

### cve-metadata-extractor

```
cve-metadata-extractor [OPTIONS]

Input (one required):
  --yocto-summary FILE    Yocto cve-summary.json
  --cve-id CVE-XXXX-YYYY  One or more CVE IDs

Options:
  --output FILE           Output path (default: stdout)
  --checkpoint-interval S Periodic save interval; 0 disables (default: 60)
  --cve-component-name N  Override component name deduction
  --check-oe-status       Check if already fixed in OE branches
  --no-debian / --no-osv / --no-cvelistv5 / --no-ubuntu
                          Disable specific sources
  --config FILE           Override config.json path
```

### cve-corrector

```
cve-corrector [OPTIONS]

Required:
  --cve-id CVE-XXXX-YYYY  CVE to fix
  --cve-info FILE         Path to cve-metadata.json

Options:
  --recipe NAME           Override recipe name deduction
  --mirror-dir DIR        Local git mirror directory
  --meta-layer DIR        Target meta-layer for commit
  --skip-build            Skip build verification step
  --skip-ptest            Skip ptest step
  --bbappend              Use bbappend instead of modifying recipe
  --dry-run               Show what would be done without executing
  --continue              Resume from saved state (after conflict resolution)
  --sign-off              Add Signed-off-by trailer (default: off). On
                          --continue, omitting it preserves the choice made
                          on the original run; passing it again overrides
  --verbose               Enable debug logging
```

### cve-agent

```
cve-agent [OPTIONS]

Input (one required):
  --cve-id CVE-XXXX-YYYY  Single CVE
  --cve-list FILE         Text file with one CVE per line

Required:
  --cve-info FILE         Path to cve-metadata.json

Options:
  --trust                 Auto-approve AI changes (no human review)
  -i, --interactive       Use interactive AI agent (human-in-the-loop);
                          omit for non-interactive/CI use (default)
  --backend NAME          AI backend: kiro, claude, or openai (default: kiro)
  --model NAME            AI model (kiro/claude default: claude-sonnet-5;
                          required for openai unless configured by environment)
  --max-retries N         Per-step retry limit (default: 3)
  --session-timeout SECS  AI session timeout (default: 600)
  --skip-ptest            Skip ptest verification
  --clean                 Clean workspace before starting
  --recipe NAME           Override recipe name
  --mirror-dir DIR        Local git mirror directory
  --meta-layer DIR        Target meta-layer
  --bbappend              Use bbappend mode
  --no-knowledge          Disable the knowledge base for this run: no
                          similar-pattern lookups, and no pattern is
                          saved on success
  --sign-off              Passed through to cve-corrector (default: off).
                          Rejected in combination with --trust — no human
                          review means no DCO certification to make.

OpenAI-compatible backend options:
  --openai-base-url URL
  --openai-api-key-env NAME
  --openai-max-steps N
  --openai-max-tool-calls N
  --openai-max-output-tokens N
  --openai-connect-timeout SECS
  --openai-request-timeout SECS
  --openai-allow-remote
  --openai-allow-insecure-remote-http
```

## Inter-Process Interface

The agent communicates with the corrector via:

| Channel | Format |
|---------|--------|
| Invocation | `subprocess.run([python, -m, cve_corrector, ...])` |
| Exit code | Integer 0–12 (see `shared/exit_codes.py`) |
| State file | `<state_dir>/<recipe>.json` (WorkflowState serialized) |
| Conclusion | `<agent_dir>/conclusion.json` (legacy backend output; native host writes only after verified `finish`) |
| Feedback | `<agent_dir>/feedback.txt` (consumed and deleted on next context build) |

## Environment Variable Interface

| Variable | Consumer | Purpose |
|----------|----------|---------|
| `BBPATH` | corrector, agent | Yocto build environment (required) |
| `BUILDDIR` | corrector | Build directory for state/workspace paths |
| `GITHUB_TOKEN` | extractor | GitHub API authentication for PR metadata |
| `OPENEMBEDDED_TOKEN` | extractor | OE mailing list API access |
| `CVE_EXTRACTOR_CONFIG` | extractor | Override config.json path |
| `CVE_TOOLS_DATA_DIR` | all | Override XDG data directory |
| `CVE_TOOLS_CACHE_DIR` | all | Override XDG cache directory |
| `CVE_EXTRA_SOURCES_DIR` | extractor | Override plugin directory |
| `CVE_EXTRA_BACKENDS_DIR` | agent | Override backend plugin directory |
| `CVE_AGENT_OPENAI_MODEL` | agent | Required model for `openai` when `--model` is omitted |
| `CVE_AGENT_OPENAI_BASE_URL` | agent | OpenAI-compatible API root |
| `CVE_AGENT_OPENAI_API_KEY_ENV` | agent | Name of the environment variable containing an API key |
| `CVE_AGENT_OPENAI_MAX_STEPS` | agent | Maximum model turns per session |
| `CVE_AGENT_OPENAI_MAX_TOOL_CALLS` | agent | Maximum total tool calls per session |
| `CVE_AGENT_OPENAI_MAX_OUTPUT_TOKENS` | agent | Maximum output tokens per response |
| `CVE_AGENT_OPENAI_CONNECT_TIMEOUT` | agent | Connection timeout in seconds |
| `CVE_AGENT_OPENAI_REQUEST_TIMEOUT` | agent | Request timeout in seconds |
| `CVE_AGENT_OPENAI_ALLOW_REMOTE` | agent | Explicit opt-in for non-loopback endpoints |
| `CVE_AGENT_OPENAI_ALLOW_INSECURE_REMOTE_HTTP` | agent | Separate opt-in for remote HTTP |
| `OPENAI_BASE_URL` | agent | Standard fallback API root for the `openai` backend |
| `OPENAI_API_KEY` | agent | Default optional API-key environment variable |
| `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` / `NO_PROXY` | native OpenAI HTTP client | Used only for opted-in remote endpoints; loopback bypasses ambient proxies and redirects remain disabled |

## File Format Interfaces

### cve-metadata.json (Pipeline Data)

```json
{
  "CVE-2024-1234": {
    "name": "openssl",
    "hashes": ["abc123..."],
    "hash_details": [{"hash": "abc123", "url": "https://...", "source": "debian"}],
    "series": [{"pull_url": "...", "commits": ["hash1", "hash2"]}],
    "patches": [{"url": "...", "tags": "patch"}]
  }
}
```

### WorkflowState JSON (Resume State)

```json
{
  "workspace_path": "/path/to/workspace/sources/recipe",
  "cve_id": "CVE-2024-1234",
  "recipe": "openssl",
  "commit_hash": "abc123",
  "hash_details": [...],
  "meta_layer": "/path/to/meta-layer",
  "skip_build": false,
  "skip_ptest": false,
  "current_step": "cherry_pick",
  "series_state": null
}
```

### knowledge.json (Pattern Store)

```json
[
  {
    "conflict_type": "function_signature",
    "recipe": "openssl",
    "file_pattern": "*.c",
    "resolution_summary": "Adapted foo_v2() to foo_v1() API",
    "cve_id": "CVE-2024-1234",
    "timestamp": "2026-01-15T10:30:00Z",
    "upstream_sha": "abc123",
    "affected_files": ["src/foo.c"],
    "per_file_changes": {"src/foo.c": "Changed signature"},
    "diff_stat": "1 file changed, 3 insertions(+), 2 deletions(-)"
  }
]
```
