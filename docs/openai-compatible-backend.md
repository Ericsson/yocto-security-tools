<!-- SPDX-License-Identifier: MIT -->
# Native OpenAI-compatible backend

The `openai` backend calls `POST <api-root>/chat/completions` directly. The
agent loop, typed tool execution, approval checks, build validation, and
terminal-state verification all run inside `yocto-security-tools`. It does not
invoke Claude Code, Codex CLI, or any other agent runtime.

## Compatibility contract

An endpoint is compatible with this first implementation when it supports this
portable subset:

- non-streaming JSON responses from `POST <api-root>/chat/completions`;
- `model` and `messages` request fields;
- OpenAI-style function `tools` and assistant `tool_calls`;
- a unique tool-call ID that can be echoed in the corresponding
  `role: "tool"` message; and
- a model that reliably selects and uses the supplied tools.

Function arguments may be JSON strings, as in the OpenAI schema, or decoded
JSON objects, as returned by some Ollama-compatible servers. Deterministic
tests cover both forms.

The backend does not require `/models`, Responses API conversation state,
streaming, image/audio input, arbitrary custom tools, arbitrary headers, or an
arbitrary request-body extension. Named profiles may add only the portable
`temperature`, `top_p`, and `reasoning_effort` fields described below.

## Typed commit recording

Native Git operations are closed capabilities: revisions and exact paths are
data, never arbitrary options. Cherry-pick start/continue/abort/skip are
separate tools. `git_commit(paths, message)` stages only the named authorized
paths and creates a bounded follow-up commit.
`git_amend(paths, message_mode, message?)` uses either fixed
`message_mode=no_edit` or a bounded replacement message. The host checks the
repository state, NUL-delimited staged set, regular-file modes, and allowed-file
scope before execution and verifies the resulting commit afterward.

Replacement and follow-up messages receive one trusted native provenance
trailer. Message text is carried in a mode-`0600` Git-internal temporary file,
not as model-selected argv. A commit or amend records source content without
changing it, so it does not invalidate a successful build of that same content.
Staging and unstaging likewise do not change the content generation. File
edits, removals, conflict restoration, and cherry-pick content changes do. This
supports the normal sequence: repair an allowed file, build successfully,
amend the exact repair paths, then request `finish(done)` with a clean tree.

The runtime owns an explicit trusted Git state containing the session root and
tree, current trusted commit and tree, expected parent basis, last typed Git
operation, content/build generations, and a digest of the allowed path set.
Every commit-producing tool checks that it started at the trusted HEAD, that
the resulting parents match the operation (including replacement parents for
amend), that the repository has no operation or conflict left in progress,
that the index is resolved, and that the complete root-to-result tree delta is
within scope. Only after all checks pass does the runtime advance the trusted
commit. Consequently, `finish(done)` accepts an authorized amend without
weakening protection against an externally replaced HEAD. Old/new commit and
tree IDs plus the invariant results are recorded in the native and durable
transcripts, with the latest state retained as `trusted-git-state.json`.

Abort and single-commit skip are trusted rollback operations. They may restore
paths named by the active cherry-pick even when those paths are unavailable or
outside the model's write scope, because the postcondition must exactly match
the already trusted session HEAD and tree. They may also discard exact paths
mutated through typed tools during that cherry-pick. Any unrelated tracked edit
still blocks rollback, including an edit to an otherwise allowed file that was
not produced by the typed runtime. Rollback provenance is reset at every new
cherry-pick and successful trusted commit transition, so paths touched by an
earlier operation can never authorize discarding a later external edit.

## Local Ollama quick start

Choose an Ollama model that advertises tool/function calling and has enough
context for source excerpts, diffs, tool schemas, and build diagnostics. Model
availability and tool-use quality vary, so this project does not prescribe a
universal model.

In the first terminal, start Ollama:

```bash
ollama serve
```

In a second terminal, replace the two clearly marked values, pull the selected
model, enter the Yocto build environment, and run the agent:

```bash
export OLLAMA_TOOL_MODEL='replace-with-a-tool-capable-model'
export CVE_METADATA='/absolute/path/to/cve-metadata.json'
ollama pull "$OLLAMA_TOOL_MODEL"

export CVE_AGENT_OPENAI_BASE_URL='http://127.0.0.1:11434/v1'
export CVE_AGENT_OPENAI_MODEL="$OLLAMA_TOOL_MODEL"

cve-agent --backend openai --cve-id CVE-2024-1234 --cve-info "$CVE_METADATA"
```

The invocation supplies the actual required `cve-agent` inputs: one of
`--cve-id`/`--cve-list` plus `--cve-info` (or the documented `--fix-url` and
`--recipe` alternative). Run `cve-agent --help` for the broader workflow and
build options.

Ollama's model configuration controls the context window; the portable Chat
Completions request cannot set a model's context size. A named profile can
therefore create a dedicated Ollama alias with a bounded `num_ctx`, leaving the
installed source model unchanged. Operational guidance is to select a context
window comfortably larger than the expected context file, tool schemas, diffs,
and build-diagnostic history. A larger window does not guarantee correct tool
use.

Local Ollama normally needs no API key. The default loopback URL is already
`http://127.0.0.1:11434/v1`, so `CVE_AGENT_OPENAI_BASE_URL` is shown above for
clarity rather than necessity.

## Configuration and precedence

`--backend openai` remains file-free. CLI values override environment values,
which override defaults:

| Setting | Precedence, highest first | Default |
|---|---|---|
| Model | `--model`, `CVE_AGENT_OPENAI_MODEL` | none; required |
| API root | `--openai-base-url`, `CVE_AGENT_OPENAI_BASE_URL`, `OPENAI_BASE_URL` | `http://127.0.0.1:11434/v1` |
| Key variable name | `--openai-api-key-env`, `CVE_AGENT_OPENAI_API_KEY_ENV` | `OPENAI_API_KEY` |
| Model turns | `--openai-max-steps`, `CVE_AGENT_OPENAI_MAX_STEPS` | `20` |
| Total tool calls | `--openai-max-tool-calls`, `CVE_AGENT_OPENAI_MAX_TOOL_CALLS` | `100` |
| Output-token request | `--openai-max-output-tokens`, `CVE_AGENT_OPENAI_MAX_OUTPUT_TOKENS` | `8192` |
| Connect timeout | `--openai-connect-timeout`, `CVE_AGENT_OPENAI_CONNECT_TIMEOUT` | `10` seconds |
| Request timeout | `--openai-request-timeout`, `CVE_AGENT_OPENAI_REQUEST_TIMEOUT` | `120` seconds |
| Temperature | `--openai-temperature`, `CVE_AGENT_OPENAI_TEMPERATURE` | omitted |
| Top-p | `--openai-top-p`, `CVE_AGENT_OPENAI_TOP_P` | omitted |
| Reasoning effort | `--openai-reasoning-effort`, `CVE_AGENT_OPENAI_REASONING_EFFORT` | omitted |
| Remote opt-in | `--openai-allow-remote`, `CVE_AGENT_OPENAI_ALLOW_REMOTE` | false |
| Remote HTTP opt-in | `--openai-allow-insecure-remote-http`, `CVE_AGENT_OPENAI_ALLOW_INSECURE_REMOTE_HTTP` | false |

`OPENAI_MODEL` is deliberately not a fallback: the native backend has no
Claude-specific or generic OpenAI model default. The environment variable
named by the key-variable setting contains the secret. There is no command-line
option that accepts a secret value.

### Named profiles

`--backend openai-<profile>` reserves the selector suffix for the native
backend. The canonical backend remains `openai`; the profile is recorded
separately in context and transcript metadata. Names are lowercase ASCII,
1–64 characters, begin with a letter or digit, use only letters, digits, `.`,
`_`, or `-`, and may not contain `..`.

The default file is `<repository-root>/etc/openai-<profile>.cfg`, derived from
the installed module location rather than the current directory. An absolute
`CVE_AGENT_OPENAI_CONFIG_DIR` replaces that directory. The agent never searches
the Yocto workspace, parent directories, the working directory, or user
fallback locations. A requested profile must exist; there is no fallback to
plain `openai`.

Profile precedence is:

```text
explicit CLI option > selected profile > environment variable > existing default
```

The file is strict UTF-8 INI, limited to 64 KiB, read once, and may contain
only these sections and keys:

```ini
[openai]
base_url = ...
model = ...
api_key_env = ...
max_steps = ...
max_tool_calls = ...
max_output_tokens = ...
connect_timeout = ...
request_timeout = ...
allow_remote_endpoint = true|false
allow_insecure_remote_http = true|false

[chat]
temperature = 0..2
top_p = >0..1
reasoning_effort = none|low|medium|high|max

[ollama]
api_base_url = ...
source_model = ...
target_model = ...
num_ctx = ...
create_if_missing = true|false
recreate_if_mismatch = true|false
require_tools = true|false
preload = true|false
keep_alive = ...
verify_context = true|false
```

Unknown/duplicate sections or keys, `[DEFAULT]`, malformed values, symlinked or
world-writable files, and secret-bearing keys are rejected. `api_key_env` names
an environment variable; a profile can never contain an API-key value or add
custom headers/body fields. Absent `[chat]` values are omitted from JSON rather
than sent as `null`.

### Optional Ollama preparation

`[ollama]` is profile-only. Its native API origin must exactly match the
validated OpenAI endpoint's scheme, normalized hostname, and effective port;
the same remote and insecure-HTTP opt-ins apply. When `api_base_url` is absent,
it can be derived only from an unambiguous OpenAI `/v1` root. The OpenAI model
must exactly identify the normalized target alias.

After the mandatory transcript is created and before the first Chat
Completions request, preparation performs this bounded sequence:

1. `POST /api/show` for the target.
2. If missing and allowed, verify that the source is installed, then
   `POST /api/create` for the dedicated alias with `parameters.num_ctx` and
   `stream: false`.
3. Verify the target's serialized `num_ctx`, requested `tools` capability, and
   any reported architecture context maximum. A mismatched alias is recreated
   only when explicitly enabled, then shown and verified again.
4. If `preload` is enabled, `POST /api/generate` with an empty prompt,
   `options.num_ctx`, and the configured `keep_alive`.
5. If `verify_context` is enabled, `GET /api/ps` must report the exact target
   model and exact configured `context_length`.

Preparation never pulls, deletes, pushes, copies unrelated models, or modifies
the source model. In interactive mode, creating or recreating the alias needs
one explicit approval; EOF and non-TTY input deny. Inspection and preload add
no second prompt. A setup failure ends unresolved with its transcript and does
not enter the model loop.

The preload `keep_alive` value is only an Ollama inference hint; it does not
change server-global settings. Flash Attention, KV-cache type, parallelism,
server context defaults, and loaded-model limits remain operator-controlled.
An L40S profile should start conservatively, such as at 32K, and may use CPU
offload; this guide does not claim that Qwen3-Coder-Next fits fully in 48 GB
VRAM. Site endpoint profiles are intentionally kept out of version control.

## Authentication and endpoint security

A keyed loopback endpoint can be configured without exposing the key in
process arguments:

```bash
export LOCAL_MODEL_API_KEY='replace-with-your-key'
export CVE_AGENT_OPENAI_MODEL='replace-with-a-tool-capable-model'
cve-agent --backend openai --cve-id CVE-2024-1234 --cve-info /absolute/path/to/cve-metadata.json --openai-base-url http://127.0.0.1:11434/v1 --openai-api-key-env LOCAL_MODEL_API_KEY
```

A remote endpoint requires HTTPS and explicit remote consent:

```bash
export REMOTE_MODEL_API_KEY='replace-with-your-key'
export CVE_AGENT_OPENAI_MODEL='replace-with-a-tool-capable-model'
cve-agent --backend openai --cve-id CVE-2024-1234 --cve-info /absolute/path/to/cve-metadata.json --openai-base-url https://models.example/v1 --openai-api-key-env REMOTE_MODEL_API_KEY --openai-allow-remote
```

Remote plain HTTP is refused even with `--openai-allow-remote`. The separate
`--openai-allow-insecure-remote-http` opt-in exists for exceptional, explicitly
accepted deployments:

```bash
export REMOTE_MODEL_API_KEY='replace-with-your-key'
export CVE_AGENT_OPENAI_MODEL='replace-with-a-tool-capable-model'
cve-agent --backend openai --cve-id CVE-2024-1234 --cve-info /absolute/path/to/cve-metadata.json --openai-base-url http://models.example/v1 --openai-api-key-env REMOTE_MODEL_API_KEY --openai-allow-remote --openai-allow-insecure-remote-http
```

Remote inference can disclose the CVE context, source excerpts, diffs, Git
messages, and bounded build output to the endpoint operator. More precisely,
the endpoint receives the system/user conversation and every model-visible
tool result; this can include intentionally read source/context files, Git
diffs and messages, and build-log tails. Do not opt into a remote endpoint if
that data must remain local.

Committing a site-specific endpoint profile makes its destination and data
routing policy part of the repository. Review that choice like other security
configuration. A remote plain-HTTP profile explicitly accepts that traffic is
unencrypted; use it only on a trusted, controlled network or replace it with
HTTPS.

Loopback requests explicitly bypass ambient `HTTP_PROXY`, `HTTPS_PROXY`, and
`ALL_PROXY` settings, independent of `NO_PROXY`, so a local credential is not
routed through an environment-configured proxy. Explicitly opted-in remote
endpoints retain `requests`' normal proxy-environment behavior. Redirects are
disabled in both cases and credentials never follow a redirect.

## Approval, logs, and transcripts

Pass `--interactive` (or `-i`) to approve native file/Git mutations—including
commit and amend—builds, and terminal outcomes. Inspection calls do not prompt. The prompt offers a
one-time approval, approval for the operation class, or denial; EOF and
non-TTY input deny. A denial is returned to the model as a structured tool
error and is recorded in the transcript. Without `--interactive`, these
per-tool prompts are omitted, while file scope and terminal invariants remain
enforced. The separate `--trust` option controls the outer review workflow and
retains its existing warning.

Every native session requires a redacted JSONL transcript. The CLI prints its
exact path. It is created as:

`<build>/workspace/cve_agent/<recipe>/openai-<model>-<pid>-<time>.jsonl`

with mode `0600`. It can still contain sensitive source, model, and workflow
information despite bounded fields and API-key redaction. Successful and
failed builds write at most 16 MiB of the build stream to mode-`0600`
`<build>/workspace/cve_agent/<recipe>/openai-build.log`; the process output is
still drained to avoid deadlock, and only a 16 KiB tail is returned to the
model. The tool result reports when the on-disk log was truncated.

Native Git and `devtool build` children receive a filtered locale-stable
environment. API-key variables, proxy variables, `GIT_SSH`, and SSH-agent
variables are not forwarded, and PATH entries inside the writable source or
agent-artifact roots are removed. A build that depends on authenticated
network access through those variables must be prefetched or performed by the
operator outside the native session; widening the model child environment is
not supported.

If an endpoint echoes the configured API key in a proposed tool argument, the
host refuses that call before approval or side effects. Shared redaction also
removes exact configured-key and bearer forms from HTTP diagnostics,
transcripts, and trusted terminal text.

## Troubleshooting

- Connection failure: confirm Ollama or the compatible server is running and
  that `--openai-base-url` names the API root. The client appends exactly one
  `/chat/completions` path.
- Wrong base URL: use the root once, normally ending in `/v1`. Do not supply
  `/chat/completions`, and remove a duplicated `/v1/v1` introduced by combined
  server and client configuration.
- Authentication failure: export the variable named by
  `--openai-api-key-env` or `CVE_AGENT_OPENAI_API_KEY_ENV`; the default name is
  `OPENAI_API_KEY`. Do not put the key in the URL or command line.
- Unknown model or HTTP 404: verify `--model`/`CVE_AGENT_OPENAI_MODEL` against
  the endpoint and verify the API root. The backend does not probe `/models`.
- Model stops without tools: select a model with reliable function-tool
  support. One text-only stop receives a correction; a second ends unresolved.
- Insufficient context: increase the model's server-side context setting or
  reduce supplied context. A `length` finish reason is never treated as
  success.
- Incompatible schema: require a non-streaming Chat Completions response with
  assistant `tool_calls`, function names/arguments, and stable call IDs.
- Step or deadline exhaustion: inspect the transcript before changing
  `--openai-max-steps`, `--openai-max-tool-calls`, or `--session-timeout`.
- Build timeout/failure: inspect `openai-build.log`. A build success older than
  the latest mutation cannot authorize `finish(status="done")`.
- Interactive denial: rerun only after deciding whether the denied operation
  is appropriate; do not bypass file scope or remote-endpoint gates.
- Session ends without `finish`: inspect the final transcript events. Only an
  accepted typed `finish` call creates a verified terminal outcome; assistant
  prose is not completion.

## Optional live compatibility probe

The normal test suite uses no live endpoint. Maintainers can explicitly probe
a running endpoint and selected model with:

```bash
export CVE_AGENT_LIVE_OPENAI_TEST=1
export CVE_AGENT_OPENAI_MODEL='replace-with-a-tool-capable-model'
export CVE_AGENT_OPENAI_BASE_URL='http://127.0.0.1:11434/v1'
pytest -m live tests/agent/test_openai_live.py
```

For a remote probe, the same HTTPS and explicit remote opt-in environment rules
apply. The live test creates a disposable Git workspace and requires the model
to read one harmless file and reach a trusted `needs_human` finish without
modifying the repository. It is not a quality guarantee for CVE backporting.
