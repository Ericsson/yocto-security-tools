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
streaming, provider-specific reasoning controls, image/audio input, or
arbitrary custom tools. Compatibility with those features is not claimed.

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
Completions request does not set it. Operational guidance is to select a
context window comfortably larger than the expected context file, tool
schemas, diffs, and build-diagnostic history. A larger window does not
guarantee correct tool use.

Local Ollama normally needs no API key. The default loopback URL is already
`http://127.0.0.1:11434/v1`, so `CVE_AGENT_OPENAI_BASE_URL` is shown above for
clarity rather than necessity.

## Configuration and precedence

CLI values override environment values, which override defaults:

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
| Remote opt-in | `--openai-allow-remote`, `CVE_AGENT_OPENAI_ALLOW_REMOTE` | false |
| Remote HTTP opt-in | `--openai-allow-insecure-remote-http`, `CVE_AGENT_OPENAI_ALLOW_INSECURE_REMOTE_HTTP` | false |

`OPENAI_MODEL` is deliberately not a fallback: the native backend has no
Claude-specific or generic OpenAI model default. The environment variable
named by the key-variable setting contains the secret. There is no command-line
option that accepts a secret value.

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

Loopback requests explicitly bypass ambient `HTTP_PROXY`, `HTTPS_PROXY`, and
`ALL_PROXY` settings, independent of `NO_PROXY`, so a local credential is not
routed through an environment-configured proxy. Explicitly opted-in remote
endpoints retain `requests`' normal proxy-environment behavior. Redirects are
disabled in both cases and credentials never follow a redirect.

## Approval, logs, and transcripts

Pass `--interactive` (or `-i`) to approve native file/Git mutations, builds,
and terminal outcomes. Inspection calls do not prompt. The prompt offers a
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
