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

    def run_session(self, prompt: str, workspace_path: Path,
                   allowed_files: set, model: str,
                   timeout: int, interactive: bool) -> SessionResult: ...
    def is_available(self) -> bool: ...
    def setup(self, **kwargs) -> None: ...
```

**Registration**: `register_backend(MyBackend())`

**SessionResult**:
```python
@dataclass
class SessionResult:
    resolved: bool
    duration: float
    transcript_path: Optional[Path] = None
```

## CLI Interfaces

### cve-metadata-extractor

```
cve-metadata-extractor [OPTIONS]

Input (one required):
  --yocto-summary FILE    Yocto cve-summary.json
  --cve-id CVE-XXXX-YYYY  One or more CVE IDs

Options:
  --output FILE           Output path (default: stdout)
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
  --backend NAME          AI backend to use (default: kiro)
  --model NAME            AI model (default: claude-sonnet-5)
  --max-retries N         Per-step retry limit (default: 3)
  --session-timeout SECS  AI session timeout (default: 600)
  --skip-ptest            Skip ptest verification
  --clean                 Clean workspace before starting
  --recipe NAME           Override recipe name
  --mirror-dir DIR        Local git mirror directory
  --meta-layer DIR        Target meta-layer
  --bbappend              Use bbappend mode
```

## Inter-Process Interface

The agent communicates with the corrector via:

| Channel | Format |
|---------|--------|
| Invocation | `subprocess.run([python, -m, cve_corrector, ...])` |
| Exit code | Integer 0–12 (see `shared/exit_codes.py`) |
| State file | `<state_dir>/<recipe>.json` (WorkflowState serialized) |
| Conclusion | `<agent_dir>/conclusion.json` (AI writes when CVE not applicable) |
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
