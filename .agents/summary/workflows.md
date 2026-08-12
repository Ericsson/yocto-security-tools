# Workflows

## End-to-End Pipeline

```mermaid
sequenceDiagram
    participant User
    participant Extractor as cve-metadata-extractor
    participant Corrector as cve-corrector
    participant Agent as cve-agent
    participant AI as kiro-cli

    User->>Extractor: --yocto-summary cve-summary.json
    Extractor->>Extractor: Query Debian, OSV, NVD, Ubuntu
    Extractor-->>User: cve-metadata.json

    User->>Agent: --cve-id CVE-XXXX --cve-info cve-metadata.json --trust
    Agent->>Corrector: subprocess (initial attempt)
    alt Clean cherry-pick (exit 0)
        Corrector-->>Agent: EXIT_SUCCESS
        Agent-->>User: Done
    else Conflict (exit 1)
        Corrector-->>Agent: EXIT_CONFLICT
        Agent->>AI: Context + conflict details
        AI-->>Agent: Resolution
        Agent->>Corrector: --continue
        Corrector-->>Agent: EXIT_SUCCESS
        Agent-->>User: Done
    end
```

## Metadata Extraction Workflow

```mermaid
flowchart TD
    Start["Load CVE list"] --> ForEach["For each CVE"]
    ForEach --> Sources["Query enabled sources"]
    Sources --> Debian["Debian Tracker"]
    Sources --> OSV["OSV API"]
    Sources --> NVD["NVD / CVEList V5"]
    Sources --> Ubuntu["Ubuntu API"]
    Debian & OSV & NVD & Ubuntu --> Merge["Merge & deduplicate"]
    Merge --> Enrich["Enrich (component deduction)"]
    Enrich --> OECheck{"Check OE status?"}
    OECheck -->|yes| OEStatus["Query OE branches"]
    OECheck -->|no| Save
    OEStatus --> Save["Save to cve-metadata.json"]
    Save --> ForEach
```

**Key behaviors**:
- Sources run in registration order; results are merged
- Hash deduplication by commit SHA
- Component name deduced from source data or `--cve-component-name` override
- OE status check is optional (`--check-oe-status` flag)

## Corrector Workflow (State Machine)

```mermaid
stateDiagram-v2
    [*] --> LoadMetadata
    LoadMetadata --> CheckCveStatus : metadata valid
    LoadMetadata --> EXIT_METADATA_ERROR : invalid

    CheckCveStatus --> SetupWorkspace : Unpatched / not set / cpe: scope mismatch
    CheckCveStatus --> EXIT_IGNORED_BY_STATUS : Ignored or Patched

    SetupWorkspace --> CheckApplicability
    CheckApplicability --> CherryPick : applicable
    CheckApplicability --> EXIT_NOT_APPLICABLE : not applicable
    CheckApplicability --> EXIT_ALREADY_APPLIED : already fixed

    CherryPick --> Build : clean apply
    CherryPick --> EXIT_CONFLICT : conflicts

    Build --> Ptest : build passes
    Build --> EXIT_BUILD_ERROR : build fails

    Ptest --> Finish : tests pass
    Ptest --> EXIT_PTEST_ERROR : tests fail

    Finish --> EXIT_SUCCESS
```

### Corrector Steps Detail

1. **LoadMetadata**: Read `cve-metadata.json`, validate CVE entry exists
2. **SetupWorkspace**: `devtool modify <recipe>`, setup upstream remote, create CVE branch
3. **CheckApplicability**: `git blame` analysis to verify vulnerable code exists in recipe version
4. **CherryPick**: Try strategies in order:
   - Single commit cherry-pick
   - Series application (if `series` data available)
   - Least-conflict commit selection (if multiple hashes)
5. **Build**: `devtool build <recipe>` (skippable with `--skip-build`)
6. **Ptest**: Enable ptest, run before/after comparison (skippable)
7. **Finish**: `devtool finish`, update recipe SRC_URI, create meta-layer commit

## Agent Orchestration Loop

```mermaid
flowchart TD
    Start["process_single_cve()"] --> RunCorrector["Run cve-corrector"]
    RunCorrector --> CheckExit{"Exit code?"}

    CheckExit -->|0 SUCCESS| Done["Return SUCCESS"]
    CheckExit -->|11 ALREADY_APPLIED| Skip["Return SKIPPED"]
    CheckExit -->|12 NOT_APPLICABLE| Skip
    CheckExit -->|Unrecoverable 2,5-10| Escalate["Return ESCALATED"]
    CheckExit -->|Recoverable 1,3,4| ResLoop["Resolution Loop"]

    ResLoop --> BuildContext["Build AI context"]
    BuildContext --> SpawnAI["Spawn AI session"]
    SpawnAI --> CheckResolved{"Resolved?"}

    CheckResolved -->|yes| Review{"Trust mode?"}
    Review -->|trust| RerunCorrector["Re-run corrector --continue"]
    Review -->|interactive| Approve["Request human approval"]
    Approve -->|approved| RerunCorrector
    Approve -->|rejected| ResLoop

    CheckResolved -->|no / timeout| Retry{"Retries left?"}
    Retry -->|yes| ResLoop
    Retry -->|no| Escalate

    RerunCorrector --> CheckExit2{"Exit code?"}
    CheckExit2 -->|0| Done
    CheckExit2 -->|Recoverable| ResLoop
    CheckExit2 -->|Unrecoverable| Escalate
```

## AI Session Workflow

```mermaid
sequenceDiagram
    participant Agent as orchestrator.py
    participant Session as session.py
    participant Backend as selected AIBackend
    participant Endpoint as model endpoint
    participant Native as typed host runtime
    participant Hook as git pre-commit hook

    Agent->>Session: guarded_session(config, context)
    Session->>Session: Install scope hook (allowed_files)
    Session->>Session: Log session start
    Session->>Backend: run_session(prompt, workspace, ...)
    alt kiro or claude CLI backend
        Backend->>Backend: launch guarded agent CLI
        Note over Backend: CLI agent follows permitted shell/file workflow
    else native openai backend
        Backend->>Endpoint: POST /chat/completions with messages + tools
        Endpoint-->>Backend: assistant tool_calls with IDs
        Backend->>Native: sequential typed dispatch + approval
        Native-->>Backend: structured tool results / verified finish
        Note over Backend,Native: no arbitrary shell or agent runtime
    end
    Backend->>Hook: git commit triggers hook
    Hook-->>Backend: Reject if unauthorized files
    Backend-->>Session: SessionResult
    Session->>Session: Check resolution state
    Session->>Session: Build deviation section
    Session->>Session: Write audit log
    Session->>Session: Remove scope hook
    Session-->>Agent: SessionResult
```

The native branch creates a mandatory mode-`0600` JSONL transcript and shares
one deadline across HTTP, typed Git, approvals, build, and terminal checks.
Only host-verified `finish` resolves the session. Unresolved results carry safe
operator guidance plus the transcript path; the outer guard still reverts
out-of-scope changes and writes its independent audit. The orchestrator does
not read a conclusion or advance the corrector unless that guarded result is
resolved; unresolved terminal artifacts are removed.

## Knowledge Base Workflow

```mermaid
flowchart TD
    Resolve["CVE resolved successfully"] --> Gather["gather_pattern_details()"]
    Gather --> Similar["find_similar() in knowledge base"]
    Similar --> Prompt{"Trust mode?"}
    Prompt -->|trust| AutoSave["Auto-save pattern"]
    Prompt -->|interactive| Ask["Ask user to save?"]
    Ask -->|yes| Save["save_knowledge_pattern()"]
    Ask -->|no| Skip["Skip"]
    AutoSave & Save --> Done["Pattern stored in knowledge.json"]

    subgraph "Future runs"
        Context["build_context()"] --> Load["Load knowledge base"]
        Load --> Match["find_similar(recipe, files)"]
        Match --> Include["Include in AI prompt"]
    end
```

## Resume (--continue) Workflow

```mermaid
flowchart TD
    Start["cve-corrector --continue"] --> LoadState["Load state from JSON"]
    LoadState --> CheckStep{"current_step?"}
    CheckStep -->|cherry_pick| Conflicts["Check if conflicts resolved"]
    Conflicts -->|resolved| Build["Continue to build step"]
    Conflicts -->|still present| EXIT_CONFLICT
    CheckStep -->|build| Build
    CheckStep -->|ptest| Ptest["Run ptest"]
    CheckStep -->|finish| Finish["devtool finish"]
    Build --> Ptest
    Ptest --> Finish
    Finish --> EXIT_SUCCESS
```

## Batch Processing (Agent)

```mermaid
flowchart TD
    Start["--cve-list cves.txt"] --> Parse["Read CVE IDs"]
    Parse --> Loop["For each CVE"]
    Loop --> Process["process_single_cve()"]
    Process --> Result{"Status?"}
    Result -->|SUCCESS/RESOLVED| Next["Continue to next"]
    Result -->|FAILED/ESCALATED| Check{"--continue-on-error?"}
    Check -->|yes| Next
    Check -->|no| Stop["Stop batch"]
    Next --> Loop
    Loop --> Summary["Print batch summary"]
```
