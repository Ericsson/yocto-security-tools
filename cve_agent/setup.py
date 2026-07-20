# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Agent installation verification and setup for cve_agent.

Checks that required kiro-cli agents are installed (symlinked into
~/.kiro/agents/) and offers to install them if missing.
"""
import json
import os
import shutil
import sys
from pathlib import Path

from shared.exit_codes import EXIT_AGENT_ERROR
from shared.paths import data_dir

# Agents required by cve_agent, defined in this package's .kiro/agents/
REQUIRED_AGENTS = ("yocto-cve-backport", "yocto-cve-backport-interactive")

# Source directory containing agent JSON definitions
# Prefer the project root .kiro/agents/ (editable install), fall back to packaged
_PROJECT_AGENT_DIR = Path(__file__).resolve().parent.parent / ".kiro" / "agents"
_PACKAGED_AGENT_DIR = Path(__file__).resolve().parent / "agents"
AGENT_SOURCE_DIR = _PROJECT_AGENT_DIR if _PROJECT_AGENT_DIR.is_dir() else _PACKAGED_AGENT_DIR

# Global kiro-cli agent directory
KIRO_AGENTS_DIR = Path.home() / ".kiro" / "agents"

# Packaged copy of the agent prompt, shipped alongside this module.
PACKAGED_AGENT_INSTRUCTIONS = Path(__file__).resolve().parent / "AGENT_INSTRUCTIONS.md"

# Stable, package-location-independent copy of the agent prompt. The kiro
# agent JSON's ``prompt`` field is pointed here (not at PACKAGED_AGENT_INSTRUCTIONS)
# so it keeps working across editable-install moves, reinstalls into a
# different venv/site-packages path, or package upgrades/uninstalls.
STABLE_AGENT_INSTRUCTIONS = data_dir() / "AGENT_INSTRUCTIONS.md"


def sync_agent_instructions() -> Path:
    """Copy the packaged AGENT_INSTRUCTIONS.md to the stable data_dir() path.

    The kiro agent JSON's ``prompt`` field points at this stable copy rather
    than at the package's own copy, so the prompt keeps resolving correctly
    even if the project/package is later moved, reinstalled into a different
    environment, or upgraded — none of which change the XDG data directory.

    Always overwrites the destination so upgrades to the packaged file
    propagate on the next install. Writes to a temporary sibling file and
    ``os.replace()``s it into place (same pattern as ``shared/json_cache.py``)
    so a crash mid-copy can never leave a truncated/corrupt stable copy.

    Returns:
        Path to the synced, stable copy.

    Raises:
        FileNotFoundError: If the packaged AGENT_INSTRUCTIONS.md is missing.
    """
    if not PACKAGED_AGENT_INSTRUCTIONS.is_file():
        raise FileNotFoundError(
            f"Packaged agent instructions not found: {PACKAGED_AGENT_INSTRUCTIONS}")
    STABLE_AGENT_INSTRUCTIONS.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = STABLE_AGENT_INSTRUCTIONS.with_suffix(
        STABLE_AGENT_INSTRUCTIONS.suffix + '.tmp')
    shutil.copyfile(PACKAGED_AGENT_INSTRUCTIONS, tmp_path)
    os.replace(tmp_path, STABLE_AGENT_INSTRUCTIONS)
    return STABLE_AGENT_INSTRUCTIONS


def _prompt_file_path(agent_json: Path) -> tuple[bool, Path | None]:
    """Extract the local filesystem path from an agent JSON's file:// prompt URI.

    Uses the same simple prefix-stripping convention as ``install_agents()``
    (not ``urllib.parse.urlparse``, which misparses relative ``file://``
    URIs by treating the first path segment as a netloc).

    Returns:
        A ``(readable, path)`` tuple. ``readable`` is False if the JSON
        could not be parsed at all (malformed/unreadable file). ``path`` is
        the file:// prompt's Path if present, else None (valid JSON with no
        file:// prompt, or unreadable JSON).
    """
    try:
        data = json.loads(agent_json.read_text(encoding='utf-8'))
    except (json.JSONDecodeError, OSError):
        return False, None
    prompt = data.get('prompt', '')
    if not isinstance(prompt, str) or not prompt.startswith('file://'):
        return True, None
    return True, Path(prompt[len('file://'):])


def _is_stale_install(agent_json: Path) -> bool:
    """Check whether an installed agent JSON is stale and should be reinstalled.

    An install is considered stale if:
      - the JSON file is malformed/unreadable (fail closed — reinstall
        rather than silently keep a broken config), or
      - its ``prompt`` is a ``file://`` URI with an absolute path that no
        longer resolves to an existing file (e.g. the project was relocated,
        or reinstalled into a different venv/site-packages path).

    Only absolute prompt paths are checked: ``install_agents()`` always
    rewrites the prompt to an absolute path on install, so an installed
    JSON with a relative path is not one this tool produced (or is
    unresolvable without knowing the intended base) — leave it alone rather
    than risk false positives.
    """
    readable, prompt_path = _prompt_file_path(agent_json)
    if not readable:
        return True
    if prompt_path is None or not prompt_path.is_absolute():
        return False
    return not prompt_path.is_file()


def get_missing_agents() -> list[str]:
    """Return list of required agents not installed in ~/.kiro/agents/.

    An agent counts as missing if its JSON config file is absent, or if its
    ``prompt`` field is a ``file://`` URI pointing at a file that no longer
    exists (a stale install left behind by a moved/relocated project or a
    reinstall into a different environment).

    Returns:
        List of agent names whose JSON configs are missing or stale in the
        global kiro-cli agents directory.
    """
    missing = []
    for name in REQUIRED_AGENTS:
        target = KIRO_AGENTS_DIR / f"{name}.json"
        if not target.exists() or _is_stale_install(target):
            missing.append(name)
    return missing


def verify_agents_installed() -> bool:
    """Check if all required agents are installed.

    Returns:
        True if all agents are present, False otherwise.
    """
    return len(get_missing_agents()) == 0


def install_agents(missing: list[str]) -> bool:
    """Install missing agents by copying into ~/.kiro/agents/ with resolved paths.

    Copies agent JSON files (rather than symlinking) so that relative file://
    URIs in the 'prompt' field are rewritten to absolute paths that kiro-cli
    can resolve regardless of working directory. The prompt is pointed at
    the stable data_dir() copy (synced from the packaged file here), not at
    the package's own copy, so it survives moves/reinstalls/upgrades.

    Args:
        missing: List of agent names to install.

    Returns:
        True if all agents were installed successfully.
    """
    try:
        sync_agent_instructions()
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return False

    KIRO_AGENTS_DIR.mkdir(parents=True, exist_ok=True)

    for name in missing:
        source = AGENT_SOURCE_DIR / f"{name}.json"
        target = KIRO_AGENTS_DIR / f"{name}.json"

        if not source.exists():
            print(f"Error: Agent source not found: {source}", file=sys.stderr)
            return False

        # Load and rewrite file:// URIs to the stable, package-independent path
        data = json.loads(source.read_text(encoding='utf-8'))
        prompt_target = None
        if 'prompt' in data and data['prompt'].startswith('file://'):
            prompt_target = STABLE_AGENT_INSTRUCTIONS
            data['prompt'] = f"file://{prompt_target}"

        # Remove stale symlink/file before writing
        if target.exists() or target.is_symlink():
            target.unlink()

        target.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
        if prompt_target:
            print(f"  Installed: {name} (prompt -> {prompt_target})")
        else:
            print(f"  Installed: {name}")

    return True


def check_kiro_cli() -> bool:
    """Verify kiro-cli is available on PATH.

    Returns:
        True if kiro-cli is found.
    """
    return shutil.which("kiro-cli") is not None


def ensure_agents(interactive: bool = True) -> None:
    """Verify agent prerequisites and install if user approves.

    Checks for kiro-cli availability and required agent configs.
    In interactive mode, prompts the user before installing.
    Exits with error if prerequisites cannot be met.

    Always re-syncs the stable AGENT_INSTRUCTIONS.md copy (data_dir()) from
    the packaged file, even if the agent JSONs themselves are already
    installed — so content upgrades to the packaged instructions propagate
    on every run, not just on (re)install.

    Args:
        interactive: If True, prompt user for approval before installing.
    """
    if not check_kiro_cli():
        print(
            "Error: kiro-cli not found on PATH.\n"
            "Install it from: https://kiro.dev/docs/install",
            file=sys.stderr,
        )
        sys.exit(EXIT_AGENT_ERROR)

    try:
        sync_agent_instructions()
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(EXIT_AGENT_ERROR)

    missing = get_missing_agents()
    if not missing:
        return

    print(f"\n⚠️  Missing required kiro-cli agents: {', '.join(missing)}")
    print(f"   Source: {AGENT_SOURCE_DIR}")
    print(f"   Target: {KIRO_AGENTS_DIR}\n")

    if interactive:
        response = input("Install missing agents now? [Y/n]: ").strip().lower()
        if response in ("n", "no"):
            print(
                "Agents not installed. Run the setup script manually:\n"
                "  python -m cve_agent.setup",
                file=sys.stderr,
            )
            sys.exit(EXIT_AGENT_ERROR)

    if install_agents(missing):
        print("✓ All required agents installed.\n")
    else:
        print("Error: Failed to install agents.", file=sys.stderr)
        sys.exit(EXIT_AGENT_ERROR)
