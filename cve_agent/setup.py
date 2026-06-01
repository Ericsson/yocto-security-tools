# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Agent installation verification and setup for cve_agent.

Checks that required kiro-cli agents are installed (symlinked into
~/.kiro/agents/) and offers to install them if missing.
"""
import shutil
import sys
from pathlib import Path

from shared.exit_codes import EXIT_AGENT_ERROR

# Agents required by cve_agent, defined in this package's .kiro/agents/
REQUIRED_AGENTS = ("yocto-cve-backport", "yocto-cve-backport-interactive")

# Source directory containing agent JSON definitions
# Prefer the project root .kiro/agents/ (editable install), fall back to packaged
_PROJECT_AGENT_DIR = Path(__file__).resolve().parent.parent / ".kiro" / "agents"
_PACKAGED_AGENT_DIR = Path(__file__).resolve().parent / "agents"
AGENT_SOURCE_DIR = _PROJECT_AGENT_DIR if _PROJECT_AGENT_DIR.is_dir() else _PACKAGED_AGENT_DIR

# Global kiro-cli agent directory
KIRO_AGENTS_DIR = Path.home() / ".kiro" / "agents"


def get_missing_agents() -> list[str]:
    """Return list of required agents not installed in ~/.kiro/agents/.

    Returns:
        List of agent names whose JSON configs are missing from the
        global kiro-cli agents directory.
    """
    missing = []
    for name in REQUIRED_AGENTS:
        target = KIRO_AGENTS_DIR / f"{name}.json"
        if not target.exists():
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
    can resolve regardless of working directory.

    Args:
        missing: List of agent names to install.

    Returns:
        True if all agents were installed successfully.
    """
    import json

    KIRO_AGENTS_DIR.mkdir(parents=True, exist_ok=True)
    project_root = AGENT_SOURCE_DIR.parent.parent  # security/ directory

    for name in missing:
        source = AGENT_SOURCE_DIR / f"{name}.json"
        target = KIRO_AGENTS_DIR / f"{name}.json"

        if not source.exists():
            print(f"Error: Agent source not found: {source}", file=sys.stderr)
            return False

        # Load and rewrite file:// URIs to absolute paths
        data = json.loads(source.read_text(encoding='utf-8'))
        prompt_target = None
        if 'prompt' in data and data['prompt'].startswith('file://'):
            rel_path = data['prompt'][len('file://'):]
            prompt_target = (project_root / rel_path).resolve()
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
