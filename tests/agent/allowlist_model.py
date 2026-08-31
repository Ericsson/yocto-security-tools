# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Model of kiro-cli's ``execute_bash`` guard, shared by the allow-list tests.

The manifests' ``allowedCommands`` regexes are *not* matched against the whole
command line. Behaviour verified empirically against kiro-cli 2.9.0 and
re-confirmed in benchmark run ``bench_20260828_145923``:

1. ``>`` / ``>>`` file redirection is refused unconditionally — no
   ``allowedCommands`` pattern can re-enable it. ``2>&1`` is not a file
   redirect and is accepted.
2. A compound command is split on ``;``, ``|``, ``||`` and ``&&``, and **every**
   part must match an ``allowedCommands`` entry on its own.

Point 2 matters: ``^git show .*$`` looks like it permits
``git show HEAD:f.c | sed -n '1,20p'`` — a naive whole-string ``re.fullmatch``
says yes — but kiro-cli rejected exactly that command in the benchmark, because
the ``sed`` segment was checked separately and had no entry of its own. Tests
that assert a *pipeline* is runnable must therefore use :func:`kiro_permits`,
not ``re.fullmatch``.
"""
import json
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# A bare ``>`` / ``>>`` file redirect. ``2>&1`` (digit before, ``&`` after) is
# not a file redirect and is accepted by kiro-cli.
_FILE_REDIRECT_RE = re.compile(r'(?<![0-9])>>?(?!&)')


def has_file_redirect(command: str) -> bool:
    """Whether ``command`` contains a ``>``/``>>`` file redirect."""
    return _FILE_REDIRECT_RE.search(command) is not None


def split_subcommands(command: str) -> list[str]:
    """Split a compound command the way kiro-cli's guard does."""
    return [part.strip() for part in re.split(r'&&|\|\||[;|]', command)
            if part.strip()]


def kiro_permits(command: str, allowed: list[str]) -> bool:
    """Whether kiro-cli's execute_bash guard would run ``command``."""
    if has_file_redirect(command):
        return False
    return all(any(re.fullmatch(pattern, part) for pattern in allowed)
               for part in split_subcommands(command))


def allowed_commands(agent: str = 'yocto-cve-backport',
                     source: str = 'kiro') -> list[str]:
    """Load an agent manifest's ``allowedCommands`` list.

    Args:
        agent: manifest basename, e.g. ``yocto-cve-backport``.
        source: ``kiro`` for ``.kiro/agents/`` (preferred by
            ``cve_agent.setup`` on editable installs) or ``packaged`` for
            ``cve_agent/agents/``.
    """
    directory = (PROJECT_ROOT / '.kiro' / 'agents' if source == 'kiro'
                 else PROJECT_ROOT / 'cve_agent' / 'agents')
    manifest = json.loads(
        (directory / f'{agent}.json').read_text(encoding='utf-8'))
    return manifest['toolsSettings']['execute_bash']['allowedCommands']
