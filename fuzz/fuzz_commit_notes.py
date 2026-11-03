# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Fuzz the commit-msg hook parser that reads AI-written commit messages."""
import sys

import atheris

with atheris.instrument_imports():
    from cve_agent.commit_notes import (
        check_note_budget,
        format_violations,
        parse_conflict_notes,
        strip_comments,
    )


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    # The stanza parser only runs after the notes heading, which random bytes
    # rarely hit; prefix it on half the inputs to reach the deeper code.
    prefix = "subject\n\nConflicts Resolved:\n" if fdp.ConsumeBool() else ""
    msg = prefix + fdp.ConsumeUnicodeNoSurrogates(16384)
    msg = strip_comments(msg)
    parse_conflict_notes(msg)
    format_violations(check_note_budget(msg))


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
