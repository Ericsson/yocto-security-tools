#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Schema-v2 adapter for the shell integration runner.

All outcome decisions delegate to :mod:`cve_agent.result`; this file only
handles CSV transport and legacy-file migration.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path

# Direct execution makes the script directory, not the repository, sys.path[0].
# Anchor the import to this checked-out source tree and never to cwd.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cve_agent.result import (  # noqa: E402
    RESULT_SCHEMA_VERSION,
    ResultOutcome,
    SecurityStatus,
    migrate_legacy_status,
    security_gate_satisfied,
)

LEGACY_COLUMNS = [
    "cve_id", "recipe", "status", "exit_code", "diff_changes",
    "diff_patches", "diff_files", "duration_s",
]
OUTCOME_COLUMNS = [
    "schema_version", "workflow_status", "build_status", "security_status",
    "failure_class", "failure_code", "legacy_status", "summary_state",
]
CSV_COLUMNS = LEGACY_COLUMNS + OUTCOME_COLUMNS


def _outcome_from_row(row: Mapping[str, str], mode: str) -> ResultOutcome:
    if row.get("schema_version"):
        return ResultOutcome.from_dict({
            "schema_version": int(row["schema_version"]),
            "workflow_status": row["workflow_status"],
            "build_status": row["build_status"],
            "security_status": row["security_status"],
            "failure_class": row.get("failure_class") or None,
            "failure_code": row.get("failure_code") or None,
            "legacy_status": row.get("legacy_status") or row.get("status") or None,
        })
    status = row.get("status", "")
    # A successful old full-mode row records that the old runner completed its
    # build path.  This is build evidence only, never semantic verification.
    build_evidence = mode == "full" and status in {
        "SUCCESS", "IDENTICAL", "AGENT_RESOLVED",
    }
    return migrate_legacy_status(
        status,
        build_evidence=build_evidence,
        failure_code=(row.get("exit_code") or None) if status.startswith("FAIL") else None,
    )


def _outcome_fields(outcome: ResultOutcome) -> list[str]:
    value = outcome.to_dict()
    return [
        str(RESULT_SCHEMA_VERSION),
        str(value["workflow_status"]),
        str(value["build_status"]),
        str(value["security_status"]),
        str(value["failure_class"] or ""),
        str(value["failure_code"] or ""),
        str(value["legacy_status"] or ""),
        str(value["summary_state"]),
    ]


def _fields(args: argparse.Namespace) -> None:
    outcome = migrate_legacy_status(
        args.status,
        build_evidence=args.build_evidence,
        failure_code=args.failure_code,
    )
    print(",".join(_outcome_fields(outcome)))


def _artifact_fields(args: argparse.Namespace) -> None:
    with Path(args.result_json).open(encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, Mapping):
        raise ValueError("durable result must be a JSON object")
    print(",".join(_outcome_fields(ResultOutcome.from_dict(value))))


def _migrate(args: argparse.Namespace) -> None:
    path = Path(args.csv_file)
    with path.open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    temporary = path.with_suffix(path.suffix + ".schema2.tmp")
    with temporary.open("w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, CSV_COLUMNS)
        writer.writeheader()
        for row in rows:
            outcome = _outcome_from_row(row, args.mode)
            normalized = {key: row.get(key, "") for key in LEGACY_COLUMNS}
            normalized.update(dict(zip(OUTCOME_COLUMNS, _outcome_fields(outcome))))
            writer.writerow(normalized)
        target.flush()
        os.fsync(target.fileno())
    os.replace(temporary, path)


def _resumable(args: argparse.Namespace) -> None:
    with Path(args.csv_file).open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    required = SecurityStatus(args.required) if args.required else None
    for row in rows:
        if required is None:
            print(row.get("cve_id", ""))
            continue
        outcome = _outcome_from_row(row, args.mode)
        if security_gate_satisfied(outcome, required):
            print(row.get("cve_id", ""))


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    fields = subparsers.add_parser("fields")
    fields.add_argument("status")
    fields.add_argument("--build-evidence", action="store_true")
    fields.add_argument("--failure-code")
    fields.set_defaults(func=_fields)
    artifact_fields = subparsers.add_parser("artifact-fields")
    artifact_fields.add_argument("result_json")
    artifact_fields.set_defaults(func=_artifact_fields)
    migrate = subparsers.add_parser("migrate")
    migrate.add_argument("csv_file")
    migrate.add_argument("mode")
    migrate.set_defaults(func=_migrate)
    resumable = subparsers.add_parser("resumable")
    resumable.add_argument("csv_file")
    resumable.add_argument("mode")
    resumable.add_argument("--required", default="")
    resumable.set_defaults(func=_resumable)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
