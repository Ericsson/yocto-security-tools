# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Fuzz the URL parsers that turn untrusted advisory links into hashes/repos.

Only the pure, offline helpers are exercised; ``parse_fix_urls`` is skipped
because PR URLs trigger network requests.
"""
import sys

import atheris

with atheris.instrument_imports():
    from shared.url_parser import HASH_RE, deduce_repo_url, extract_commit_hash


def TestOneInput(data: bytes) -> None:
    url = atheris.FuzzedDataProvider(data).ConsumeUnicodeNoSurrogates(4096)

    commit = extract_commit_hash(url)
    if commit is not None and not HASH_RE.fullmatch(commit):
        raise AssertionError(f"non-hash returned for {url!r}: {commit!r}")

    repo = deduce_repo_url(url)
    if repo is not None and not isinstance(repo, str):
        raise AssertionError(f"non-str repo for {url!r}: {repo!r}")


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
