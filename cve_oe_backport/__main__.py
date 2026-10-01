"""CLI entry point for preparing OpenEmbedded CVE backports."""

from .backport import main

if __name__ == "__main__":
    raise SystemExit(main())
