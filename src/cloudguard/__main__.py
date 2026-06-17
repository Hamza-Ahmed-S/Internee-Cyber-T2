"""Allow ``python -m cloudguard`` to run the CLI."""

from __future__ import annotations

from cloudguard.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
