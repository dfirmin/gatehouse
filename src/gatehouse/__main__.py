"""Command-line entry point: `gatehouse check | lint | stop-hook`."""

from __future__ import annotations

import sys
from typing import List, Optional

from . import __version__

USAGE = """usage: gatehouse <command> [args]

commands:
  check       run gates, record evidence, manage scopes and leases
  lint        audit whether a ledger's gates can fail honestly (never executes)
  stop-hook   Claude Code Stop hook; reads the hook payload on stdin
  version     print the version

Run `gatehouse <command> --help` for command options."""


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0 if args else 2
    command, rest = args[0], args[1:]
    if command == "check":
        from .check import main as run
    elif command == "lint":
        from .lint import main as run
    elif command in ("stop-hook", "stop_hook"):
        from .stop_hook import main as run
    elif command in ("version", "--version", "-V"):
        print(__version__)
        return 0
    else:
        sys.stderr.write(f"gatehouse: unknown command {command!r}\n{USAGE}\n")
        return 2
    return run(rest)


if __name__ == "__main__":
    sys.exit(main())
