#!/usr/bin/env python3
"""Run gatehouse straight from a checkout or a skill folder, no install needed.

    python3 scripts/gatehouse.py check --status GATES.md
    python3 scripts/gatehouse.py lint GATES.md
    python3 scripts/gatehouse.py stop-hook < payload.json
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from gatehouse.__main__ import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
