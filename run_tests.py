#!/usr/bin/env python3
"""Run the whole suite with the stdlib - no pytest required.

    python run_tests.py            # all tests
    python run_tests.py -v         # verbose
    python -m pytest tests -q      # works too, if you have pytest
"""

from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))


def main() -> int:
    verbosity = 2 if "-v" in sys.argv else 1
    suite = unittest.TestLoader().discover(
        start_dir=os.path.join(ROOT, "tests"), pattern="test_*.py", top_level_dir=ROOT
    )
    result = unittest.TextTestRunner(verbosity=verbosity).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
