#!/usr/bin/env python3
"""Explicit isolated-stack entry point for the bounded owned-target harness."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from experiments.attacks.live import main  # noqa: E402

if __name__ == '__main__':
    raise SystemExit(main())
