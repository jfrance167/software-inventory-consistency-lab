"""Trusted local source bootstrap; permits -I without package installation."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from inventory_lab.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
