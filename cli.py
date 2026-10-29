#!/usr/bin/env python3
"""Root CLI entrypoint for FirewallLang Compiler."""
import os
import sys
from pathlib import Path

# Add backend directory to sys.path
backend_path = Path(__file__).resolve().parent / "backend"
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

from app.cli import run_cli

if __name__ == "__main__":
    run_cli()
