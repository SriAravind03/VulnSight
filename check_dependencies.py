#!/usr/bin/env python3
"""
Standalone dependency checker for Sentinel Vulnerability Scanner.

Run this before first launch (or any time) to verify that required
Python packages and the optional nmap binary are available:

    python check_dependencies.py
"""

from __future__ import annotations

import importlib
import shutil
import sys

REQUIRED_PACKAGES = {
    "ttkbootstrap": "ttkbootstrap",
    "nmap": "python-nmap",
    "requests": "requests",
    "bs4": "beautifulsoup4",
    "reportlab": "reportlab",
    "jinja2": "Jinja2",
    "matplotlib": "matplotlib",
    "yaml": "PyYAML",
}


def main() -> int:
    print("Checking Python version...")
    if sys.version_info < (3, 10):
        print(f"  WARNING: Python 3.10+ recommended, found {sys.version.split()[0]}")
    else:
        print(f"  OK: Python {sys.version.split()[0]}")

    print("\nChecking required Python packages...")
    missing = []
    for module_name, pip_name in REQUIRED_PACKAGES.items():
        try:
            importlib.import_module(module_name)
            print(f"  OK: {pip_name}")
        except ImportError:
            print(f"  MISSING: {pip_name}")
            missing.append(pip_name)

    print("\nChecking optional nmap binary...")
    if shutil.which("nmap"):
        print("  OK: nmap binary found on PATH")
    else:
        print("  NOT FOUND: nmap binary. The app will use its built-in fallback scanner.")

    if missing:
        print("\nMissing packages detected. Install them with:")
        print(f"  pip install {' '.join(missing)}")
        print("or simply:")
        print("  pip install -r requirements.txt")
        return 1

    print("\nAll required Python packages are installed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
