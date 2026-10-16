#!/usr/bin/env python3
"""
Sentinel Vulnerability Scanner
===============================

Entry point for the desktop application.

IMPORTANT / LEGAL: This tool is designed exclusively for assessing
systems you own or have explicit written authorization to test.
Unauthorized scanning of computer systems may violate the law in your
jurisdiction (e.g. the U.S. Computer Fraud and Abuse Act, the UK
Computer Misuse Act, or local equivalents). By running this software
you confirm you will use it only against authorized targets.

Usage:
    python main.py
"""

from __future__ import annotations

import sys

from utils.logger import get_logger, setup_logging

logger = get_logger("main")


def _check_dependencies() -> list[str]:
    """Return a list of human-readable messages for any missing/mismatched deps."""
    warnings = []
    try:
        import nmap  # noqa: F401
    except ImportError:
        warnings.append(
            "python-nmap is not installed (pip install python-nmap). "
            "The application will use the built-in fallback scanner."
        )
    import shutil
    if shutil.which("nmap") is None:
        warnings.append(
            "The 'nmap' binary was not found on PATH. Install it for full port/OS "
            "detection features; the application will otherwise use its built-in "
            "fallback scanner automatically."
        )

    _TESTED_TTKBOOTSTRAP = "1.10.1"
    try:
        import ttkbootstrap
        installed = getattr(ttkbootstrap, "__version__", None)
        if installed and installed != _TESTED_TTKBOOTSTRAP:
            warnings.append(
                f"ttkbootstrap {installed} is installed, but this application was built and "
                f"tested against ttkbootstrap {_TESTED_TTKBOOTSTRAP}. The UI may not render "
                f"correctly. Run 'pip install -r requirements.txt' inside your virtual "
                f"environment to install the exact tested version."
            )
    except ImportError:
        pass  # reported by the GUI import failure path below

    return warnings


def main() -> int:
    setup_logging()
    logger.info("Starting Sentinel Vulnerability Scanner...")

    for warning in _check_dependencies():
        logger.warning(warning)

    try:
        from gui.main_window import SentinelApp
    except ImportError as exc:
        logger.error("Failed to import GUI dependencies: %s", exc)
        print(
            "\nMissing dependencies. Please run:\n"
            "    pip install -r requirements.txt\n"
        )
        return 1

    app = SentinelApp()
    app.mainloop()
    logger.info("Application closed cleanly.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
