#!/usr/bin/env bash
# Sentinel Vulnerability Scanner - automatic setup script (Linux/macOS)
#
# Creates a virtual environment, installs Python dependencies, checks for
# the optional nmap binary, and prepares the runtime directories.

set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR=".venv"

echo "== Sentinel Vulnerability Scanner setup =="

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "ERROR: $PYTHON_BIN was not found. Please install Python 3.12+." >&2
    exit 1
fi

PY_VERSION=$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
echo "Using Python $PY_VERSION"

if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment in $VENV_DIR ..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

echo "Upgrading pip..."
pip install --upgrade pip >/dev/null

echo "Installing dependencies from requirements.txt..."
pip install -r requirements.txt

echo "Creating runtime directories..."
mkdir -p logs exports database

if command -v nmap >/dev/null 2>&1; then
    echo "nmap binary found: $(command -v nmap)"
else
    echo "NOTE: nmap binary not found on PATH."
    echo "  The application will run using its built-in fallback scanner."
    echo "  For full functionality (OS detection, faster scans), install nmap:"
    echo "    Debian/Ubuntu: sudo apt-get install nmap"
    echo "    macOS (brew):  brew install nmap"
    echo "    Windows:       https://nmap.org/download.html"
fi

echo ""
echo "Setup complete. To run the application:"
echo "  source $VENV_DIR/bin/activate"
echo "  python main.py"
