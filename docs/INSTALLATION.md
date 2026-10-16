# Installation Guide

## 1. Prerequisites

- **Python 3.12+** (3.10+ generally works). Verify with:
  ```bash
  python3 --version
  ```
- **(Optional) nmap binary** — enables full TCP/UDP scanning, OS
  detection, and faster service/version fingerprinting. If it is not
  installed, Sentinel automatically uses its built-in pure-Python
  fallback scanner (TCP-connect based) with no loss of core
  functionality other than OS detection and UDP scanning.

  | OS | Install command |
  |---|---|
  | Debian/Ubuntu | `sudo apt-get install nmap` |
  | Fedora/RHEL | `sudo dnf install nmap` |
  | macOS (Homebrew) | `brew install nmap` |
  | Windows | Download the installer from https://nmap.org/download.html |

- **(Optional) OpenVAS / Greenbone Community Edition** — if a local
  `gvmd` install is detected (via `gvm-cli` on PATH or its Unix socket),
  Sentinel will report it as available on the Dashboard/About pages.
  Direct GMP-protocol scan integration is a natural extension point;
  see `docs/ARCHITECTURE.md`.

## 2. Automatic Setup

**Linux / macOS**
```bash
git clone <this-repository> sentinel-scanner
cd sentinel-scanner
chmod +x setup.sh
./setup.sh
source .venv/bin/activate
python main.py
```

**Windows (Command Prompt)**
```bat
git clone <this-repository> sentinel-scanner
cd sentinel-scanner
setup.bat
.venv\Scripts\activate.bat
python main.py
```

The setup script:
1. Verifies your Python installation.
2. Creates a virtual environment in `.venv/`.
3. Installs all dependencies from `requirements.txt`.
4. Creates the `logs/`, `exports/`, and `database/` runtime directories.
5. Checks for the `nmap` binary and prints guidance if it's missing.

## 3. Manual Setup

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate.bat
pip install --upgrade pip
pip install -r requirements.txt
python check_dependencies.py       # confirms every package is importable
python main.py
```

## 4. Verifying the Installation

Run the dependency checker at any time:
```bash
python check_dependencies.py
```
This reports the Python version, the status of every required package,
and whether the `nmap` binary is available — without needing to launch
the full GUI.

## 5. First Run

On first launch, Sentinel copies `config/default_config.yaml` to
`config/user_config.yaml` (git-ignored) and initializes the SQLite
database at `database/sentinel.db`. Both are safe to delete if you want
to reset the application to a clean state.

## 6. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `ModuleNotFoundError` on launch | Run `pip install -r requirements.txt` inside the activated virtual environment. |
| GUI window doesn't appear (Linux) | Ensure a display server is available (`echo $DISPLAY`); Tkinter requires a windowing environment (X11/Wayland). |
| Scans are slow / only using the fallback scanner | Install the `nmap` binary (see table above) for significantly faster, more capable scanning. |
| CVE lookups return nothing | The public NVD API is rate-limited (~1 request/6s) and occasionally returns `403` under heavy load; add a free NVD API key in Settings to raise the limit, or retry later. CIRCL is used automatically as a fallback. |
| PDF report generation fails | Ensure `reportlab` and `matplotlib` installed correctly; re-run `pip install -r requirements.txt`. |
