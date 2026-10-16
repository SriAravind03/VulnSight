# 🛡 Sentinel Vulnerability Scanner

A professional desktop vulnerability scanner for **authorized** security
assessments of systems, servers, internal networks, and web applications
you own or have explicit written permission to test.

Sentinel discovers hosts, fingerprints services and versions, correlates
findings against public CVE databases (NVD/CIRCL), performs safe/passive
web application checks, calculates a weighted risk score, and generates
polished PDF/HTML/CSV/JSON reports — all from a modern Tkinter +
ttkbootstrap desktop GUI that never freezes while a scan runs.

> ⚠️ **Authorized use only.** Scanning systems without permission may be
> illegal in your jurisdiction. See [Legal Notice](#legal-notice) below.

> 📌 **v1.0.1 update:** fixed a dependency-pinning issue that could cause
> a newer/incompatible `ttkbootstrap` version to be installed via
> `pip install -r requirements.txt`, producing a broken/blank-looking UI.
> All dependencies are now pinned to exact tested versions, the KPI
> cards / sidebar / severity badges were rebuilt with guaranteed
> cross-platform rendering, empty-state screens were added to every page
> so a fresh install doesn't look "broken" before you've run a scan, and
> a real bug was fixed where host discovery could silently skip scanning
> a reachable single IP/hostname target if it didn't answer on one of a
> small fixed list of common ports. **If you installed before this
> update, delete your `.venv` folder and re-run setup** to pick up the
> corrected dependency versions.

---

## Features

| Area | Details |
|---|---|
| **Host Discovery** | IP / CIDR / hostname / URL targets; nmap-based or built-in pure-Python fallback |
| **Port Scanning** | TCP (and optional UDP via nmap) with state, service, product, and version |
| **Service Enumeration** | HTTP(S), SSH, FTP, SMTP, DNS, RDP, SMB, MySQL, PostgreSQL, MongoDB, Redis, LDAP, NTP, SNMP, and more |
| **CVE Correlation** | NVD REST API primary, CIRCL API fallback, local SQLite cache, CVSS-based severity |
| **Safe Web Scanning** | Security headers, cookie flags, TLS config, HTTP→HTTPS redirect, directory listing exposure, form security, server banners, robots.txt/security.txt — **non-destructive, passive checks only** |
| **Risk Engine** | Combines CVSS, exploit availability, patch availability, exposure, and service sensitivity into a 0–10 score and Critical/High/Medium/Low/Informational rating |
| **Reporting** | PDF (reportlab), HTML (Jinja2), CSV, and JSON — all built from one consistent data model, plus a severity chart |
| **GUI** | Dashboard, Scan, Results, Reports, Settings, About; sidebar nav; dark/light themes; live progress and log |
| **Storage & Search** | SQLite database of scans/hosts/ports/CVEs/reports; searchable results view |
| **Concurrency** | `ThreadPoolExecutor` + background threads — the UI never blocks during a scan |
| **OpenVAS/Greenbone** | Auto-detected if installed locally; the app runs fully without it using its built-in engines |

---

## Quickstart

### 1. Requirements
- Python 3.12+ (3.10+ generally works)
- (Optional but recommended) the `nmap` binary for full scanning features —
  the app automatically falls back to a built-in pure-Python scanner if
  it isn't found.

### 2. Setup

> **Note:** dependencies in `requirements.txt` are pinned to exact tested
> versions (not `>=` ranges). This matters most for `ttkbootstrap` —
> newer major versions changed internal styling behavior in ways that
> can visually break this UI (cards/sidebar rendering incorrectly). If
> you already have an environment with a different ttkbootstrap version
> installed, re-run `pip install -r requirements.txt` in a **fresh
> virtual environment** to get the exact tested versions.

**Linux / macOS**
```bash
./setup.sh
source .venv/bin/activate
python main.py
```

**Windows**
```bat
setup.bat
.venv\Scripts\activate.bat
python main.py
```

**Manual setup (any OS)**
```bash
python3 -m venv .venv
source .venv/bin/activate      # or .venv\Scripts\activate.bat on Windows
pip install -r requirements.txt
python check_dependencies.py    # verify everything is installed correctly
python main.py
```

### 3. Run your first scan
1. Open the **Scan** page.
2. Enter a target: a single IP (`192.168.1.10`), a CIDR range
   (`192.168.1.0/24`), a hostname, or an authorized URL
   (`https://your-authorized-app.example`).
3. Choose scan options (host discovery, TCP/UDP, service detection,
   web scan, CVE lookup).
4. **Tick the authorization checkbox** — the scan will not start without it.
5. Click **Start Scan** and watch live progress in the log.
6. Review results on the **Results** page, then generate a report from
   the **Reports** page.

---

## Project Structure

```
scanner/
├── main.py                  # Application entry point
├── check_dependencies.py    # Standalone dependency checker
├── setup.sh / setup.bat     # Automatic environment setup
├── requirements.txt
│
├── gui/                     # Tkinter/ttkbootstrap desktop UI
│   ├── main_window.py       # Main window: sidebar + content + status bar
│   ├── sidebar.py
│   ├── widgets.py           # Reusable widgets (status bar, stat cards, badges)
│   └── pages/                # Dashboard, Scan, Results, Reports, Settings, About
│
├── scanner/                 # Scan engines and logic
│   ├── engine.py             # nmap wrapper + OpenVAS detection
│   ├── fallback_scanner.py   # Pure-Python threaded TCP scanner (no nmap needed)
│   ├── web_scanner.py        # Safe/passive web application checks
│   ├── risk_engine.py        # Risk scoring
│   └── orchestrator.py       # End-to-end scan pipeline coordinator
│
├── cve/
│   └── lookup.py             # NVD/CIRCL CVE lookup + local caching
│
├── reports/                  # Report generation
│   ├── data_builder.py       # Aggregates DB data into one ReportData object
│   ├── pdf_report.py / html_report.py / csv_json_report.py
│   ├── charts.py             # matplotlib severity charts
│   └── manager.py            # Unified generate_report() entry point
│
├── database/
│   ├── schema.py              # SQLite schema + connection management
│   └── models.py              # Dataclasses + repository (CRUD) classes
│
├── utils/
│   ├── config.py              # YAML configuration manager
│   ├── logger.py              # Centralized rotating-file logging
│   └── validators.py          # Strict input validation (anti-injection)
│
├── config/default_config.yaml # Default settings (copied to user_config.yaml on first run)
├── templates/report_template.html
├── assets/, logs/, exports/, database/   # Runtime directories
└── docs/                      # Additional documentation (see below)
```

---

## Configuration

Settings live in `config/user_config.yaml` (auto-created from
`config/default_config.yaml` on first run) and can also be edited from
the **Settings** page: theme, thread count, socket timeout, report
output directory, company/author name for reports, and an optional NVD
API key (raises the public rate limit from ~1 request/6s to a much
higher ceiling).

## Security Notes

- All user-supplied targets and port specs are validated in
  `utils/validators.py` before being used anywhere — shell
  metacharacters are rejected outright, and `python-nmap` invokes the
  `nmap` binary via an argument list (never a shell string).
- The web scanner performs **read-only, non-destructive checks only**.
  It does not attempt authentication bypass, payload injection, or
  denial-of-service testing.
- No API keys or secrets are hardcoded; the optional NVD API key is
  stored in your local `config/user_config.yaml`, which is not
  committed to version control (see `.gitignore`).

## Legal Notice

This software is provided for **defensive, authorized security
assessment only**. You must own the target system(s) or hold explicit
written authorization to test them. Unauthorized scanning of computer
systems may violate laws such as the U.S. Computer Fraud and Abuse Act,
the UK Computer Misuse Act, or equivalent legislation elsewhere. The
authors accept no liability for misuse of this software. The
in-application authorization checkbox on the Scan page is a required,
non-bypassable gate before any scan can run.

## Further Documentation

See the `docs/` folder for the [Installation Guide](docs/INSTALLATION.md),
[Architecture Overview](docs/ARCHITECTURE.md), [User Guide](docs/USER_GUIDE.md),
and [Developer Guide](docs/DEVELOPER_GUIDE.md).
