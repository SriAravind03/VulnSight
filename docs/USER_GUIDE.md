# User Guide

## Overview of the Interface

The application has a left-hand sidebar with six sections:

- **Dashboard** — KPI cards (total scans, critical/high findings,
  detected scan engine, OpenVAS availability) and a table of recent
  scans. Double-click any row to jump straight to its results.
- **Scan** — configure and launch a new scan.
- **Results** — browse hosts, ports/services, CVE findings, and web
  findings for any past scan, with a live search box.
- **Reports** — generate PDF/HTML/CSV/JSON reports and reopen
  previously generated ones.
- **Settings** — theme, thread count, timeouts, report directory,
  company/author metadata, and an optional NVD API key.
- **About** — version info, detected engine, and the authorized-use
  disclaimer.

## Running a Scan

1. Go to **Scan**.
2. **Target** accepts:
   - A single IP: `10.0.0.5`
   - A CIDR range: `10.0.0.0/24` (capped at 1024 hosts per scan as a
     safety guardrail when using the fallback scanner)
   - A hostname: `internal-app.mycompany.local`
   - An authorized URL: `https://staging.mycompany.example`
3. **Ports** accepts nmap-style specs: `22,80,443`, `1-1024`, or
   `1-65535`.
4. Choose which checks to run:
   - **Host Discovery** — find live hosts before/instead of a full port scan.
   - **TCP Scan / UDP Scan** — UDP requires the `nmap` binary.
   - **Service Detection** — identify product/version banners.
   - **OS Detection** — requires `nmap`; unavailable in fallback mode.
   - **Safe Web Scan** — passive checks against any detected HTTP(S)
     service, or directly against a URL target.
   - **CVE Lookup** — correlate detected products/versions against
     NVD/CIRCL.
5. **Tick the authorization checkbox.** This is mandatory — Sentinel
   will refuse to start a scan otherwise, both in the UI and at the
   underlying engine level.
6. Click **Start Scan**. Progress streams into the log panel below and
   the status bar at the bottom of the window; the UI stays fully
   responsive throughout (scanning runs on a background thread).
7. When the scan finishes, you're taken automatically to **Results**.

## Reading Results

- **Hosts** tab: IP, hostname, status, OS guess (nmap only), vendor.
- **Ports & Services** tab: every open/closed/filtered port found,
  with service name and detected product/version.
- **CVE Findings** tab: each matched CVE with its computed severity
  (Critical/High/Medium/Low/Informational), CVSS score, whether a
  known exploit exists, and whether a patch is available.
- **Web Findings** tab: passive web checks (missing headers, cookie
  flags, TLS issues, directory listing exposure, etc.) with severity.

Use the **Search** box at the top to filter any of the four tabs by
any visible column (IP, port, service, CVE ID, severity, etc. all
match).

## Generating Reports

From **Results**, click **Generate Report** (or go directly to the
**Reports** page), pick the scan from the dropdown, and click any of
**Generate PDF / HTML / CSV / JSON**. Each format contains the same
underlying findings:

- **PDF** — a polished, shareable document with an executive summary,
  a severity chart, host/port tables, and full CVE/web-finding detail.
- **HTML** — the same content, self-contained and viewable in any browser.
- **CSV** — one row per finding (CVE or web), ideal for spreadsheet
  triage or importing into a ticketing system.
- **JSON** — the full structured data, useful for feeding into other
  tooling or pipelines.

Double-click any row in the **Generated Reports** table to open that
file with your OS's default viewer.

## Tips

- If `nmap` isn't installed, Sentinel automatically uses its built-in
  fallback scanner — you'll see this noted on the Scan page and in
  the status bar. Install `nmap` for OS detection, UDP scanning, and
  generally faster/more accurate results.
- Add an NVD API key in **Settings** if you're running frequent scans;
  the public NVD rate limit is roughly one request per 6 seconds
  without a key.
- The **Report Directory** setting controls where generated reports
  are saved (default: `exports/`).
