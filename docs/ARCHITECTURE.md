# Architecture Overview

## High-Level Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                              GUI Layer                              │
│   gui/main_window.py  ─┬─ gui/sidebar.py                             │
│                        └─ gui/pages/*  (Dashboard, Scan, Results,    │
│                            Reports, Settings, About)                 │
│   Runs scans on background threads via ScanOrchestrator; the GUI      │
│   thread only ever reads results and updates widgets via .after().   │
└───────────────────────────────┬───────────────────────────────────┘
                                 │ ScanOrchestrator.run(target, options, authorized, progress_cb)
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        scanner/orchestrator.py                       │
│  1. Validates authorization flag (hard gate)                         │
│  2. Chooses engine: scanner/engine.py (nmap) or                      │
│     scanner/fallback_scanner.py (pure Python, no nmap needed)        │
│  3. For web targets / detected HTTP(S) ports → scanner/web_scanner.py│
│  4. For each open port with a product/version → cve/lookup.py        │
│  5. Applies scanner/risk_engine.py to every CVE / web finding        │
│  6. Persists everything via database/models.py repositories          │
└───────────────────────────────┬───────────────────────────────────┘
                                 │
                 ┌───────────────┼────────────────┐
                 ▼               ▼                ▼
        database/schema.py   cve/lookup.py   scanner/web_scanner.py
        (SQLite, WAL-free,   (NVD → CIRCL     (requests + BeautifulSoup4,
         thread-local conns)  fallback,        ssl module for TLS checks)
                               local cache)

                                 │
                                 ▼
                        reports/data_builder.py
                     (aggregates one scan into a single
                      ReportData object used by every format)
                                 │
              ┌──────────────┬──────────────┬──────────────┐
              ▼              ▼              ▼              ▼
        pdf_report.py   html_report.py  csv_json_report.py  charts.py
        (reportlab)     (Jinja2 +       (stdlib csv/json)  (matplotlib,
                         templates/)                          Agg backend)
```

## Design Principles

1. **Separation of concerns.** The GUI never talks to the database,
   the scan engines, or the report generators directly — everything
   flows through `ScanOrchestrator` and `reports/manager.py`, which
   are fully testable without any GUI dependency (see the functional
   test approach used during development: instantiate
   `ScanOrchestrator` and `generate_report()` directly in a script).

2. **Defense in depth against injection.** `utils/validators.py` is
   the single choke point for every user-supplied string (target,
   port spec, filename). `python-nmap` invokes `nmap` via an argument
   list, never a shell string, and the fallback scanner uses only
   `socket` — there is no `subprocess`/`shell=True` path for scan
   targets anywhere in the codebase.

3. **Graceful degradation.** `scanner/engine.is_nmap_available()` is
   checked at scan time; if nmap isn't installed, the orchestrator
   transparently swaps in `FallbackScanner` with no change to the
   downstream pipeline (ports/services still flow into the same
   `Port` dataclass / database table).

4. **One data model, four report formats.** `reports/data_builder.py`
   is the only place that reads from the database for reporting
   purposes. Every generator (`pdf_report.py`, `html_report.py`,
   `csv_json_report.py`) consumes the same `ReportData` object, so
   the four output formats can never drift out of sync with each
   other.

5. **Non-blocking UI.** Every scan and report-generation call from the
   GUI happens on a `threading.Thread`, with progress reported back to
   the Tk main loop via `widget.after(0, callback, ...)` — the only
   thread-safe way to touch Tkinter widgets from a worker thread.

6. **Authorization as a hard gate, not a suggestion.** `ScanOrchestrator.run()`
   raises `AuthorizationError` unless `authorized=True` is passed, and
   the GUI's Scan page will not proceed unless the user has ticked the
   on-screen confirmation checkbox — this exists at both the UI and
   the engine layer so it can't be bypassed by calling the orchestrator
   directly.

## Database Schema (summary)

`scans (1) ─< hosts (1) ─< ports (1) ─< cve_matches`
`scans (1) ─< web_findings`
`scans (1) ─< reports`
`cve_cache` — standalone keyed by CVE ID, with a TTL enforced in
`cve/lookup.py` via `CveLookupClient.get_cached()`.

See `database/schema.py` for the full `CREATE TABLE` statements and
`database/models.py` for the dataclasses/repositories built on top of
them.

## Extension Points

- **OpenVAS/GVM integration:** `scanner/engine.is_openvas_available()`
  already detects a local install. A `scanner/openvas_engine.py`
  module implementing the same `scan()` interface as `NmapEngine`
  (using `python-gvm`'s GMP protocol) could be added and selected by
  the orchestrator when available, following the same
  detect-and-fall-back pattern already used for nmap.
- **Additional CVE sources:** `cve/lookup.py`'s `CveLookupClient` is
  structured so a third `_search_<source>()` method can be added and
  chained after CIRCL with minimal changes.
- **Additional report formats:** add a `generate_<format>_report(data, path)`
  function and register it in `reports/manager.py`'s `_GENERATORS` dict.
