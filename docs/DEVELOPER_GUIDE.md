# Developer Guide

## Code Style

- Python 3.12+, PEP 8, `from __future__ import annotations` used
  throughout for cleaner type hints.
- Dataclasses for all structured data (`scanner/*.py`, `database/models.py`,
  `reports/data_builder.py`) instead of raw dicts wherever practical.
- Every public function/class has a docstring explaining intent, not
  just mechanics.
- Repository pattern for persistence: GUI and orchestration code call
  `ScanRepository`, `HostRepository`, etc. — never raw SQL.

## Running Without the GUI (for testing/automation)

Every layer below the GUI is independently usable, which makes it easy
to test or script:

```python
from utils.validators import ValidatedTarget
from scanner.orchestrator import ScanOrchestrator, ScanOptions
from reports.manager import generate_report

target = ValidatedTarget.from_input("127.0.0.1")
options = ScanOptions(port_spec="1-1024", cve_lookup=True, web_scan=True)

orchestrator = ScanOrchestrator()
scan_id = orchestrator.run(target, options, authorized=True,
                           progress_cb=lambda evt: print(evt.stage, evt.message))

report_path = generate_report(scan_id, "pdf")
print("Report written to", report_path)
```

This is exactly how the GUI's `ScanPage` and `ReportsPage` use these
modules internally (on background threads).

## Adding a New Scan Check

1. Add a new method to `scanner/web_scanner.WebScanner` (for web
   checks) or extend `scanner/engine.NmapEngine` / `scanner/fallback_scanner.FallbackScanner`
   (for network checks), returning your finding type
   (`WebFinding` or a new dataclass).
2. Wire it into `WebScanner.scan()` or `ScanOrchestrator._run_network_scan()`.
3. If it's a new finding category, extend `database/schema.py` only if
   the existing `web_findings` / `cve_matches` tables don't already fit
   — most new checks fit into `web_findings` as-is.

## Adding a New Report Format

1. Create `reports/<format>_report.py` with a function
   `generate_<format>_report(data: ReportData, output_path: Path) -> Path`.
2. Register it in `reports/manager.py`'s `_GENERATORS` dict.
3. It will automatically appear wherever `generate_report()` /
   `generate_all_formats()` are called, and can be wired into the
   Reports page UI with one new button.

## Adding a New CVE Source

`cve/lookup.py`'s `CveLookupClient.search_by_product_version()` tries
NVD, then falls back to CIRCL. To add a third source, add a
`_search_<source>()` method following the same signature
(`(keyword_or_product, version, max_results) -> list[CveResult]`) and
chain it in `search_by_product_version()`.

## Testing Approach

There's no GUI-dependent logic below `gui/` — `scanner/`, `cve/`,
`reports/`, `database/`, and `utils/` can all be exercised directly in
unit tests with `pytest` (not bundled, but straightforward to add: the
dataclass-heavy design means most functions take/return plain data and
are easy to assert against). The pattern used during development was:

```python
def test_validators_reject_shell_metacharacters():
    from utils.validators import classify_and_validate_target, ValidationError
    import pytest
    with pytest.raises(ValidationError):
        classify_and_validate_target("127.0.0.1; rm -rf /")
```

GUI smoke-testing can be done headlessly with `xvfb-run` (Linux):
```bash
xvfb-run -a python3 -c "
from gui.main_window import SentinelApp
app = SentinelApp()
for page in ['dashboard','scan','results','reports','settings','about']:
    app.navigate(page); app.update()
app.destroy()
"
```

## Logging

All modules log through `utils.logger.get_logger(__name__-like-string)`,
which writes to a rotating file at `logs/sentinel.log` (5 MB x 5
backups) plus the console, respecting the `app.log_level` setting
(`DEBUG`/`INFO`/`WARNING`/`ERROR`).

## Configuration

`utils/config.py`'s `ConfigManager` reads/writes
`config/user_config.yaml` using dotted-key access
(`config.get("scan.max_threads")` / `config.set(...)`). Add new
settings to `config/default_config.yaml` first so fresh installs get a
sensible default.
