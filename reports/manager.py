"""Unified entry point for generating any report format for a given scan."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from database.models import ReportRepository
from reports.csv_json_report import generate_csv_report, generate_json_report
from reports.data_builder import build_report_data
from reports.html_report import generate_html_report
from reports.pdf_report import generate_pdf_report
from utils.config import config, PROJECT_ROOT
from utils.logger import get_logger
from utils.validators import sanitize_filename

logger = get_logger("reports.manager")

_report_repo = ReportRepository()

_GENERATORS = {
    "pdf": generate_pdf_report,
    "html": generate_html_report,
    "json": generate_json_report,
    "csv": generate_csv_report,
}


def generate_report(scan_id: int, fmt: str) -> Path:
    fmt = fmt.lower()
    if fmt not in _GENERATORS:
        raise ValueError(f"Unsupported report format: {fmt}")

    data = build_report_data(scan_id)
    output_dir = PROJECT_ROOT / config.get("report.output_dir", "exports")
    output_dir.mkdir(parents=True, exist_ok=True)

    target_slug = sanitize_filename(data.scan.get("target", "target"))
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"sentinel_{target_slug}_{timestamp}.{fmt}"
    output_path = output_dir / filename

    generator = _GENERATORS[fmt]
    generator(data, output_path)

    _report_repo.create(scan_id, fmt, str(output_path))
    logger.info("Generated %s report for scan %s at %s", fmt, scan_id, output_path)
    return output_path


def generate_all_formats(scan_id: int) -> dict[str, Path]:
    return {fmt: generate_report(scan_id, fmt) for fmt in _GENERATORS}
