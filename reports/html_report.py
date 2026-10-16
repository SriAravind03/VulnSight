"""HTML report generator using Jinja2 against templates/report_template.html."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from reports.data_builder import ReportData
from scanner.risk_engine import SEVERITY_COLORS
from utils.config import PROJECT_ROOT
from utils.logger import get_logger

logger = get_logger("reports.html")

_env = Environment(
    loader=FileSystemLoader(str(PROJECT_ROOT / "templates")),
    autoescape=select_autoescape(["html"]),
)


def generate_html_report(data: ReportData, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    template = _env.get_template("report_template.html")
    html = template.render(
        scan=data.scan,
        hosts=data.hosts,
        ports_by_host=data.ports_by_host,
        cves=data.cves,
        web_findings=data.web_findings,
        severity_counts=data.severity_counts,
        severity_colors=SEVERITY_COLORS,
        generated_at=data.generated_at,
        company_name=data.company_name,
        author=data.author,
        tool_version=data.tool_version,
    )
    output_path.write_text(html, encoding="utf-8")
    logger.info("HTML report written to %s", output_path)
    return output_path
