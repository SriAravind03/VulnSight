"""
PDF report generator built on reportlab (Platypus flowables).

Produces a professional multi-section report: executive summary,
target/scan configuration, host inventory, open ports/services,
CVE findings with risk ratings, web application findings, and a
severity distribution chart.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak,
)

from reports.charts import render_severity_chart
from reports.data_builder import ReportData
from scanner.risk_engine import SEVERITY_COLORS
from utils.logger import get_logger

logger = get_logger("reports.pdf")

_styles = getSampleStyleSheet()
_title_style = ParagraphStyle("SentinelTitle", parent=_styles["Title"], textColor=colors.HexColor("#1b2838"))
_heading_style = ParagraphStyle("SentinelHeading", parent=_styles["Heading2"], textColor=colors.HexColor("#1b2838"),
                                 spaceBefore=14, spaceAfter=6)
_body_style = _styles["BodyText"]
_small_style = ParagraphStyle("Small", parent=_styles["BodyText"], fontSize=8, leading=10)


def _severity_cell(severity: str) -> Paragraph:
    color = SEVERITY_COLORS.get(severity, "#7d8fa3")
    return Paragraph(f'<font color="{color}"><b>{severity}</b></font>', _body_style)


def generate_pdf_report(data: ReportData, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(output_path), pagesize=LETTER,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        title="Sentinel Vulnerability Scan Report",
    )

    story = []

    # -- Title / cover --------------------------------------------------
    story.append(Paragraph("Sentinel Vulnerability Scanner", _title_style))
    story.append(Paragraph("Security Assessment Report", _styles["Heading3"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"<b>Target:</b> {data.scan.get('target')}", _body_style))
    story.append(Paragraph(f"<b>Scan Started:</b> {data.scan.get('started_at')}", _body_style))
    story.append(Paragraph(f"<b>Scan Finished:</b> {data.scan.get('finished_at') or 'N/A'}", _body_style))
    story.append(Paragraph(f"<b>Report Generated:</b> {data.generated_at}", _body_style))
    story.append(Paragraph(f"<b>Prepared By:</b> {data.author} &mdash; {data.company_name}", _body_style))
    story.append(Spacer(1, 20))

    # -- Executive summary -----------------------------------------------
    story.append(Paragraph("Executive Summary", _heading_style))
    total_findings = len(data.cves) + len(data.web_findings)
    summary_text = (
        f"This report presents the results of an authorized security assessment of "
        f"<b>{data.scan.get('target')}</b>. The scan identified <b>{len(data.hosts)}</b> host(s), "
        f"<b>{sum(len(p) for p in data.ports_by_host.values())}</b> port record(s), and a total of "
        f"<b>{total_findings}</b> findings across CVE correlation and web application checks."
    )
    story.append(Paragraph(summary_text, _body_style))
    story.append(Spacer(1, 10))

    with tempfile.TemporaryDirectory() as tmp:
        chart_path = Path(tmp) / "severity_chart.png"
        try:
            render_severity_chart(data.severity_counts, chart_path)
            story.append(Image(str(chart_path), width=4.5 * inch, height=2.9 * inch))
        except Exception as exc:
            logger.warning("Could not render severity chart: %s", exc)

        story.append(Spacer(1, 10))

        # -- Host summary --------------------------------------------------
        story.append(Paragraph("Host Summary", _heading_style))
        host_rows = [["IP Address", "Hostname", "Status", "OS Guess", "Vendor"]]
        for host in data.hosts:
            host_rows.append([
                host.get("ip_address", ""), host.get("hostname", "") or "-",
                host.get("status", ""), host.get("os_guess", "") or "-", host.get("vendor", "") or "-",
            ])
        story.append(_make_table(host_rows, [1.3, 1.6, 0.9, 1.6, 1.1]))
        story.append(Spacer(1, 10))

        # -- Ports / services -----------------------------------------------
        story.append(Paragraph("Open Ports & Services", _heading_style))
        port_rows = [["Host", "Port", "Proto", "State", "Service", "Version"]]
        for host in data.hosts:
            for port in data.ports_by_host.get(host["id"], []):
                port_rows.append([
                    host.get("ip_address", ""), str(port.get("port_number")), port.get("protocol", ""),
                    port.get("state", ""), port.get("service_name", "") or "-",
                    f"{port.get('product','')} {port.get('version','')}".strip() or "-",
                ])
        if len(port_rows) == 1:
            port_rows.append(["-", "-", "-", "-", "-", "-"])
        story.append(_make_table(port_rows, [1.2, 0.6, 0.6, 0.8, 1.2, 2.1]))
        story.append(PageBreak())

        # -- CVE findings -----------------------------------------------------
        story.append(Paragraph("CVE Findings & Risk Ratings", _heading_style))
        if data.cves:
            for cve in data.cves:
                story.append(Paragraph(
                    f"<b>{cve.get('cve_id')}</b> &mdash; Host {cve.get('host_ip','?')}"
                    + (f":{cve.get('port_number')}" if cve.get('port_number') else ""),
                    _styles["Heading4"],
                ))
                risk_row = [[
                    _severity_cell(cve.get("risk_severity", "Informational")),
                    Paragraph(f"CVSS: {cve.get('cvss_score', 'N/A')}", _body_style),
                    Paragraph(f"Exploit known: {'Yes' if cve.get('exploit_known') else 'No'}", _body_style),
                    Paragraph(f"Patch available: {'Yes' if cve.get('patch_available') else 'No'}", _body_style),
                ]]
                story.append(_make_table(risk_row, [1.2, 1.6, 1.6, 1.6], header=False))
                story.append(Paragraph(cve.get("description", "") or "No description available.", _small_style))
                story.append(Paragraph(f"<i>Recommendation:</i> {cve.get('risk_recommendation','')}", _small_style))
                story.append(Spacer(1, 8))
        else:
            story.append(Paragraph("No CVE matches were identified for the detected services.", _body_style))

        story.append(Spacer(1, 10))

        # -- Web findings -------------------------------------------------
        story.append(Paragraph("Web Application Findings", _heading_style))
        if data.web_findings:
            web_rows = [["URL", "Category", "Severity", "Finding"]]
            for f in data.web_findings:
                web_rows.append([
                    f.get("url", ""), f.get("category", ""), f.get("severity", ""), f.get("finding", ""),
                ])
            story.append(_make_table(web_rows, [1.6, 1.1, 0.9, 2.4]))
        else:
            story.append(Paragraph("No web application checks were performed or no issues were found.", _body_style))

        story.append(Spacer(1, 16))
        story.append(Paragraph(
            "This report was generated by Sentinel Vulnerability Scanner using only "
            "non-destructive, defensive assessment techniques against an authorized target.",
            _small_style,
        ))

        doc.build(story)

    logger.info("PDF report written to %s", output_path)
    return output_path


def _make_table(rows: list[list], col_widths_in: list[float], header: bool = True) -> Table:
    widths = [w * inch for w in col_widths_in]
    wrapped_rows = []
    for r_index, row in enumerate(rows):
        wrapped_row = []
        for cell in row:
            if isinstance(cell, (Paragraph,)):
                wrapped_row.append(cell)
            else:
                wrapped_row.append(Paragraph(str(cell), _small_style))
        wrapped_rows.append(wrapped_row)

    table = Table(wrapped_rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b2838")))
        style.append(("TEXTCOLOR", (0, 0), (-1, 0), colors.white))
    table.setStyle(TableStyle(style))
    return table
