"""CSV and JSON report generators (flat, machine-readable exports)."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from reports.data_builder import ReportData
from utils.logger import get_logger

logger = get_logger("reports.csv_json")


def generate_json_report(data: ReportData, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "scan": data.scan,
        "hosts": data.hosts,
        "ports_by_host": {str(k): v for k, v in data.ports_by_host.items()},
        "cves": data.cves,
        "web_findings": data.web_findings,
        "severity_counts": data.severity_counts,
        "generated_at": data.generated_at,
        "company_name": data.company_name,
        "author": data.author,
        "tool_version": data.tool_version,
    }
    output_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    logger.info("JSON report written to %s", output_path)
    return output_path


def generate_csv_report(data: ReportData, output_path: Path) -> Path:
    """
    Writes a single CSV with one row per finding (CVE or web finding),
    denormalized with host/target context, which is the most useful
    flat shape for spreadsheet analysis.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "finding_type", "target", "host_ip", "port", "service",
        "identifier", "severity", "cvss_score", "description", "recommendation",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()

        for cve in data.cves:
            writer.writerow({
                "finding_type": "cve",
                "target": data.scan.get("target", ""),
                "host_ip": cve.get("host_ip", ""),
                "port": cve.get("port_number", ""),
                "service": "",
                "identifier": cve.get("cve_id", ""),
                "severity": cve.get("risk_severity", ""),
                "cvss_score": cve.get("cvss_score", ""),
                "description": cve.get("description", ""),
                "recommendation": cve.get("risk_recommendation", ""),
            })

        for f in data.web_findings:
            writer.writerow({
                "finding_type": "web",
                "target": data.scan.get("target", ""),
                "host_ip": f.get("url", ""),
                "port": "",
                "service": f.get("category", ""),
                "identifier": "",
                "severity": f.get("severity", ""),
                "cvss_score": "",
                "description": f.get("finding", ""),
                "recommendation": f.get("recommendation", ""),
            })

    logger.info("CSV report written to %s", output_path)
    return output_path
