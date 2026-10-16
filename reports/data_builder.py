"""
Assembles a single ReportData structure from the database for a given
scan ID. All report generators (PDF/HTML/CSV/JSON) consume this same
structure so the content is guaranteed to be consistent across formats.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from database.models import ScanRepository, HostRepository, PortRepository, CveRepository, WebFindingRepository
from scanner.risk_engine import assess_cve_risk, assess_finding_risk, summarize_severities
from utils.config import config
from utils.validators import is_private_or_loopback

_scan_repo = ScanRepository()
_host_repo = HostRepository()
_port_repo = PortRepository()
_cve_repo = CveRepository()
_web_repo = WebFindingRepository()


@dataclass
class ReportData:
    scan: dict
    hosts: list[dict]
    ports_by_host: dict[int, list[dict]]
    cves: list[dict]
    web_findings: list[dict]
    severity_counts: dict[str, int]
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    company_name: str = ""
    author: str = ""
    tool_version: str = "1.0.0"


def build_report_data(scan_id: int) -> ReportData:
    scan = _scan_repo.get(scan_id)
    if not scan:
        raise ValueError(f"No scan found with id {scan_id}")

    hosts = _host_repo.list_for_scan(scan_id)
    ports_by_host: dict[int, list[dict]] = {}
    for host in hosts:
        ports_by_host[host["id"]] = _port_repo.list_for_host(host["id"])

    cves = _cve_repo.list_for_scan(scan_id)
    web_findings = _web_repo.list_for_scan(scan_id)

    assessments = []
    for cve in cves:
        host_ip = cve.get("host_ip", "")
        risk = assess_cve_risk(
            cvss_score=cve.get("cvss_score"),
            exploit_known=bool(cve.get("exploit_known")),
            patch_available=bool(cve.get("patch_available")),
            internet_exposed=not is_private_or_loopback(host_ip) if host_ip else False,
        )
        cve["risk_score"] = risk.score
        cve["risk_severity"] = risk.severity
        cve["risk_color"] = risk.color
        cve["risk_recommendation"] = risk.recommendation
        assessments.append(risk)

    for finding in web_findings:
        risk = assess_finding_risk(finding.get("severity", "Informational"))
        finding["risk_color"] = risk.color
        assessments.append(risk)

    severity_counts = summarize_severities(assessments)

    return ReportData(
        scan=scan,
        hosts=hosts,
        ports_by_host=ports_by_host,
        cves=cves,
        web_findings=web_findings,
        severity_counts=severity_counts,
        company_name=config.get("report.company_name", "Your Organization"),
        author=config.get("report.author", "Security Team"),
    )
