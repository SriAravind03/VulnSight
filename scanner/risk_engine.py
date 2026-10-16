"""
Risk scoring engine.

Combines CVSS base score, exploit availability, patch availability,
network exposure, and a simple service-importance weighting into a
single 0-10 risk score and a Critical/High/Medium/Low/Informational
rating, used consistently across the results view and generated reports.
"""

from __future__ import annotations

from dataclasses import dataclass

# Services considered more sensitive if exposed (auth, data, admin surfaces).
HIGH_VALUE_SERVICES = {
    "rdp", "ssh", "smb", "mysql", "postgresql", "mongodb", "redis",
    "ldap", "mssql", "ftp", "telnet", "vnc",
}

SEVERITY_COLORS = {
    "Critical": "#d9534f",
    "High": "#f0ad4e",
    "Medium": "#f7d154",
    "Low": "#5bc0de",
    "Informational": "#7d8fa3",
}

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


@dataclass
class RiskAssessment:
    score: float          # 0.0 - 10.0
    severity: str
    color: str
    recommendation: str


def score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Informational"


def assess_cve_risk(
    cvss_score: float | None,
    exploit_known: bool,
    patch_available: bool,
    internet_exposed: bool,
    service_name: str = "",
) -> RiskAssessment:
    """
    Produce a weighted risk score for a single CVE match against a
    detected service.

    Base = CVSS score (0 if unknown, treated conservatively as Medium-ish).
    Modifiers:
      +1.0 if a known exploit exists
      -1.0 if a patch is available (residual risk still present, but lower)
      +0.5 if the service is internet-exposed
      +0.5 if the service is in the high-value set (auth/data/admin surfaces)
    Result is clamped to [0, 10].
    """
    base = cvss_score if cvss_score is not None else 5.0

    adjustment = 0.0
    if exploit_known:
        adjustment += 1.0
    if patch_available:
        adjustment -= 1.0
    if internet_exposed:
        adjustment += 0.5
    if service_name.lower() in HIGH_VALUE_SERVICES:
        adjustment += 0.5

    score = max(0.0, min(10.0, base + adjustment))
    severity = score_to_severity(score)

    recommendation = _build_recommendation(severity, patch_available, exploit_known)

    return RiskAssessment(
        score=round(score, 1),
        severity=severity,
        color=SEVERITY_COLORS[severity],
        recommendation=recommendation,
    )


def _build_recommendation(severity: str, patch_available: bool, exploit_known: bool) -> str:
    parts = []
    if severity in ("Critical", "High"):
        parts.append("Remediate as a priority.")
    else:
        parts.append("Remediate during the next maintenance window.")
    if patch_available:
        parts.append("A vendor patch/update is available -- apply it.")
    else:
        parts.append("No confirmed patch is available; consider mitigating controls or isolation.")
    if exploit_known:
        parts.append("Public exploit code exists, increasing urgency.")
    return " ".join(parts)


def assess_finding_risk(severity_label: str) -> RiskAssessment:
    """
    Convert a qualitative severity label (used by the web scanner, which
    doesn't have a CVSS score) into a consistent RiskAssessment.
    """
    severity = severity_label if severity_label in SEVERITY_ORDER else "Informational"
    approx_scores = {"Critical": 9.5, "High": 7.5, "Medium": 5.0, "Low": 2.5, "Informational": 0.0}
    score = approx_scores[severity]
    return RiskAssessment(
        score=score,
        severity=severity,
        color=SEVERITY_COLORS[severity],
        recommendation=_build_recommendation(severity, patch_available=False, exploit_known=False),
    )


def summarize_severities(assessments: list[RiskAssessment]) -> dict[str, int]:
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for a in assessments:
        counts[a.severity] = counts.get(a.severity, 0) + 1
    return counts
