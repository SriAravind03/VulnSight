"""
CVE intelligence lookup.

Normalizes a detected (product, version) pair into a CPE-like search
string, queries the NVD REST API (falling back to the CIRCL API if
NVD is unreachable or rate-limited), and caches results locally in
SQLite so repeat scans of the same software don't re-hit the network.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import requests

from database.models import CveRepository, CveMatch
from utils.config import config
from utils.logger import get_logger

logger = get_logger("cve.lookup")

_cve_repo = CveRepository()

_VERSION_STRIP_RE = re.compile(r"^[vV]")


@dataclass
class CveResult:
    cve_id: str
    description: str
    cvss_score: Optional[float]
    cvss_severity: str
    published_date: str
    reference_url: str
    exploit_known: bool = False
    patch_available: bool = False
    source: str = "nvd"


def normalize_product_name(raw_product: str) -> str:
    """Lowercase, strip vendor prefixes/suffixes nmap sometimes adds."""
    name = raw_product.strip().lower()
    name = re.sub(r"\s+(httpd|server|daemon)\s*$", "", name)
    return name.strip()


def normalize_version(raw_version: str) -> str:
    version = raw_version.strip()
    version = _VERSION_STRIP_RE.sub("", version)
    # keep only the leading numeric/dotted version token
    match = re.match(r"[\d][\d.\-a-zA-Z]*", version)
    return match.group(0) if match else version


def _severity_from_score(score: Optional[float]) -> str:
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Informational"


class CveLookupClient:
    def __init__(self) -> None:
        self.nvd_base = config.get("cve.nvd_api_base", "https://services.nvd.nist.gov/rest/json/cves/2.0")
        self.circl_base = config.get("cve.circl_api_base", "https://cve.circl.lu/api")
        self.api_key = config.get("cve.nvd_api_key", "") or None
        self.request_delay = float(config.get("cve.request_delay_seconds", 6))
        self.cache_ttl_days = int(config.get("cve.cache_ttl_days", 7))
        self._last_request_time = 0.0

    def search_by_product_version(self, product: str, version: str, max_results: int = 15) -> list[CveResult]:
        product_n = normalize_product_name(product)
        version_n = normalize_version(version)
        if not product_n:
            return []

        keyword = f"{product_n} {version_n}".strip()
        results = self._search_nvd(keyword, max_results)
        if not results:
            results = self._search_circl(product_n, version_n, max_results)
        return results

    # -- NVD -----------------------------------------------------------------

    def _respect_rate_limit(self) -> None:
        elapsed = time.time() - self._last_request_time
        if elapsed < self.request_delay:
            time.sleep(self.request_delay - elapsed)

    def _search_nvd(self, keyword: str, max_results: int) -> list[CveResult]:
        headers = {"apiKey": self.api_key} if self.api_key else {}
        params = {"keywordSearch": keyword, "resultsPerPage": max_results}
        self._respect_rate_limit()
        try:
            resp = requests.get(self.nvd_base, params=params, headers=headers, timeout=15)
            self._last_request_time = time.time()
            if resp.status_code != 200:
                logger.warning("NVD returned status %s for '%s'", resp.status_code, keyword)
                return []
            data = resp.json()
        except (requests.RequestException, ValueError) as exc:
            logger.warning("NVD lookup failed for '%s': %s", keyword, exc)
            return []

        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

            score, severity = None, "Unknown"
            metrics = cve.get("metrics", {})
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metric_key in metrics and metrics[metric_key]:
                    cvss_data = metrics[metric_key][0].get("cvssData", {})
                    score = cvss_data.get("baseScore")
                    severity = metrics[metric_key][0].get("baseSeverity", _severity_from_score(score))
                    break

            reference_url = ""
            refs = cve.get("references", [])
            if refs:
                reference_url = refs[0].get("url", "")

            results.append(CveResult(
                cve_id=cve_id,
                description=description[:1000],
                cvss_score=score,
                cvss_severity=severity or _severity_from_score(score),
                published_date=cve.get("published", ""),
                reference_url=reference_url or f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                source="nvd",
            ))
            self._cache_result(cve_id, item)
        return results

    # -- CIRCL fallback --------------------------------------------------------

    def _search_circl(self, product: str, version: str, max_results: int) -> list[CveResult]:
        query = f"{product} {version}".strip()
        url = f"{self.circl_base}/search/{requests.utils.quote(product)}"
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code != 200:
                return []
            data = resp.json()
        except (requests.RequestException, ValueError) as exc:
            logger.warning("CIRCL lookup failed for '%s': %s", query, exc)
            return []

        results = []
        entries = data if isinstance(data, list) else data.get("data", [])
        for entry in entries[:max_results]:
            cve_id = entry.get("id") or entry.get("cve_id", "")
            if not cve_id:
                continue
            score = entry.get("cvss")
            results.append(CveResult(
                cve_id=cve_id,
                description=(entry.get("summary") or "")[:1000],
                cvss_score=score,
                cvss_severity=_severity_from_score(score),
                published_date=entry.get("Published", ""),
                reference_url=f"https://cve.circl.lu/cve/{cve_id}",
                source="circl",
            ))
        return results

    # -- caching -----------------------------------------------------------

    def _cache_result(self, cve_id: str, payload: dict) -> None:
        if not cve_id:
            return
        try:
            _cve_repo.set_cached(cve_id, payload)
        except Exception as exc:
            logger.debug("Failed to cache %s: %s", cve_id, exc)

    def get_cached(self, cve_id: str) -> Optional[dict]:
        cached = _cve_repo.get_cached(cve_id)
        if not cached:
            return None
        cached_at = datetime.fromisoformat(cached["cached_at"])
        age_days = (datetime.now(timezone.utc) - cached_at.replace(tzinfo=timezone.utc)).days
        if age_days > self.cache_ttl_days:
            return None
        return cached
