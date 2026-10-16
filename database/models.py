"""
Dataclass models and repository classes for Sentinel's SQLite store.

Each repository wraps CRUD operations for one table so the rest of the
application never writes raw SQL outside this module.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional

from database.schema import db
from utils.logger import get_logger

logger = get_logger("database.models")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------
# Dataclasses
# --------------------------------------------------------------------------

@dataclass
class Scan:
    target: str
    target_type: str
    scan_options: dict[str, Any] = field(default_factory=dict)
    started_at: str = field(default_factory=_now)
    finished_at: Optional[str] = None
    status: str = "running"
    notes: str = ""
    id: Optional[int] = None


@dataclass
class Host:
    scan_id: int
    ip_address: str
    hostname: str = ""
    status: str = "up"
    response_ms: Optional[float] = None
    mac_address: str = ""
    vendor: str = ""
    os_guess: str = ""
    id: Optional[int] = None


@dataclass
class Port:
    host_id: int
    port_number: int
    protocol: str
    state: str
    service_name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    banner: str = ""
    id: Optional[int] = None


@dataclass
class CveMatch:
    cve_id: str
    description: str = ""
    cvss_score: Optional[float] = None
    cvss_severity: str = ""
    published_date: str = ""
    reference_url: str = ""
    exploit_known: bool = False
    patch_available: bool = False
    source: str = "nvd"
    port_id: Optional[int] = None
    host_id: Optional[int] = None
    id: Optional[int] = None


@dataclass
class WebFinding:
    scan_id: int
    url: str
    category: str
    finding: str
    severity: str
    recommendation: str = ""
    id: Optional[int] = None


# --------------------------------------------------------------------------
# Repositories
# --------------------------------------------------------------------------

class ScanRepository:
    def create(self, scan: Scan) -> int:
        with db.cursor() as cur:
            cur.execute(
                """INSERT INTO scans (target, target_type, scan_options, started_at, status, notes)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (scan.target, scan.target_type, json.dumps(scan.scan_options),
                 scan.started_at, scan.status, scan.notes),
            )
            return cur.lastrowid

    def mark_finished(self, scan_id: int, status: str = "completed") -> None:
        with db.cursor() as cur:
            cur.execute(
                "UPDATE scans SET status = ?, finished_at = ? WHERE id = ?",
                (status, _now(), scan_id),
            )

    def get(self, scan_id: int) -> Optional[dict]:
        with db.cursor() as cur:
            cur.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_recent(self, limit: int = 50) -> list[dict]:
        with db.cursor() as cur:
            cur.execute("SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,))
            return [dict(r) for r in cur.fetchall()]

    def search(self, **filters: Any) -> list[dict]:
        clauses, params = [], []
        for field_name in ("target", "status"):
            if filters.get(field_name):
                clauses.append(f"{field_name} LIKE ?")
                params.append(f"%{filters[field_name]}%")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with db.cursor() as cur:
            cur.execute(f"SELECT * FROM scans {where} ORDER BY started_at DESC", params)
            return [dict(r) for r in cur.fetchall()]

    def delete(self, scan_id: int) -> None:
        with db.cursor() as cur:
            cur.execute("DELETE FROM scans WHERE id = ?", (scan_id,))


class HostRepository:
    def create(self, host: Host) -> int:
        with db.cursor() as cur:
            cur.execute(
                """INSERT INTO hosts (scan_id, ip_address, hostname, status, response_ms,
                   mac_address, vendor, os_guess) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (host.scan_id, host.ip_address, host.hostname, host.status,
                 host.response_ms, host.mac_address, host.vendor, host.os_guess),
            )
            return cur.lastrowid

    def list_for_scan(self, scan_id: int) -> list[dict]:
        with db.cursor() as cur:
            cur.execute("SELECT * FROM hosts WHERE scan_id = ?", (scan_id,))
            return [dict(r) for r in cur.fetchall()]


class PortRepository:
    def create(self, port: Port) -> int:
        with db.cursor() as cur:
            cur.execute(
                """INSERT INTO ports (host_id, port_number, protocol, state, service_name,
                   product, version, extra_info, banner) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (port.host_id, port.port_number, port.protocol, port.state,
                 port.service_name, port.product, port.version, port.extra_info, port.banner),
            )
            return cur.lastrowid

    def list_for_host(self, host_id: int) -> list[dict]:
        with db.cursor() as cur:
            cur.execute("SELECT * FROM ports WHERE host_id = ?", (host_id,))
            return [dict(r) for r in cur.fetchall()]

    def list_for_scan(self, scan_id: int) -> list[dict]:
        with db.cursor() as cur:
            cur.execute(
                """SELECT ports.*, hosts.ip_address AS host_ip FROM ports
                   JOIN hosts ON ports.host_id = hosts.id
                   WHERE hosts.scan_id = ?""",
                (scan_id,),
            )
            return [dict(r) for r in cur.fetchall()]


class CveRepository:
    def create(self, match: CveMatch) -> int:
        with db.cursor() as cur:
            cur.execute(
                """INSERT INTO cve_matches (port_id, host_id, cve_id, description, cvss_score,
                   cvss_severity, published_date, reference_url, exploit_known, patch_available, source)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (match.port_id, match.host_id, match.cve_id, match.description, match.cvss_score,
                 match.cvss_severity, match.published_date, match.reference_url,
                 int(match.exploit_known), int(match.patch_available), match.source),
            )
            return cur.lastrowid

    def list_for_scan(self, scan_id: int) -> list[dict]:
        with db.cursor() as cur:
            cur.execute(
                """SELECT cve_matches.*, hosts.ip_address AS host_ip, ports.port_number
                   FROM cve_matches
                   JOIN hosts ON cve_matches.host_id = hosts.id
                   LEFT JOIN ports ON cve_matches.port_id = ports.id
                   WHERE hosts.scan_id = ?
                   ORDER BY cvss_score DESC""",
                (scan_id,),
            )
            return [dict(r) for r in cur.fetchall()]

    def get_cached(self, cve_id: str) -> Optional[dict]:
        with db.cursor() as cur:
            cur.execute("SELECT * FROM cve_cache WHERE id = ?", (cve_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def set_cached(self, cve_id: str, payload: dict) -> None:
        with db.cursor() as cur:
            cur.execute(
                """INSERT INTO cve_cache (id, payload_json, cached_at) VALUES (?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET payload_json = excluded.payload_json,
                   cached_at = excluded.cached_at""",
                (cve_id, json.dumps(payload), _now()),
            )


class WebFindingRepository:
    def create(self, finding: WebFinding) -> int:
        with db.cursor() as cur:
            cur.execute(
                """INSERT INTO web_findings (scan_id, url, category, finding, severity, recommendation)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (finding.scan_id, finding.url, finding.category, finding.finding,
                 finding.severity, finding.recommendation),
            )
            return cur.lastrowid

    def list_for_scan(self, scan_id: int) -> list[dict]:
        with db.cursor() as cur:
            cur.execute("SELECT * FROM web_findings WHERE scan_id = ?", (scan_id,))
            return [dict(r) for r in cur.fetchall()]


class ReportRepository:
    def create(self, scan_id: int, fmt: str, file_path: str) -> int:
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO reports (scan_id, format, file_path, generated_at) VALUES (?, ?, ?, ?)",
                (scan_id, fmt, file_path, _now()),
            )
            return cur.lastrowid

    def list_for_scan(self, scan_id: int) -> list[dict]:
        with db.cursor() as cur:
            cur.execute("SELECT * FROM reports WHERE scan_id = ?", (scan_id,))
            return [dict(r) for r in cur.fetchall()]
