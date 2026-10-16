"""
SQLite schema definition and connection management for Sentinel.

A single file-based database stores scans, discovered hosts, ports,
services, matched CVEs, web findings, and generated report records so
that historical results can be searched and re-reported later.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

from utils.config import config, PROJECT_ROOT
from utils.logger import get_logger

logger = get_logger("database.schema")

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target          TEXT NOT NULL,
    target_type     TEXT NOT NULL,
    scan_options    TEXT,               -- JSON blob of options used
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    status          TEXT NOT NULL DEFAULT 'running',   -- running|completed|failed|cancelled
    notes           TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip_address      TEXT NOT NULL,
    hostname        TEXT,
    status          TEXT,               -- up|down
    response_ms     REAL,
    mac_address     TEXT,
    vendor          TEXT,
    os_guess        TEXT
);

CREATE TABLE IF NOT EXISTS ports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port_number     INTEGER NOT NULL,
    protocol        TEXT NOT NULL,      -- tcp|udp
    state           TEXT NOT NULL,      -- open|closed|filtered
    service_name    TEXT,
    product         TEXT,
    version         TEXT,
    extra_info      TEXT,
    banner           TEXT
);

CREATE TABLE IF NOT EXISTS cve_matches (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    port_id         INTEGER REFERENCES ports(id) ON DELETE CASCADE,
    host_id         INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    cve_id          TEXT NOT NULL,
    description     TEXT,
    cvss_score      REAL,
    cvss_severity   TEXT,
    published_date  TEXT,
    reference_url   TEXT,
    exploit_known   INTEGER DEFAULT 0,
    patch_available INTEGER DEFAULT 0,
    source          TEXT                -- nvd|circl|local_cache
);

CREATE TABLE IF NOT EXISTS web_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    url             TEXT NOT NULL,
    category        TEXT NOT NULL,      -- headers|tls|cookies|directory_listing|etc
    finding         TEXT NOT NULL,
    severity        TEXT NOT NULL,      -- Critical|High|Medium|Low|Informational
    recommendation  TEXT
);

CREATE TABLE IF NOT EXISTS reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    format          TEXT NOT NULL,      -- pdf|html|csv|json
    file_path       TEXT NOT NULL,
    generated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cve_cache (
    id              TEXT PRIMARY KEY,   -- CVE ID
    payload_json    TEXT NOT NULL,
    cached_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_cve_port ON cve_matches(port_id);
CREATE INDEX IF NOT EXISTS idx_cve_cache_id ON cve_cache(id);
"""


class Database:
    """Thread-safe SQLite access with a single shared connection per thread."""

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or (PROJECT_ROOT / config.get("database.path", "database/sentinel.db"))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            self._local.conn = conn
        return self._local.conn

    def _init_schema(self) -> None:
        conn = self._connect()
        conn.executescript(SCHEMA_SQL)
        conn.commit()
        logger.debug("Database schema ensured at %s", self.db_path)

    @contextmanager
    def cursor(self):
        conn = self._connect()
        cur = conn.cursor()
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()


# Shared instance for the whole application.
db = Database()
