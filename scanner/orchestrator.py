"""
Scan orchestrator.

Coordinates host discovery -> port scanning -> service/version
detection -> CVE correlation -> (optional) web scan -> risk scoring,
persisting results to SQLite as it goes and reporting progress through
a callback so the GUI thread can update without blocking.

IMPORTANT: every orchestrated scan requires an explicit `authorized=True`
flag. This mirrors the authorization checkbox the GUI requires the user
to tick before a scan can start, and is a deliberate second gate against
accidentally scanning systems without permission.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Callable, Optional

from cve.lookup import CveLookupClient
from database.models import (
    Scan, Host, Port, CveMatch, WebFinding as WebFindingRow,
    ScanRepository, HostRepository, PortRepository, CveRepository, WebFindingRepository,
)
from scanner.engine import NmapEngine, is_nmap_available
from scanner.fallback_scanner import FallbackScanner, discover_host
from scanner.risk_engine import assess_cve_risk, assess_finding_risk
from scanner.web_scanner import WebScanner
from utils.config import config
from utils.logger import get_logger
from utils.validators import ValidatedTarget, TargetType, is_private_or_loopback

logger = get_logger("scanner.orchestrator")


class AuthorizationError(RuntimeError):
    """Raised when a scan is requested without the required authorization flag."""


@dataclass
class ScanOptions:
    port_spec: str = "1-1024"
    host_discovery: bool = True
    tcp_scan: bool = True
    udp_scan: bool = False
    service_detection: bool = True
    os_detection: bool = False
    web_scan: bool = False
    cve_lookup: bool = True


@dataclass
class ProgressEvent:
    stage: str          # discovery|ports|services|cve|web|done|error
    message: str
    current: int = 0
    total: int = 0


ProgressCallback = Callable[[ProgressEvent], None]


class ScanOrchestrator:
    def __init__(self) -> None:
        self.scan_repo = ScanRepository()
        self.host_repo = HostRepository()
        self.port_repo = PortRepository()
        self.cve_repo = CveRepository()
        self.web_repo = WebFindingRepository()
        self.cve_client = CveLookupClient()
        self.web_scanner = WebScanner()
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def run(
        self,
        target: ValidatedTarget,
        options: ScanOptions,
        authorized: bool,
        progress_cb: Optional[ProgressCallback] = None,
    ) -> int:
        if not authorized:
            raise AuthorizationError(
                "Scan refused: you must confirm you own this target or have explicit "
                "written authorization to test it."
            )
        self._cancelled = False

        def emit(stage: str, message: str, current: int = 0, total: int = 0) -> None:
            if progress_cb:
                progress_cb(ProgressEvent(stage=stage, message=message, current=current, total=total))

        scan_id = self.scan_repo.create(Scan(
            target=target.raw_input,
            target_type=target.target_type.value,
            scan_options=options.__dict__,
        ))

        try:
            if target.target_type == TargetType.URL:
                self._run_web_only(scan_id, target, emit)
            else:
                self._run_network_scan(scan_id, target, options, emit)

            self.scan_repo.mark_finished(scan_id, "completed")
            emit("done", "Scan completed.")
        except Exception as exc:
            logger.exception("Scan %s failed", scan_id)
            self.scan_repo.mark_finished(scan_id, "failed")
            emit("error", f"Scan failed: {exc}")
            raise
        return scan_id

    # -- web-only target -----------------------------------------------------

    def _run_web_only(self, scan_id: int, target: ValidatedTarget, emit) -> None:
        emit("web", f"Running safe web scan against {target.normalized_value}...")
        findings = self.web_scanner.scan(target.normalized_value)
        for f in findings:
            self.web_repo.create(WebFindingRow(
                scan_id=scan_id, url=target.normalized_value, category=f.category,
                finding=f.finding, severity=f.severity, recommendation=f.recommendation,
            ))
        emit("web", f"Web scan found {len(findings)} finding(s).", len(findings), len(findings))

    # -- network target -------------------------------------------------------

    def _run_network_scan(self, scan_id: int, target: ValidatedTarget, options: ScanOptions, emit) -> None:
        use_nmap = is_nmap_available()
        emit("discovery", f"Starting host discovery ({'nmap' if use_nmap else 'fallback scanner'})...")

        if target.target_type == TargetType.CIDR:
            # A CIDR range can be large, so we genuinely need a discovery
            # pass to find which hosts exist before scanning each one.
            if use_nmap:
                hosts = self._discover_with_nmap(target, options, emit)
            else:
                hosts = self._discover_with_fallback(target, emit)
        else:
            # Single IP or hostname: never gate the scan behind a
            # fixed-port "is it up" probe -- resolve it and scan directly.
            # If the user asked for discovery info too, fetch it as
            # best-effort metadata (hostname / response time) without
            # dropping the host if that probe happens not to succeed.
            hosts = self._resolve_single_target(target, options, use_nmap, emit)

        if self._cancelled:
            return

        for host_data in hosts:
            if self._cancelled:
                break
            host_id = self.host_repo.create(Host(
                scan_id=scan_id,
                ip_address=host_data["ip_address"],
                hostname=host_data.get("hostname", ""),
                status=host_data.get("status", "up"),
                response_ms=host_data.get("response_ms"),
                mac_address=host_data.get("mac_address", ""),
                vendor=host_data.get("vendor", ""),
                os_guess=host_data.get("os_guess", ""),
            ))

            ports = host_data.get("ports")
            if ports is None and (options.tcp_scan or options.udp_scan):
                ports = self._scan_ports_for_host(host_data["ip_address"], options, use_nmap, emit)
            ports = ports or []

            internet_exposed = not is_private_or_loopback(host_data["ip_address"])

            for p in ports:
                port_id = self.port_repo.create(Port(
                    host_id=host_id,
                    port_number=p["port"],
                    protocol=p["protocol"],
                    state=p["state"],
                    service_name=p.get("service", ""),
                    product=p.get("product", ""),
                    version=p.get("version", ""),
                    extra_info=p.get("extra_info", ""),
                    banner=p.get("banner", ""),
                ))

                if options.cve_lookup and p.get("state") == "open" and (p.get("product") or p.get("service")):
                    self._lookup_and_store_cves(host_id, port_id, p, internet_exposed, emit)

                if options.web_scan and p.get("service", "").lower() in ("http", "https", "http-alt", "https-alt"):
                    scheme = "https" if "https" in p.get("service", "").lower() or p["port"] in (443, 8443) else "http"
                    url = f"{scheme}://{host_data['ip_address']}:{p['port']}"
                    self._run_web_scan_for_url(scan_id, url, emit)

        emit("done", f"Discovered {len(hosts)} host(s).", len(hosts), len(hosts))

    def _resolve_single_target(self, target: ValidatedTarget, options: ScanOptions, use_nmap: bool, emit) -> list[dict]:
        if target.target_type == TargetType.HOSTNAME:
            from utils.validators import resolve_hostname
            ip = resolve_hostname(target.normalized_value)
            if ip is None:
                emit("discovery", f"Could not resolve hostname '{target.normalized_value}'.")
                return []
        else:
            ip = target.normalized_value

        host_entry: dict = {"ip_address": ip, "status": "up"}

        # If nmap is available and a port/UDP scan was requested, let nmap
        # do discovery + scanning together in one call (more efficient,
        # and -Pn ensures a quiet host still gets scanned when the user
        # didn't ask for a separate discovery gate).
        if use_nmap and (options.tcp_scan or options.udp_scan):
            try:
                engine = NmapEngine()
                results = engine.scan(
                    target, options.port_spec, tcp=options.tcp_scan, udp=options.udp_scan,
                    service_detection=options.service_detection, os_detection=options.os_detection,
                    skip_host_discovery=not options.host_discovery,
                )
                if results:
                    h = results[0]
                    return [{
                        "ip_address": h.ip_address, "hostname": h.hostname, "status": "up",
                        "mac_address": h.mac_address, "vendor": h.vendor, "os_guess": h.os_guess,
                        "ports": [
                            {"port": p.port, "protocol": p.protocol, "state": p.state, "service": p.service,
                             "product": p.product, "version": p.version, "extra_info": p.extra_info}
                            for p in h.ports
                        ],
                    }]
                # nmap ran but returned nothing for this host -- fall through to fallback path
            except Exception as exc:
                logger.warning("nmap engine failed (%s); falling back to socket scanner", exc)

        if options.host_discovery:
            scanner = FallbackScanner()
            probe = discover_host(ip, scanner.timeout)
            if probe.status == "up":
                host_entry["hostname"] = probe.hostname
                host_entry["response_ms"] = probe.response_ms
            # NOTE: we deliberately do NOT drop the host here even if the
            # discovery probe says "down" -- it only tested a handful of
            # common ports, and the user's requested port range may still
            # be reachable.

        return [host_entry]

    def _discover_with_nmap(self, target: ValidatedTarget, options: ScanOptions, emit) -> list[dict]:
        engine = NmapEngine()
        try:
            if options.tcp_scan or options.udp_scan:
                results = engine.scan(
                    target, options.port_spec,
                    tcp=options.tcp_scan, udp=options.udp_scan,
                    service_detection=options.service_detection,
                    os_detection=options.os_detection,
                    skip_host_discovery=not options.host_discovery,
                )
            else:
                results = engine.ping_sweep(target)
        except Exception as exc:
            logger.warning("nmap engine failed (%s); falling back to socket scanner", exc)
            return self._discover_with_fallback(target, emit)

        hosts = []
        for h in results:
            hosts.append({
                "ip_address": h.ip_address, "hostname": h.hostname, "status": h.status,
                "mac_address": h.mac_address, "vendor": h.vendor, "os_guess": h.os_guess,
                "ports": [
                    {"port": p.port, "protocol": p.protocol, "state": p.state, "service": p.service,
                     "product": p.product, "version": p.version, "extra_info": p.extra_info}
                    for p in h.ports
                ],
            })
        emit("discovery", f"nmap discovered {len(hosts)} host(s).", len(hosts), len(hosts))
        return hosts

    def _discover_with_fallback(self, target: ValidatedTarget, emit) -> list[dict]:
        scanner = FallbackScanner()
        found = scanner.discover_hosts(
            target, progress_cb=lambda cur, total: emit("discovery", "Probing hosts...", cur, total)
        )
        return [{
            "ip_address": h.ip_address, "hostname": h.hostname, "status": h.status,
            "response_ms": h.response_ms, "ports": None,
        } for h in found]

    def _scan_ports_for_host(self, ip: str, options: ScanOptions, use_nmap: bool, emit) -> list[dict]:
        scanner = FallbackScanner()
        results = scanner.scan_ports(
            ip, options.port_spec,
            progress_cb=lambda cur, total: emit("ports", f"Scanning ports on {ip}...", cur, total),
        )
        return [{"port": r.port, "protocol": r.protocol, "state": r.state,
                  "service": r.service, "banner": r.banner} for r in results]

    def _lookup_and_store_cves(self, host_id: int, port_id: int, port_data: dict, internet_exposed: bool, emit) -> None:
        product = port_data.get("product") or port_data.get("service", "")
        version = port_data.get("version", "")
        if not product:
            return
        emit("cve", f"Checking CVEs for {product} {version}...")
        try:
            matches = self.cve_client.search_by_product_version(product, version)
        except Exception as exc:
            logger.warning("CVE lookup failed for %s %s: %s", product, version, exc)
            return

        for m in matches:
            risk = assess_cve_risk(
                cvss_score=m.cvss_score, exploit_known=m.exploit_known,
                patch_available=m.patch_available, internet_exposed=internet_exposed,
                service_name=port_data.get("service", ""),
            )
            self.cve_repo.create(CveMatch(
                port_id=port_id, host_id=host_id, cve_id=m.cve_id, description=m.description,
                cvss_score=m.cvss_score, cvss_severity=risk.severity, published_date=m.published_date,
                reference_url=m.reference_url, exploit_known=m.exploit_known,
                patch_available=m.patch_available, source=m.source,
            ))

    def _run_web_scan_for_url(self, scan_id: int, url: str, emit) -> None:
        emit("web", f"Running safe web checks on {url}...")
        try:
            findings = self.web_scanner.scan(url)
        except Exception as exc:
            logger.warning("Web scan failed for %s: %s", url, exc)
            return
        for f in findings:
            self.web_repo.create(WebFindingRow(
                scan_id=scan_id, url=url, category=f.category,
                finding=f.finding, severity=f.severity, recommendation=f.recommendation,
            ))
