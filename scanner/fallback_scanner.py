"""
Pure-Python fallback scan engine.

Used automatically when the nmap binary is not installed. Implements a
TCP-connect port scan and best-effort banner grabbing using only the
standard library's socket module -- no subprocess, no shell, so there
is no injection surface at all. Host discovery falls back to a
TCP-connect probe against a handful of very common ports since raw
ICMP sockets require elevated privileges we do not want to request.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Optional

from utils.config import config
from utils.logger import get_logger
from utils.validators import ValidatedTarget, TargetType, validate_port_spec

logger = get_logger("scanner.fallback")

# service name guesses for common ports, used when we cannot bannergrab
COMMON_PORT_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    587: "smtp-submission", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 27017: "mongodb", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch", 11211: "memcached",
    123: "ntp", 161: "snmp",
}

DISCOVERY_PROBE_PORTS = [80, 443, 22, 445, 3389, 21, 25, 53]


@dataclass
class PortScanResult:
    port: int
    protocol: str
    state: str
    service: str = ""
    banner: str = ""


@dataclass
class HostScanResult:
    ip_address: str
    hostname: str = ""
    status: str = "down"
    response_ms: Optional[float] = None
    ports: list[PortScanResult] = field(default_factory=list)


def _expand_targets(target: ValidatedTarget) -> list[str]:
    if target.target_type == TargetType.CIDR:
        network = ipaddress.ip_network(target.normalized_value, strict=False)
        hosts = [str(ip) for ip in network.hosts()]
        # Guardrail: refuse to silently enumerate enormous ranges.
        return hosts[:1024]
    if target.target_type == TargetType.HOSTNAME:
        try:
            return [socket.gethostbyname(target.normalized_value)]
        except socket.gaierror:
            return []
    return [target.normalized_value]


def _parse_ports(port_spec: str) -> list[int]:
    spec = validate_port_spec(port_spec)
    ports: set[int] = set()
    for token in spec.replace(" ", "").split(","):
        token = token.replace("T:", "").replace("U:", "")
        if "-" in token:
            lo, hi = token.split("-")
            ports.update(range(int(lo), int(hi) + 1))
        elif token:
            ports.add(int(token))
    return sorted(ports)


_KNOWN_HTTP_PORTS = {80, 8080, 8000, 8888, 3000, 5000, 8443, 9090, 9000}


def _grab_banner(sock: socket.socket, port: int) -> tuple[str, str]:
    """
    Attempt to read a banner from a freshly-connected socket. Returns
    (banner_text, detected_service). For well-known HTTP-ish ports we
    proactively send a HEAD request; for anything else we first listen
    passively (many services -- SSH, FTP, SMTP -- greet immediately),
    and only if that yields nothing do we try a HEAD request as a
    fallback probe, which lets us correctly identify HTTP servers
    running on non-standard ports.
    """
    try:
        sock.settimeout(1.5)
        if port in _KNOWN_HTTP_PORTS:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            data = sock.recv(512)
        else:
            try:
                sock.settimeout(0.6)
                data = sock.recv(256)
            except socket.timeout:
                data = b""
            if not data:
                try:
                    sock.settimeout(1.5)
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    data = sock.recv(512)
                except Exception:
                    data = b""

        text = data.decode(errors="replace").strip().replace("\x00", "")[:200]
        service = ""
        if text.upper().startswith("HTTP/"):
            service = "http"
        elif text.startswith("SSH-"):
            service = "ssh"
        elif text.startswith("220") and ("FTP" in text.upper() or "ftp" in text.lower()):
            service = "ftp"
        elif text.startswith("220") and "SMTP" in text.upper():
            service = "smtp"
        return text, service
    except Exception:
        return "", ""


def _scan_one_port(ip: str, port: int, timeout: float) -> Optional[PortScanResult]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            banner, detected_service = _grab_banner(sock, port)
            service = COMMON_PORT_SERVICES.get(port, "") or detected_service
            return PortScanResult(
                port=port,
                protocol="tcp",
                state="open",
                service=service,
                banner=banner,
            )
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def discover_host(ip: str, timeout: float) -> HostScanResult:
    """TCP-connect-based liveness probe against common ports."""
    start = time.perf_counter()
    for port in DISCOVERY_PROBE_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                elapsed = (time.perf_counter() - start) * 1000
                hostname = ""
                try:
                    hostname = socket.getfqdn(ip)
                    if hostname == ip:
                        hostname = ""
                except OSError:
                    pass
                return HostScanResult(ip_address=ip, hostname=hostname, status="up", response_ms=round(elapsed, 1))
        except (socket.timeout, ConnectionRefusedError, OSError):
            continue
    return HostScanResult(ip_address=ip, status="down")


class FallbackScanner:
    """Threaded TCP-connect scanner used when nmap is not available."""

    def __init__(self, max_workers: Optional[int] = None, timeout: Optional[float] = None) -> None:
        self.max_workers = max_workers or int(config.get("scan.max_threads", 40))
        self.timeout = timeout or float(config.get("scan.socket_timeout", 2.0))

    def discover_hosts(
        self, target: ValidatedTarget, progress_cb: Optional[Callable[[int, int], None]] = None
    ) -> list[HostScanResult]:
        ips = _expand_targets(target)
        results: list[HostScanResult] = []
        total = len(ips)
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(discover_host, ip, self.timeout): ip for ip in ips}
            for done, future in enumerate(as_completed(futures), start=1):
                res = future.result()
                if res.status == "up":
                    results.append(res)
                if progress_cb:
                    progress_cb(done, total)
        return results

    def scan_ports(
        self,
        ip: str,
        port_spec: str,
        progress_cb: Optional[Callable[[int, int], None]] = None,
    ) -> list[PortScanResult]:
        ports = _parse_ports(port_spec)
        found: list[PortScanResult] = []
        total = len(ports)
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(_scan_one_port, ip, p, self.timeout): p for p in ports}
            for done, future in enumerate(as_completed(futures), start=1):
                result = future.result()
                if result:
                    found.append(result)
                if progress_cb:
                    progress_cb(done, total)
        return sorted(found, key=lambda r: r.port)
