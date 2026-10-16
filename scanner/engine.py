"""
Primary scan engine built on python-nmap.

python-nmap invokes the real 'nmap' binary under the hood via
subprocess with an argument LIST (never a shell string), so this
module never constructs shell commands from user input -- all target
and port-spec values are validated (utils.validators) before being
handed to the nmap.PortScanner API.

If the nmap binary is not installed, `is_nmap_available()` returns
False and callers should fall back to scanner.fallback_scanner instead.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from typing import Callable, Optional

from utils.logger import get_logger
from utils.validators import ValidatedTarget, validate_port_spec

logger = get_logger("scanner.engine")

try:
    import nmap  # python-nmap
    _NMAP_LIB_AVAILABLE = True
except ImportError:
    _NMAP_LIB_AVAILABLE = False


def is_nmap_available() -> bool:
    """True only if both the python-nmap library and the nmap binary exist."""
    return _NMAP_LIB_AVAILABLE and shutil.which("nmap") is not None


def is_openvas_available() -> bool:
    """
    Best-effort detection of a local OpenVAS / Greenbone install.
    Checks for the gvm-cli tool and the common gvmd unix socket.
    Never raises -- returns False on any uncertainty.
    """
    if shutil.which("gvm-cli") is not None:
        return True
    from pathlib import Path
    from utils.config import config
    socket_path = Path(config.get("openvas.socket_path", "/run/gvm/gvmd.sock"))
    return socket_path.exists()


@dataclass
class NmapPortResult:
    port: int
    protocol: str
    state: str
    service: str
    product: str
    version: str
    extra_info: str


@dataclass
class NmapHostResult:
    ip_address: str
    hostname: str
    status: str
    mac_address: str = ""
    vendor: str = ""
    os_guess: str = ""
    ports: list[NmapPortResult] = field(default_factory=list)


class NmapEngine:
    """Thin, safety-conscious wrapper around python-nmap's PortScanner."""

    def __init__(self) -> None:
        if not _NMAP_LIB_AVAILABLE:
            raise RuntimeError("python-nmap is not installed.")
        self._scanner = nmap.PortScanner()

    def scan(
        self,
        target: ValidatedTarget,
        port_spec: str,
        *,
        tcp: bool = True,
        udp: bool = False,
        service_detection: bool = True,
        os_detection: bool = False,
        timing_template: int = 3,
        skip_host_discovery: bool = False,
    ) -> list[NmapHostResult]:
        """
        Run an nmap scan against an already-validated target.

        Arguments map to a whitelisted set of nmap flags -- nothing here is
        built from raw string concatenation with user input.

        `skip_host_discovery=True` adds nmap's -Pn flag, which treats the
        target as online and scans its ports directly instead of first
        doing a lightweight ping-style discovery pass and skipping hosts
        that don't answer it. This matters for hosts/firewalls that block
        ICMP/common discovery probes but still serve the port(s) you
        actually asked to scan.
        """
        ports = validate_port_spec(port_spec)

        flags = [f"-T{max(0, min(5, timing_template))}"]
        if skip_host_discovery:
            flags.append("-Pn")
        if tcp and udp:
            flags.append("-sS -sU")
        elif udp:
            flags.append("-sU")
        else:
            flags.append("-sS")

        if service_detection:
            flags.append("-sV")
        if os_detection:
            flags.append("-O")
        flags.append("--host-timeout 300s")

        arg_string = " ".join(flags)
        logger.info("Running nmap scan on %s (ports=%s, args=%s)",
                    target.normalized_value, ports, arg_string)

        try:
            self._scanner.scan(
                hosts=target.normalized_value, ports=ports, arguments=arg_string, sudo=False
            )
        except Exception as exc:  # nmap.PortScannerError and friends
            logger.error("nmap scan failed for %s: %s", target.normalized_value, exc)
            raise

        results: list[NmapHostResult] = []
        for host in self._scanner.all_hosts():
            info = self._scanner[host]
            hostnames = info.hostnames() if hasattr(info, "hostnames") else []
            hostname = hostnames[0]["name"] if hostnames else ""

            addresses = info.get("addresses", {})
            mac = addresses.get("mac", "")
            vendor_map = info.get("vendor", {})
            vendor = vendor_map.get(mac, "") if mac else ""

            os_guess = ""
            if "osmatch" in info and info["osmatch"]:
                os_guess = info["osmatch"][0].get("name", "")

            host_result = NmapHostResult(
                ip_address=host,
                hostname=hostname,
                status=info.state(),
                mac_address=mac,
                vendor=vendor,
                os_guess=os_guess,
            )

            for proto in ("tcp", "udp"):
                if proto not in info:
                    continue
                for port_num, pdata in info[proto].items():
                    host_result.ports.append(
                        NmapPortResult(
                            port=int(port_num),
                            protocol=proto,
                            state=pdata.get("state", "unknown"),
                            service=pdata.get("name", ""),
                            product=pdata.get("product", ""),
                            version=pdata.get("version", ""),
                            extra_info=pdata.get("extrainfo", ""),
                        )
                    )
            results.append(host_result)

        return results

    def ping_sweep(self, target: ValidatedTarget) -> list[NmapHostResult]:
        """Host discovery only (-sn), no port scan."""
        logger.info("Running nmap host discovery on %s", target.normalized_value)
        self._scanner.scan(hosts=target.normalized_value, arguments="-sn -T4")
        results = []
        for host in self._scanner.all_hosts():
            info = self._scanner[host]
            hostnames = info.hostnames() if hasattr(info, "hostnames") else []
            hostname = hostnames[0]["name"] if hostnames else ""
            addresses = info.get("addresses", {})
            mac = addresses.get("mac", "")
            vendor_map = info.get("vendor", {})
            results.append(
                NmapHostResult(
                    ip_address=host,
                    hostname=hostname,
                    status=info.state(),
                    mac_address=mac,
                    vendor=vendor_map.get(mac, "") if mac else "",
                )
            )
        return results
