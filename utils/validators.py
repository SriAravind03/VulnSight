"""
Input validation for Sentinel Vulnerability Scanner.

Every value that originates from the user (target strings, ports,
URLs, filenames) MUST be validated through this module before being
used to build a scan, a filesystem path, or -- especially -- any
argument passed to a subprocess. This is the primary defense against
command injection and path traversal.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse


class TargetType(str, Enum):
    IP = "ip"
    CIDR = "cidr"
    HOSTNAME = "hostname"
    URL = "url"


class ValidationError(ValueError):
    """Raised when user-supplied input fails validation."""


# Hostnames: letters, digits, hyphens, dots. RFC 1123-ish, no wildcards.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

# Characters that must never appear in a value destined for a subprocess
# argument list, even though we never use shell=True or string-built commands.
_SHELL_METACHARACTERS = set(";&|`$()<>\\\"'\n\r")


def reject_shell_metacharacters(value: str, field_name: str = "value") -> None:
    if any(ch in _SHELL_METACHARACTERS for ch in value):
        raise ValidationError(
            f"{field_name} contains disallowed characters and was rejected."
        )


def classify_and_validate_target(raw: str) -> tuple[TargetType, str]:
    """
    Determine whether `raw` is an IP, CIDR block, hostname, or URL, validate
    it strictly, and return the normalized (type, value) pair.

    Raises ValidationError on anything that doesn't cleanly parse -- we
    never pass ambiguous or partially-valid input further into the pipeline.
    """
    if not raw or not raw.strip():
        raise ValidationError("Target cannot be empty.")

    value = raw.strip()
    reject_shell_metacharacters(value, "Target")

    # URL (web target)
    if value.lower().startswith(("http://", "https://")):
        parsed = urlparse(value)
        if not parsed.netloc:
            raise ValidationError(f"'{value}' is not a valid URL.")
        return TargetType.URL, value

    # CIDR network
    if "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValidationError(f"'{value}' is not a valid CIDR network: {exc}")
        return TargetType.CIDR, str(network)

    # Single IP address
    try:
        ip = ipaddress.ip_address(value)
        return TargetType.IP, str(ip)
    except ValueError:
        pass

    # Hostname
    if _HOSTNAME_RE.match(value):
        return TargetType.HOSTNAME, value

    raise ValidationError(
        f"'{value}' is not a recognizable IP, CIDR range, hostname, or URL."
    )


def validate_port_spec(port_spec: str) -> str:
    """
    Validate an nmap-style port specification, e.g. '22,80,443' or
    '1-1024' or '1-65535,U:53'. Returns the sanitized spec or raises.
    """
    if not port_spec or not port_spec.strip():
        raise ValidationError("Port specification cannot be empty.")
    value = port_spec.strip()
    reject_shell_metacharacters(value, "Port specification")
    if not re.match(r"^[0-9,\-:UT ]+$", value):
        raise ValidationError(
            f"'{value}' contains characters not valid in a port specification."
        )
    for token in re.split(r"[,]", value.replace(" ", "")):
        token = token.replace("U:", "").replace("T:", "")
        if "-" in token:
            lo, _, hi = token.partition("-")
            _validate_port_number(lo)
            _validate_port_number(hi)
        elif token:
            _validate_port_number(token)
    return value


def _validate_port_number(token: str) -> None:
    if not token.isdigit():
        raise ValidationError(f"'{token}' is not a valid port number.")
    port = int(token)
    if not (0 <= port <= 65535):
        raise ValidationError(f"Port {port} is out of the valid range 0-65535.")


def is_private_or_loopback(ip_str: str) -> bool:
    """Helper used to nudge users toward authorized/local targets in the UI."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def resolve_hostname(hostname: str) -> str | None:
    """Best-effort DNS resolution; returns None rather than raising."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def sanitize_filename(name: str) -> str:
    """Strip path separators and traversal sequences from a report filename."""
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    name = name.replace("..", "_")
    return name.strip("_") or "report"


@dataclass
class ValidatedTarget:
    """Normalized representation of a user-entered scan target."""

    raw_input: str
    target_type: TargetType
    normalized_value: str

    @classmethod
    def from_input(cls, raw: str) -> "ValidatedTarget":
        target_type, normalized = classify_and_validate_target(raw)
        return cls(raw_input=raw.strip(), target_type=target_type, normalized_value=normalized)
