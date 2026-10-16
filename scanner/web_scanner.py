"""
Safe web application scanner.

Performs only passive / non-destructive checks: it reads responses to
ordinary GET requests, inspects headers, cookies, and TLS certificate
metadata. It never attempts authentication bypass, payload injection,
fuzzing, or denial-of-service style requests, in line with the
project's defensive-security-only scope.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from utils.config import config
from utils.logger import get_logger

logger = get_logger("scanner.web")

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS and protects against protocol downgrade attacks.",
    "Content-Security-Policy": "Mitigates XSS and data-injection attacks by restricting content sources.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing (should be 'nosniff').",
    "X-Frame-Options": "Protects against clickjacking (should be 'DENY' or 'SAMEORIGIN').",
    "Referrer-Policy": "Controls how much referrer information is leaked on navigation.",
    "Permissions-Policy": "Restricts which browser features/APIs the page may use.",
}


@dataclass
class WebFinding:
    category: str
    finding: str
    severity: str  # Critical|High|Medium|Low|Informational
    recommendation: str = ""


class WebScanner:
    def __init__(self) -> None:
        self.timeout = float(config.get("web_scan.timeout", 8))
        self.user_agent = config.get("web_scan.user_agent", "Sentinel-Scanner/1.0")
        self.verify_tls_default = bool(config.get("web_scan.verify_tls", True))
        self.max_redirects = int(config.get("web_scan.max_redirects", 5))

    def scan(self, url: str) -> list[WebFinding]:
        findings: list[WebFinding] = []
        session = requests.Session()
        session.headers.update({"User-Agent": self.user_agent})
        session.max_redirects = self.max_redirects

        response = self._safe_get(session, url)
        if response is None:
            findings.append(WebFinding(
                category="connectivity",
                finding=f"Could not establish an HTTP(S) connection to {url}.",
                severity="Informational",
            ))
            return findings

        findings.extend(self._check_https_redirect(session, url))
        findings.extend(self._check_security_headers(response))
        findings.extend(self._check_cookies(response))
        findings.extend(self._check_server_banner(response))
        findings.extend(self._check_tls(url))
        findings.extend(self._check_directory_listing(session, url))
        findings.extend(self._check_wellknown_files(session, url))
        findings.extend(self._check_forms(response))

        return findings

    # -- individual checks --------------------------------------------------

    def _safe_get(self, session: requests.Session, url: str) -> Optional[requests.Response]:
        try:
            return session.get(url, timeout=self.timeout, verify=self.verify_tls_default, allow_redirects=True)
        except requests.exceptions.SSLError:
            logger.warning("TLS verification failed for %s, retrying unverified for reporting purposes", url)
            try:
                return session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            except requests.RequestException as exc:
                logger.warning("GET failed for %s: %s", url, exc)
                return None
        except requests.RequestException as exc:
            logger.warning("GET failed for %s: %s", url, exc)
            return None

    def _check_https_redirect(self, session: requests.Session, url: str) -> list[WebFinding]:
        findings = []
        parsed = urlparse(url)
        if parsed.scheme == "https":
            return findings
        http_url = url
        try:
            resp = session.get(http_url, timeout=self.timeout, allow_redirects=False)
            if resp.is_redirect and resp.headers.get("Location", "").startswith("https://"):
                return findings
            findings.append(WebFinding(
                category="transport",
                finding="Site does not redirect HTTP traffic to HTTPS.",
                severity="Medium",
                recommendation="Configure the web server/load balancer to redirect all HTTP requests to HTTPS.",
            ))
        except requests.RequestException:
            pass
        return findings

    def _check_security_headers(self, response: requests.Response) -> list[WebFinding]:
        findings = []
        for header, explanation in SECURITY_HEADERS.items():
            if header not in response.headers:
                findings.append(WebFinding(
                    category="headers",
                    finding=f"Missing security header: {header}.",
                    severity="Low" if header in ("Referrer-Policy", "Permissions-Policy") else "Medium",
                    recommendation=explanation,
                ))
        return findings

    def _check_cookies(self, response: requests.Response) -> list[WebFinding]:
        findings = []
        for cookie in response.cookies:
            flags = []
            if not cookie.secure:
                flags.append("Secure")
            httponly = cookie.has_nonstandard_attr("HttpOnly") or cookie._rest.get("HttpOnly")
            if not httponly:
                flags.append("HttpOnly")
            samesite = cookie._rest.get("SameSite")
            if not samesite:
                flags.append("SameSite")
            if flags:
                findings.append(WebFinding(
                    category="cookies",
                    finding=f"Cookie '{cookie.name}' is missing flag(s): {', '.join(flags)}.",
                    severity="Medium",
                    recommendation="Set Secure, HttpOnly, and SameSite attributes on session/auth cookies.",
                ))
        return findings

    def _check_server_banner(self, response: requests.Response) -> list[WebFinding]:
        findings = []
        for header in ("Server", "X-Powered-By"):
            value = response.headers.get(header)
            if value:
                findings.append(WebFinding(
                    category="information_disclosure",
                    finding=f"'{header}' header discloses: {value}.",
                    severity="Low",
                    recommendation=f"Suppress or minimize the '{header}' header to reduce fingerprinting.",
                ))
        return findings

    def _check_tls(self, url: str) -> list[WebFinding]:
        findings = []
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return findings
        host = parsed.hostname
        port = parsed.port or 443
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                        findings.append(WebFinding(
                            category="tls",
                            finding=f"Server negotiated a deprecated TLS protocol version: {version}.",
                            severity="High",
                            recommendation="Disable protocols older than TLS 1.2 on the web server.",
                        ))
                    not_after = cert.get("notAfter")
                    if not_after:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days_left = (expiry - datetime.now(timezone.utc)).days
                        if days_left < 0:
                            findings.append(WebFinding(
                                category="tls", finding="TLS certificate has expired.",
                                severity="Critical", recommendation="Renew the TLS certificate immediately.",
                            ))
                        elif days_left < 30:
                            findings.append(WebFinding(
                                category="tls",
                                finding=f"TLS certificate expires in {days_left} day(s).",
                                severity="Medium", recommendation="Renew the TLS certificate before it expires.",
                            ))
        except ssl.SSLCertVerificationError as exc:
            findings.append(WebFinding(
                category="tls", finding=f"TLS certificate validation failed: {exc}",
                severity="High", recommendation="Install a valid certificate from a trusted CA.",
            ))
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            logger.debug("TLS check could not connect to %s:%s (%s)", host, port, exc)
        return findings

    def _check_directory_listing(self, session: requests.Session, url: str) -> list[WebFinding]:
        findings = []
        candidates = ["images/", "uploads/", "assets/", "backup/", "files/", "static/"]
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}/"
        for path in candidates:
            try:
                resp = session.get(urljoin(base, path), timeout=self.timeout, verify=self.verify_tls_default)
                text_lower = resp.text.lower()
                if resp.status_code == 200 and "index of /" in text_lower:
                    findings.append(WebFinding(
                        category="directory_listing",
                        finding=f"Directory listing appears to be enabled at /{path}.",
                        severity="Medium",
                        recommendation="Disable directory indexing on the web server for this path.",
                    ))
            except requests.RequestException:
                continue
        return findings

    def _check_wellknown_files(self, session: requests.Session, url: str) -> list[WebFinding]:
        findings = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}/"
        for filename, category in (("robots.txt", "info"), (".well-known/security.txt", "info")):
            try:
                resp = session.get(urljoin(base, filename), timeout=self.timeout, verify=self.verify_tls_default)
                if resp.status_code == 200:
                    findings.append(WebFinding(
                        category="disclosure",
                        finding=f"{filename} is present and publicly accessible.",
                        severity="Informational",
                        recommendation="Review its contents to ensure no sensitive paths are disclosed.",
                    ))
            except requests.RequestException:
                continue
        return findings

    def _check_forms(self, response: requests.Response) -> list[WebFinding]:
        findings = []
        try:
            soup = BeautifulSoup(response.text, "html.parser")
        except Exception:
            return findings
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = (form.get("method") or "get").lower()
            if action.startswith("http://"):
                findings.append(WebFinding(
                    category="forms",
                    finding=f"A form submits over plain HTTP to '{action}'.",
                    severity="High",
                    recommendation="Ensure all forms submit exclusively over HTTPS.",
                ))
            has_password = any(
                (inp.get("type") or "").lower() == "password" for inp in form.find_all("input")
            )
            if has_password and method == "get":
                findings.append(WebFinding(
                    category="forms",
                    finding="A login/password form uses the GET method, which may leak credentials in URLs/logs.",
                    severity="High",
                    recommendation="Change the form method to POST.",
                ))
        return findings
