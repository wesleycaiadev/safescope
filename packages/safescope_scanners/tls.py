"""TLS Scanner — analyzes certificate and protocol security.

Parser is separated from I/O: parse_tls_info() operates on a data dict,
making it testable with synthetic observations (no real TLS connection needed).
The scan() method handles the I/O and delegates to the parser.

Risk: PASSIVE — only observes, never modifies.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from safescope_core.policy.engine import Risk

from .base import RawObservation, ScanContext, Scanner, Severity


@dataclass
class TLSInfo:
    """Parsed TLS connection information. Pure data, no I/O."""

    protocol_version: str = ""
    cipher_name: str = ""
    cipher_bits: int = 0
    cert_subject: dict[str, str] = field(default_factory=dict)
    cert_issuer: dict[str, str] = field(default_factory=dict)
    cert_not_before: datetime | None = None
    cert_not_after: datetime | None = None
    cert_san: list[str] = field(default_factory=list)
    cert_serial: str = ""
    cert_is_self_signed: bool = False
    cert_is_wildcard: bool = False
    has_hsts: bool = False
    hsts_max_age: int = 0
    hsts_include_subdomains: bool = False
    hsts_preload: bool = False
    error: str | None = None


# ── Parser (pure logic, no I/O) ─────────────────────────────────────


def analyze_tls(info: TLSInfo, url: str) -> list[RawObservation]:
    """Analyze TLS info and produce observations. Pure function, no I/O."""
    observations: list[RawObservation] = []
    now = datetime.now(UTC)

    if info.error:
        observations.append(
            RawObservation(
                title="TLS Connection Failed",
                severity=Severity.CRITICAL,
                url=url,
                detail=f"Could not establish TLS connection: {info.error}",
                confidence=1.0,
                evidence={"error": info.error},
                cwe="CWE-319",
                owasp_wstg="WSTG-CRYP-01",
                remediation="Configure a valid TLS certificate and ensure the server supports TLS 1.2+.",
            )
        )
        return observations

    # Certificate expiration
    if info.cert_not_after:
        days_remaining = (info.cert_not_after - now).days
        if days_remaining < 0:
            observations.append(
                RawObservation(
                    title="TLS Certificate Expired",
                    severity=Severity.CRITICAL,
                    url=url,
                    detail=f"Certificate expired {abs(days_remaining)} days ago on {info.cert_not_after.isoformat()}",
                    confidence=1.0,
                    evidence={"not_after": info.cert_not_after.isoformat(), "days_expired": abs(days_remaining)},
                    cwe="CWE-295",
                    owasp_wstg="WSTG-CRYP-01",
                    remediation="Renew the TLS certificate immediately.",
                )
            )
        elif days_remaining < 30:
            observations.append(
                RawObservation(
                    title="TLS Certificate Expiring Soon",
                    severity=Severity.MEDIUM,
                    url=url,
                    detail=f"Certificate expires in {days_remaining} days on {info.cert_not_after.isoformat()}",
                    confidence=1.0,
                    evidence={"not_after": info.cert_not_after.isoformat(), "days_remaining": days_remaining},
                    cwe="CWE-295",
                    remediation="Renew the certificate before expiration. Consider automated renewal (e.g., certbot).",
                )
            )

    # Self-signed certificate
    if info.cert_is_self_signed:
        observations.append(
            RawObservation(
                title="Self-Signed TLS Certificate",
                severity=Severity.HIGH,
                url=url,
                detail="The certificate is self-signed and will not be trusted by browsers.",
                confidence=1.0,
                evidence={"issuer": info.cert_issuer, "subject": info.cert_subject},
                cwe="CWE-295",
                remediation="Use a certificate from a trusted CA (Let's Encrypt is free).",
            )
        )

    # Weak protocol version
    weak_protocols = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
    if info.protocol_version in weak_protocols:
        observations.append(
            RawObservation(
                title="Weak TLS Protocol Version",
                severity=Severity.HIGH,
                url=url,
                detail=f"Server negotiated {info.protocol_version}, which has known vulnerabilities.",
                confidence=1.0,
                evidence={"protocol": info.protocol_version},
                cwe="CWE-326",
                owasp_wstg="WSTG-CRYP-01",
                remediation="Disable TLS 1.0 and 1.1. Configure minimum TLS 1.2.",
            )
        )

    # Weak cipher
    weak_ciphers = {"RC4", "DES", "3DES", "NULL", "EXPORT", "anon"}
    if info.cipher_name and any(weak in info.cipher_name.upper() for weak in weak_ciphers):
        observations.append(
            RawObservation(
                title="Weak Cipher Suite",
                severity=Severity.HIGH,
                url=url,
                detail=f"Cipher suite '{info.cipher_name}' is considered weak.",
                confidence=1.0,
                evidence={"cipher": info.cipher_name, "bits": info.cipher_bits},
                cwe="CWE-326",
                remediation="Configure strong cipher suites. Prefer ECDHE with AES-GCM or ChaCha20.",
            )
        )

    # HSTS
    if not info.has_hsts:
        observations.append(
            RawObservation(
                title="Missing HSTS Header",
                severity=Severity.MEDIUM,
                url=url,
                detail="Strict-Transport-Security header is not set. Visitors may access the site via HTTP.",
                confidence=1.0,
                evidence={"hsts": False},
                cwe="CWE-319",
                owasp_wstg="WSTG-CRYP-03",
                remediation="Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.",
            )
        )
    elif info.hsts_max_age < 15_768_000:  # < 6 months
        observations.append(
            RawObservation(
                title="HSTS Max-Age Too Short",
                severity=Severity.LOW,
                url=url,
                detail=(
                    f"HSTS max-age is {info.hsts_max_age}s ({info.hsts_max_age // 86400} days). Recommend >= 1 year."
                ),
                confidence=0.9,
                evidence={"hsts_max_age": info.hsts_max_age},
                remediation="Set max-age to at least 31536000 (1 year).",
            )
        )

    # All good
    if not observations:
        observations.append(
            RawObservation(
                title="TLS Configuration Adequate",
                severity=Severity.INFO,
                url=url,
                detail=(
                    f"Protocol: {info.protocol_version}, "
                    f"Cipher: {info.cipher_name} ({info.cipher_bits} bits), "
                    f"HSTS: {info.hsts_max_age}s"
                ),
                confidence=1.0,
                evidence={
                    "protocol": info.protocol_version,
                    "cipher": info.cipher_name,
                    "hsts_max_age": info.hsts_max_age,
                },
            )
        )

    return observations


# ── Scanner (I/O wrapper) ───────────────────────────────────────────


class TLSScanner(Scanner):
    """Passive TLS scanner — checks certificate, protocol, cipher, HSTS."""

    id = "tls-check"
    name = "TLS Scanner"
    risk = Risk.PASSIVE
    requires_auth = False
    budget_units = 2  # 1 TLS handshake + 1 HEAD for HSTS

    async def scan(self, ctx: ScanContext) -> list[RawObservation]:
        """Connect to the target, gather TLS info, and analyze."""
        parsed = urlsplit(ctx.target_base_url)
        hostname = parsed.hostname or ""
        port = parsed.port or 443

        info = await self._gather_tls_info(hostname, port, ctx)
        return analyze_tls(info, ctx.target_base_url)

    async def _gather_tls_info(self, hostname: str, port: int, ctx: ScanContext) -> TLSInfo:
        """Gather TLS data only through the provided gated transport."""
        info = TLSInfo()
        if ctx.tls is None:
            info.error = "TLS transport is not configured"
            return info
        try:
            probe = await ctx.tls(hostname, port)
        except OSError as error:
            info.error = str(error)
            return info

        info.protocol_version = probe.protocol_version
        info.cipher_name = probe.cipher_name
        info.cipher_bits = probe.cipher_bits
        if probe.certificate:
            info = self._parse_cert(probe.certificate, info)

        # Check HSTS via HTTP response
        try:
            from safescope_core.policy.request import RequestDescriptor

            req = RequestDescriptor(method="HEAD", url=f"https://{hostname}:{port}/")
            resp = await ctx.http(req)
            hsts_value = resp.headers.get("strict-transport-security", "")
            if hsts_value:
                info.has_hsts = True
                for part in hsts_value.split(";"):
                    part = part.strip().lower()
                    if part.startswith("max-age="):
                        with contextlib.suppress(ValueError):
                            info.hsts_max_age = int(part.split("=", 1)[1])
                    elif part == "includesubdomains":
                        info.hsts_include_subdomains = True
                    elif part == "preload":
                        info.hsts_preload = True
        except Exception:
            # The TLS observation remains useful even if the optional HSTS
            # HTTP request fails.
            info.has_hsts = False

        return info

    @staticmethod
    def _parse_cert(cert: dict[str, Any], info: TLSInfo) -> TLSInfo:
        """Parse certificate dict from ssl.getpeercert(). Pure logic."""
        # Subject
        for rdn in cert.get("subject", ()):
            for attr, val in rdn:
                info.cert_subject[attr] = val

        # Issuer
        for rdn in cert.get("issuer", ()):
            for attr, val in rdn:
                info.cert_issuer[attr] = val

        # Self-signed check
        info.cert_is_self_signed = info.cert_subject == info.cert_issuer

        # Validity dates
        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")
        if not_before:
            with contextlib.suppress(ValueError):
                info.cert_not_before = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        if not_after:
            with contextlib.suppress(ValueError):
                info.cert_not_after = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)

        # SAN
        for san_type, san_value in cert.get("subjectAltName", ()):
            info.cert_san.append(f"{san_type}:{san_value}")

        # Wildcard
        cn = info.cert_subject.get("commonName", "")
        info.cert_is_wildcard = cn.startswith("*.")

        # Serial
        info.cert_serial = cert.get("serialNumber", "")

        return info
