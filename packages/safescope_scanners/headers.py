"""Security Headers Scanner — checks HTTP response headers for security best practices.

Parser is separated from I/O: analyze_headers() operates on a dict of headers,
making it testable with synthetic data. The scan() method handles the I/O.

Risk: PASSIVE — only observes via a single GET request.
"""

from __future__ import annotations

from typing import Any

from safescope_core.policy.engine import Risk

from .base import RawObservation, ScanContext, Scanner, Severity

# ── Header definitions ───────────────────────────────────────────────

SECURITY_HEADERS: dict[str, dict[str, Any]] = {
    "strict-transport-security": {
        "severity": Severity.MEDIUM,
        "title": "Missing HSTS Header",
        "cwe": "CWE-319",
        "owasp": "WSTG-CRYP-03",
        "remediation": "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
    },
    "content-security-policy": {
        "severity": Severity.HIGH,
        "title": "Missing Content-Security-Policy",
        "cwe": "CWE-79",
        "owasp": "WSTG-CONF-12",
        "remediation": (
            "Implement a Content-Security-Policy. Start with `default-src 'self'` "
            "and allow only necessary sources. Avoid `unsafe-inline` and `unsafe-eval`."
        ),
    },
    "x-frame-options": {
        "severity": Severity.MEDIUM,
        "title": "Missing X-Frame-Options",
        "cwe": "CWE-1021",
        "owasp": "WSTG-CLNT-09",
        "remediation": "Add `X-Frame-Options: DENY` or `SAMEORIGIN`. Better: use CSP `frame-ancestors`.",
    },
    "x-content-type-options": {
        "severity": Severity.LOW,
        "title": "Missing X-Content-Type-Options",
        "cwe": "CWE-16",
        "remediation": "Add `X-Content-Type-Options: nosniff`.",
    },
    "referrer-policy": {
        "severity": Severity.LOW,
        "title": "Missing Referrer-Policy",
        "cwe": "CWE-200",
        "remediation": "Add `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`.",
    },
    "permissions-policy": {
        "severity": Severity.LOW,
        "title": "Missing Permissions-Policy",
        "cwe": "CWE-16",
        "remediation": (
            "Add `Permissions-Policy` to restrict browser features. "
            "Example: `camera=(), microphone=(), geolocation=()`."
        ),
    },
}

# Headers that leak information when present
INFO_LEAK_HEADERS: dict[str, dict[str, Any]] = {
    "server": {
        "severity": Severity.LOW,
        "title": "Server Header Exposes Technology",
        "cwe": "CWE-200",
        "remediation": "Remove or genericize the Server header to avoid exposing server software and version.",
    },
    "x-powered-by": {
        "severity": Severity.LOW,
        "title": "X-Powered-By Header Exposes Technology",
        "cwe": "CWE-200",
        "remediation": "Remove the X-Powered-By header.",
    },
    "x-aspnet-version": {
        "severity": Severity.LOW,
        "title": "X-AspNet-Version Header Exposes Framework",
        "cwe": "CWE-200",
        "remediation": "Remove the X-AspNet-Version header in web.config.",
    },
    "x-aspnetmvc-version": {
        "severity": Severity.LOW,
        "title": "X-AspNetMvc-Version Header Exposes Framework",
        "cwe": "CWE-200",
        "remediation": "Remove the X-AspNetMvc-Version header.",
    },
}


# ── Parser (pure logic, no I/O) ─────────────────────────────────────


def analyze_headers(headers: dict[str, str], url: str) -> list[RawObservation]:
    """Analyze HTTP response headers for security issues. Pure function, no I/O.

    Args:
        headers: Response headers (keys lowercased).
        url: The URL that was checked.

    Returns:
        List of observations (findings).
    """
    observations: list[RawObservation] = []
    lower_headers = {k.lower(): v for k, v in headers.items()}

    # Check for missing security headers
    for header_name, meta in SECURITY_HEADERS.items():
        if header_name not in lower_headers:
            observations.append(
                RawObservation(
                    title=meta["title"],
                    severity=meta["severity"],
                    url=url,
                    detail=f"The `{header_name}` header is not present in the response.",
                    confidence=1.0,
                    evidence={"header": header_name, "present": False},
                    cwe=meta.get("cwe"),
                    owasp_wstg=meta.get("owasp"),
                    remediation=meta.get("remediation"),
                )
            )

    # Check for CSP weaknesses when present
    csp = lower_headers.get("content-security-policy", "")
    if csp:
        csp_issues = analyze_csp(csp, url)
        observations.extend(csp_issues)

    # Check for information leaking headers
    for header_name, meta in INFO_LEAK_HEADERS.items():
        value = lower_headers.get(header_name)
        if value:
            # Only flag if it contains version-like info
            has_version = any(c.isdigit() for c in value)
            if has_version:
                observations.append(
                    RawObservation(
                        title=meta["title"],
                        severity=meta["severity"],
                        url=url,
                        detail=f"`{header_name}: {value}` — reveals server technology and version.",
                        confidence=0.9,
                        evidence={"header": header_name, "value": value},
                        cwe=meta.get("cwe"),
                        remediation=meta.get("remediation"),
                    )
                )

    # Check deprecated X-XSS-Protection
    xss_protection = lower_headers.get("x-xss-protection")
    if xss_protection and xss_protection.strip() != "0":
        observations.append(
            RawObservation(
                title="Deprecated X-XSS-Protection Header",
                severity=Severity.INFO,
                url=url,
                detail=(
                    "X-XSS-Protection is deprecated and can introduce vulnerabilities in some browsers. "
                    "Use Content-Security-Policy instead."
                ),
                confidence=0.8,
                evidence={"header": "x-xss-protection", "value": xss_protection},
                remediation="Remove X-XSS-Protection or set to `0`. Rely on CSP for XSS mitigation.",
            )
        )

    # Check Cache-Control for sensitive pages
    cache_control = lower_headers.get("cache-control", "").lower()
    if not any(d in cache_control for d in ("no-store", "no-cache", "private")):
        observations.append(
            RawObservation(
                title="Missing Cache-Control Directives",
                severity=Severity.INFO,
                url=url,
                detail="Response may be cached by proxies. Sensitive pages should use `no-store`.",
                confidence=0.6,
                evidence={"cache-control": cache_control or "(absent)"},
                remediation="Add `Cache-Control: no-store` for pages with sensitive data.",
            )
        )

    # All good summary
    if not observations:
        observations.append(
            RawObservation(
                title="Security Headers Adequately Configured",
                severity=Severity.INFO,
                url=url,
                detail="All checked security headers are present and correctly configured.",
                confidence=1.0,
                evidence={"headers_checked": list(SECURITY_HEADERS.keys())},
            )
        )

    return observations


def analyze_csp(csp: str, url: str) -> list[RawObservation]:
    """Check a CSP value for common weaknesses."""
    issues: list[RawObservation] = []
    csp_lower = csp.lower()

    dangerous_directives = {
        "'unsafe-inline'": "Allows inline scripts/styles, defeating most XSS protections.",
        "'unsafe-eval'": "Allows eval() and similar APIs, enabling script injection.",
        "data:": "Allows data: URIs which can be used for XSS.",
        "*": "Wildcard source allows loading from any origin.",
    }

    for directive, explanation in dangerous_directives.items():
        if directive in csp_lower:
            issues.append(
                RawObservation(
                    title=f"CSP Contains '{directive}'",
                    severity=Severity.MEDIUM,
                    url=url,
                    detail=f"Content-Security-Policy contains `{directive}`. {explanation}",
                    confidence=0.9,
                    evidence={"csp": csp, "problematic_directive": directive},
                    cwe="CWE-79",
                    remediation=f"Remove `{directive}` from CSP. Use nonces or hashes for inline scripts.",
                )
            )

    return issues


# ── Scanner (I/O wrapper) ───────────────────────────────────────────


class SecurityHeadersScanner(Scanner):
    """Passive scanner that checks HTTP security headers."""

    id = "security-headers"
    name = "Security Headers Scanner"
    risk = Risk.PASSIVE
    requires_auth = False
    budget_units = 1

    async def scan(self, ctx: ScanContext) -> list[RawObservation]:
        """Send a single GET request and analyze response headers."""
        from safescope_core.policy.request import RequestDescriptor

        req = RequestDescriptor(method="GET", url=ctx.target_base_url)
        resp = await ctx.http(req)
        return analyze_headers(resp.headers, ctx.target_base_url)
