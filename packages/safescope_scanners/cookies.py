"""Passive analysis of cookie attributes observed in HTTP responses."""

from __future__ import annotations

from safescope_core.policy import RequestDescriptor

from .base import RawObservation, ScanContext, Scanner, Severity


def analyze_cookies(set_cookie: str, url: str) -> list[RawObservation]:
    """Find missing browser security attributes without sending extra requests."""
    observations: list[RawObservation] = []
    for cookie in _split_cookies(set_cookie):
        name, _, attributes = cookie.partition(";")
        lowered = attributes.lower()
        cookie_name = name.split("=", 1)[0].strip() or "unnamed cookie"
        for attribute, severity, remediation in (
            ("secure", Severity.MEDIUM, "Add the Secure attribute to cookies sent over HTTPS."),
            ("httponly", Severity.MEDIUM, "Add HttpOnly to cookies that do not require JavaScript access."),
            ("samesite", Severity.LOW, "Set SameSite=Lax or SameSite=Strict as appropriate."),
        ):
            if attribute not in lowered:
                observations.append(
                    RawObservation(
                        title=f"Cookie '{cookie_name}' Missing {attribute.title()}",
                        severity=severity,
                        url=url,
                        detail=f"Observed cookie '{cookie_name}' does not declare the {attribute} attribute.",
                        confidence=0.9,
                        evidence={"cookie_name": cookie_name, "missing": attribute},
                        cwe="CWE-614" if attribute == "secure" else "CWE-1004",
                        remediation=remediation,
                    )
                )
    return observations


def _split_cookies(value: str) -> list[str]:
    """Split the common combined Set-Cookie representation without breaking Expires dates."""
    if not value:
        return []
    return [part.strip() for part in value.replace(", ", ",").split(",") if "=" in part]


class CookieScanner(Scanner):
    id = "cookie-flags"
    name = "Cookie Flags Scanner"

    async def scan(self, ctx: ScanContext) -> list[RawObservation]:
        response = await ctx.http(RequestDescriptor("GET", ctx.target_base_url))
        return analyze_cookies(response.headers.get("set-cookie", ""), ctx.target_base_url)
