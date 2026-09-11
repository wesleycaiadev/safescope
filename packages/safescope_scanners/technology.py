"""Non-invasive technology fingerprinting from a normal page response."""

from __future__ import annotations

from safescope_core.policy import RequestDescriptor

from .base import RawObservation, ScanContext, Scanner, Severity

_SIGNATURES = {
    "wordpress": "WordPress",
    "wp-content": "WordPress",
    "/_next": "Next.js",
    "laravel_session": "Laravel",
    "django": "Django",
}


def detect_technologies(headers: dict[str, str], body: bytes) -> set[str]:
    haystack = " ".join(headers.values()).lower() + " " + body.decode("utf-8", errors="ignore").lower()
    return {name for marker, name in _SIGNATURES.items() if marker in haystack}


class TechnologyScanner(Scanner):
    id = "technology-fingerprint"
    name = "Technology Fingerprint Scanner"

    async def scan(self, ctx: ScanContext) -> list[RawObservation]:
        response = await ctx.http(RequestDescriptor("GET", ctx.target_base_url))
        technologies = sorted(detect_technologies(response.headers, response.body))
        if not technologies:
            return []
        return [
            RawObservation(
                title="Public Technology Fingerprint",
                severity=Severity.INFO,
                url=ctx.target_base_url,
                detail=f"Public response indicates: {', '.join(technologies)}.",
                confidence=0.7,
                evidence={"technologies": technologies},
                remediation="Keep identified components patched and avoid unnecessary version disclosure.",
            )
        ]
