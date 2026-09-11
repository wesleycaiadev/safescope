"""Passive retrieval of well-known public security metadata."""

from __future__ import annotations

from urllib.parse import urlsplit

from safescope_core.policy import RequestDescriptor

from .base import RawObservation, ScanContext, Scanner, Severity

_PATHS = ("/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt")


def public_metadata_url(base_url: str, path: str) -> str:
    parsed = urlsplit(base_url)
    return f"{parsed.scheme}://{parsed.netloc}{path}"


class ExposedFilesScanner(Scanner):
    id = "public-metadata"
    name = "Public Metadata Scanner"

    async def scan(self, ctx: ScanContext) -> list[RawObservation]:
        observations: list[RawObservation] = []
        security_txt_found = False
        for path in _PATHS:
            url = public_metadata_url(ctx.target_base_url, path)
            response = await ctx.http(RequestDescriptor("GET", url))
            if response.status_code >= 400:
                continue
            if path.endswith("security.txt"):
                security_txt_found = True
            observations.append(
                RawObservation(
                    title=f"Public File Available: {path}",
                    severity=Severity.INFO,
                    url=url,
                    detail=f"The public file {path} responded with HTTP {response.status_code}.",
                    confidence=1.0,
                    evidence={"path": path, "status_code": response.status_code},
                )
            )
        if not security_txt_found:
            observations.append(
                RawObservation(
                    title="No security.txt Published",
                    severity=Severity.INFO,
                    url=ctx.target_base_url,
                    detail="No security.txt was observed at standard public locations.",
                    confidence=0.9,
                    evidence={"paths_checked": ["/security.txt", "/.well-known/security.txt"]},
                    remediation="Publish security.txt with a monitored contact channel for vulnerability reports.",
                )
            )
        return observations
