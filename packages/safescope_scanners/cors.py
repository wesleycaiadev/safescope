"""Passive CORS policy analysis."""

from __future__ import annotations

from safescope_core.policy import RequestDescriptor

from .base import RawObservation, ScanContext, Scanner, Severity


def analyze_cors(headers: dict[str, str], url: str) -> list[RawObservation]:
    """Report only directly observable unsafe CORS combinations."""
    origin = headers.get("access-control-allow-origin", "")
    credentials = headers.get("access-control-allow-credentials", "").lower() == "true"
    observations: list[RawObservation] = []
    if origin == "*" and credentials:
        observations.append(
            RawObservation(
                title="CORS Wildcard Origin with Credentials",
                severity=Severity.HIGH,
                url=url,
                detail=(
                    "The response allows any origin and credentials. Browser behavior may vary, "
                    "but this policy is unsafe."
                ),
                confidence=0.9,
                evidence={"allow_origin": origin, "allow_credentials": True},
                cwe="CWE-942",
                remediation="Use an explicit allowlist of trusted origins and avoid credentialed wildcard CORS.",
            )
        )
    elif origin == "*":
        observations.append(
            RawObservation(
                title="CORS Allows Any Origin",
                severity=Severity.LOW,
                url=url,
                detail="The response permits cross-origin reads from any website.",
                confidence=1.0,
                evidence={"allow_origin": origin},
                cwe="CWE-942",
                remediation="Restrict Access-Control-Allow-Origin to origins that require access.",
            )
        )
    return observations


class CorsScanner(Scanner):
    id = "cors-policy"
    name = "CORS Policy Scanner"

    async def scan(self, ctx: ScanContext) -> list[RawObservation]:
        response = await ctx.http(RequestDescriptor("GET", ctx.target_base_url))
        return analyze_cors(response.headers, ctx.target_base_url)
