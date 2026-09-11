"""Focused passive Content-Security-Policy analysis."""

from __future__ import annotations

from safescope_core.policy import RequestDescriptor

from .base import RawObservation, ScanContext, Scanner
from .headers import analyze_csp


class CspScanner(Scanner):
    id = "csp-policy"
    name = "Content-Security-Policy Scanner"

    async def scan(self, ctx: ScanContext) -> list[RawObservation]:
        response = await ctx.http(RequestDescriptor("GET", ctx.target_base_url))
        csp = response.headers.get("content-security-policy", "")
        return analyze_csp(csp, ctx.target_base_url) if csp else []
