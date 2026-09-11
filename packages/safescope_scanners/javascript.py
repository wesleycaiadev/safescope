"""Passive JavaScript and endpoint reference extraction."""

from __future__ import annotations

import re
from urllib.parse import urljoin

from safescope_core.policy import RequestDescriptor

from .base import RawObservation, ScanContext, Scanner, Severity

_SCRIPT_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)
_ENDPOINT_RE = re.compile(r"[\"'](/(?:api|v\d+|admin)[^\"'\s?#]*)", re.IGNORECASE)


def extract_javascript_references(html: bytes, base_url: str) -> dict[str, list[str]]:
    text = html.decode("utf-8", errors="ignore")
    scripts = sorted({urljoin(base_url, match) for match in _SCRIPT_RE.findall(text)})
    endpoints = sorted(set(_ENDPOINT_RE.findall(text)))
    return {"scripts": scripts, "endpoints": endpoints}


class JavaScriptScanner(Scanner):
    id = "javascript-references"
    name = "JavaScript Reference Scanner"

    async def scan(self, ctx: ScanContext) -> list[RawObservation]:
        response = await ctx.http(RequestDescriptor("GET", ctx.target_base_url))
        references = extract_javascript_references(response.body, ctx.target_base_url)
        if not references["scripts"] and not references["endpoints"]:
            return []
        return [
            RawObservation(
                title="Public JavaScript References",
                severity=Severity.INFO,
                url=ctx.target_base_url,
                detail="Public frontend assets reference scripts or application endpoints.",
                confidence=1.0,
                evidence=references,
                remediation="Review published routes and ensure sensitive functionality requires authorization.",
            )
        ]
