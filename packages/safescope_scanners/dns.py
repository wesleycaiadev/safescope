"""Passive analysis of DNS data gathered by a trusted resolver adapter."""

from __future__ import annotations

from .base import RawObservation, ScanContext, Scanner, Severity


def analyze_dns_records(records: dict[str, list[str]], url: str) -> list[RawObservation]:
    """Identify directly observable DNS hygiene signals; never performs takeover probes."""
    observations: list[RawObservation] = []
    if not records.get("CAA"):
        observations.append(
            RawObservation(
                title="No CAA Record Observed",
                severity=Severity.INFO,
                url=url,
                detail="No CAA record was supplied by the passive DNS resolver.",
                confidence=0.7,
                evidence={"record_type": "CAA", "present": False},
                remediation="Consider CAA records to restrict certificate authorities allowed to issue certificates.",
            )
        )
    return observations


class DnsScanner(Scanner):
    id = "dns-hygiene"
    name = "DNS Hygiene Scanner"

    async def scan(self, ctx: ScanContext) -> list[RawObservation]:
        records = ctx.metadata.get("dns_records", {})
        if not isinstance(records, dict):
            return []
        normalized = {str(kind).upper(): [str(value) for value in values] for kind, values in records.items()}
        return analyze_dns_records(normalized, ctx.target_base_url)
