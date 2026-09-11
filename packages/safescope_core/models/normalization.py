"""Conservative conversion of raw observations into deduplicated findings."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable

    from safescope_scanners.base import RawObservation

_SECRET_KEY = re.compile(r"(?i)(authorization|cookie|token|password|api[_-]?key|secret)")


@dataclass(frozen=True)
class NormalizedFinding:
    title: str
    severity: str
    confidence: float
    url: str
    description: str
    evidence: dict[str, Any]
    evidence_hash: str
    remediation: str | None


def normalize_observations(observations: Iterable[RawObservation]) -> list[NormalizedFinding]:
    """Redact evidence and retain one highest-confidence observation per finding key."""
    normalized: dict[tuple[str, str], NormalizedFinding] = {}
    for observation in observations:
        evidence = redact_evidence(observation.evidence)
        digest = hashlib.sha256(_canonical_json(evidence).encode("utf-8")).hexdigest()
        candidate = NormalizedFinding(
            title=observation.title,
            severity=observation.severity.value,
            confidence=observation.confidence,
            url=observation.url,
            description=observation.detail,
            evidence=evidence,
            evidence_hash=digest,
            remediation=observation.remediation,
        )
        key = (candidate.title, candidate.url)
        previous = normalized.get(key)
        if previous is None or candidate.confidence > previous.confidence:
            normalized[key] = candidate
    return list(normalized.values())


def redact_evidence(value: Any) -> Any:
    """Remove sensitive values before an observation can reach persistence."""
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if _SECRET_KEY.search(str(key)) else redact_evidence(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_evidence(item) for item in value]
    return value


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
