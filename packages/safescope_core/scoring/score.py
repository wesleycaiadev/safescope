"""Transparent conservative Security Score calculation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable


class Confidence(StrEnum):
    POTENTIAL = "POTENTIAL"
    LIKELY = "LIKELY"
    CONFIRMED = "CONFIRMED"


_SEVERITY_DEDUCTION = {"CRITICAL": 35, "HIGH": 20, "MEDIUM": 10, "LOW": 4, "INFO": 0}
_CONFIDENCE_FACTOR = {Confidence.POTENTIAL: 0.4, Confidence.LIKELY: 0.7, Confidence.CONFIRMED: 1.0}


@dataclass(frozen=True)
class ScoreInput:
    severity: str
    confidence: Confidence = Confidence.POTENTIAL
    externally_exposed: bool = True
    authentication_required: bool = False


@dataclass(frozen=True)
class SecurityScore:
    value: int
    deductions: int


def calculate_security_score(findings: Iterable[ScoreInput]) -> SecurityScore:
    """Return 0-100 with capped, confidence-weighted deductions.

    Scores describe observed risk, not proof that an issue is exploitable.
    """
    deductions = 0.0
    for finding in findings:
        base = _SEVERITY_DEDUCTION.get(finding.severity.upper(), 0)
        exposure_factor = 1.0 if finding.externally_exposed else 0.6
        auth_factor = 0.7 if finding.authentication_required else 1.0
        deductions += base * _CONFIDENCE_FACTOR[finding.confidence] * exposure_factor * auth_factor
    rounded = min(100, round(deductions))
    return SecurityScore(value=100 - rounded, deductions=rounded)
