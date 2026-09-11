"""Scanner base classes — plugin interface for SafeScope.

Scanners do NOT know the mode (PASSIVE/GUIDED/AGGRESSIVE).
They don't decide permissions. They scan, and report what they find.
The ScanPolicyEngine decides everything before the scanner runs.
"""

from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from safescope_core.policy.engine import Risk, ScannerSpec


class Severity(enum.StrEnum):
    """Finding severity level."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class RawObservation:
    """A single observation from a scanner. Not yet a Finding — needs dedup and triage."""

    title: str
    severity: Severity
    url: str
    detail: str
    confidence: float  # 0.0-1.0
    evidence: dict[str, Any] = field(default_factory=dict)
    cwe: str | None = None
    owasp_wstg: str | None = None
    remediation: str | None = None
    references: list[str] = field(default_factory=list)


@dataclass
class ScanContext:
    """Context provided to scanners. The scanner does not configure this.

    - target_base_url: the URL to scan
    - http: a callable that accepts RequestDescriptor and returns ResponseData
            (provided by GatedTransport — scanner doesn't know about gates)
    - ledger: ResourceLedger for recording created resources
    - metadata: optional target metadata (technologies, etc.)
    """

    target_base_url: str
    http: Any  # Callable[[RequestDescriptor], Awaitable[ResponseData]]
    ledger: Any  # ResourceLedger
    tls: Any | None = None  # Callable[[str, int], Awaitable[TLSProbe]]
    metadata: dict[str, Any] = field(default_factory=dict)


class Scanner(ABC):
    """Base class for all scanner plugins.

    Subclasses must define class attributes and implement scan().
    The scanner NEVER decides if it should run — that's the engine's job.
    """

    id: str = ""
    name: str = ""
    risk: Risk = Risk.PASSIVE
    requires_auth: bool = False
    destructive: bool = False
    budget_units: int = 1

    @abstractmethod
    async def scan(self, ctx: ScanContext) -> list[RawObservation]:
        """Execute the scan and return observations.

        The scanner receives an http callable that is already gated.
        It does not need to worry about scope, budget, or permissions.
        """
        ...

    def to_spec(self) -> ScannerSpec:
        """Convert to ScannerSpec for policy evaluation."""
        return ScannerSpec(
            id=self.id,
            name=self.name,
            risk=self.risk,
            requires_auth=self.requires_auth,
            destructive=self.destructive,
            budget_units=self.budget_units,
        )
