"""ScanPolicyEngine — the single authority on what can be done to a target.

This module is pure domain logic. It does NOT import httpx, FastAPI,
SQLAlchemy, or any I/O library. Decisions are made on data, not connections.

Key concepts:
- Mode: PASSIVE | GUIDED | AGGRESSIVE
- Risk: PASSIVE | LIGHT | ACTIVE | DESTRUCTIVE
- MAX_RISK: maps Mode → maximum Risk allowed
- Decision: allow/deny with typed reason
- freeze(): produces an immutable JSON snapshot of the *policy* (not context).
  KillSwitch, ResourceLedger, and budget counter are mutable references
  that live outside the snapshot.
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit


class Mode(enum.StrEnum):
    """Scan mode — determines the ceiling of what scanners may do."""

    PASSIVE = "PASSIVE"
    GUIDED = "GUIDED"
    AGGRESSIVE = "AGGRESSIVE"


class Risk(enum.StrEnum):
    """Scanner risk level — how intrusive its probes are."""

    PASSIVE = "PASSIVE"
    LIGHT = "LIGHT"
    ACTIVE = "ACTIVE"
    DESTRUCTIVE = "DESTRUCTIVE"


# Ordered from least to most intrusive
_RISK_ORDER: list[Risk] = [Risk.PASSIVE, Risk.LIGHT, Risk.ACTIVE, Risk.DESTRUCTIVE]

# Maximum scanner risk allowed per mode
MAX_RISK: dict[Mode, Risk] = {
    Mode.PASSIVE: Risk.PASSIVE,
    Mode.GUIDED: Risk.LIGHT,
    Mode.AGGRESSIVE: Risk.DESTRUCTIVE,
}

WRITE_VERBS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class Why(enum.StrEnum):
    """Typed reason for every policy decision. Each value maps to an audit log entry."""

    OK = "OK"
    TARGET_UNVERIFIED = "TARGET_UNVERIFIED"
    NO_AUTHORIZATION = "NO_AUTHORIZATION"
    AUTHORIZATION_EXPIRED = "AUTHORIZATION_EXPIRED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    EXCLUDED_PATH = "EXCLUDED_PATH"
    VERB_NOT_ALLOWED = "VERB_NOT_ALLOWED"
    MUTATION_FORBIDDEN = "MUTATION_FORBIDDEN"
    NOT_IN_LEDGER = "NOT_IN_LEDGER"
    PATH_NOT_ALLOWLISTED = "PATH_NOT_ALLOWLISTED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    RATE_CEILING = "RATE_CEILING"
    KILL_SWITCH_ENGAGED = "KILL_SWITCH_ENGAGED"
    SCANNER_RISK_TOO_HIGH = "SCANNER_RISK_TOO_HIGH"
    TIME_WINDOW_CLOSED = "TIME_WINDOW_CLOSED"
    SSRF_BLOCKED = "SSRF_BLOCKED"
    SCHEME_NOT_ALLOWED = "SCHEME_NOT_ALLOWED"


@dataclass(frozen=True)
class Decision:
    """Result of a policy evaluation. Immutable."""

    allow: bool
    why: Why
    detail: str = ""

    @staticmethod
    def ok() -> Decision:
        return Decision(allow=True, why=Why.OK)

    @staticmethod
    def deny(why: Why, detail: str = "") -> Decision:
        return Decision(allow=False, why=why, detail=detail)


@dataclass(frozen=True)
class ScannerSpec:
    """Descriptor of a scanner plugin's capabilities. No I/O, just metadata."""

    id: str
    name: str = ""
    risk: Risk = Risk.PASSIVE
    requires_auth: bool = False
    destructive: bool = False
    budget_units: int = 1


@dataclass(frozen=True)
class TargetSpec:
    """Descriptor of a scan target. Pure data, no ORM."""

    base_url: str
    root_domain: str
    verified: bool
    mode: Mode


@dataclass(frozen=True)
class AuthorizationSpec:
    """Descriptor of a signed authorization (ROE). Pure data, no ORM.

    Immutable snapshot of what the authorization allows.
    """

    id: str
    target_id: str
    valid_from: datetime
    valid_until: datetime
    allowed_origins: tuple[str, ...]
    excluded: tuple[str, ...] = ()
    allowed_verbs: tuple[str, ...] = ("GET", "HEAD")
    allow_mutations: bool = False
    active_testing: bool = True
    max_requests: int = 50_000
    max_rps: float = 3.0
    max_concurrency: int = 4
    allow_write_paths: tuple[str, ...] = ()

    def is_live(self, now: datetime | None = None) -> bool:
        """True if the authorization is currently valid (not expired)."""
        ref = now or datetime.now(UTC)
        return self.valid_from <= ref <= self.valid_until


class ScanPolicyEngine:
    """The single place in the system that decides what can be done to a target.

    Usage:
        engine = ScanPolicyEngine()

        # Check if a scanner can run against a target
        decision = engine.can_execute(scanner, target, authz)

        # Create an immutable policy snapshot for a scan run
        snapshot = engine.freeze(target, authz, scanners)
    """

    def can_execute(
        self,
        scanner: ScannerSpec,
        target: TargetSpec,
        authz: AuthorizationSpec | None,
    ) -> Decision:
        """Evaluate whether a scanner is allowed to run against a target.

        This is the only method that decides. No shortcut exists.
        """
        return self._evaluate_risk(scanner, target, authz)

    def freeze(
        self,
        target: TargetSpec,
        authz: AuthorizationSpec | None,
        scanners: list[ScannerSpec],
    ) -> dict[str, Any]:
        """Create an immutable JSON snapshot of the POLICY for this scan.

        The snapshot captures what is ALLOWED — it is frozen at scan start
        and does NOT change mid-scan. Mutable state (kill switch, budget
        counter, ledger) lives as references outside this snapshot.

        If the authorization changes mid-scan, the scan does NOT adapt.
        A new ScanRun is required.
        """
        allowed_scanners = [s.id for s in scanners if self._evaluate_risk(s, target, authz).allow]

        snap: dict[str, Any] = {
            "version": 1,
            "mode": target.mode.value,
            "target": target.base_url,
            "root_domain": target.root_domain,
            "risk_ceiling": MAX_RISK[target.mode].value,
            "authorization_id": authz.id if authz else None,
            "verbs": list(authz.allowed_verbs) if authz else ["GET", "HEAD"],
            "allow_mutations": bool(authz and authz.allow_mutations),
            "active_testing": bool(authz and authz.active_testing),
            "max_requests": authz.max_requests if authz else 300,
            "max_rps": authz.max_rps if authz else 1.0,
            "max_concurrency": authz.max_concurrency if authz else 1,
            "allowed_origins": list(authz.allowed_origins) if authz else [target.base_url],
            "excluded": list(authz.excluded) if authz else [],
            "allow_write_paths": list(authz.allow_write_paths) if authz else [],
            "scanners_allowed": allowed_scanners,
        }
        # Round-trip through JSON to guarantee serializability and immutability
        return json.loads(json.dumps(snap))

    def _evaluate_risk(
        self,
        scanner: ScannerSpec,
        target: TargetSpec,
        authz: AuthorizationSpec | None,
    ) -> Decision:
        """Core evaluation logic. Pure function on data."""
        # Step 1: Is the scanner's risk level compatible with the mode?
        scanner_risk_idx = _RISK_ORDER.index(scanner.risk)
        mode_ceiling_idx = _RISK_ORDER.index(MAX_RISK[target.mode])

        if scanner_risk_idx > mode_ceiling_idx:
            return Decision.deny(
                Why.SCANNER_RISK_TOO_HIGH,
                f"scanner '{scanner.id}' risk={scanner.risk.value} exceeds "
                f"mode={target.mode.value} ceiling={MAX_RISK[target.mode].value}",
            )

        # Step 2: PASSIVE scanners on any target are always allowed
        if scanner.risk is Risk.PASSIVE:
            return Decision.ok()

        # Step 3: Non-passive scanners require a verified target
        if not target.verified:
            return Decision.deny(Why.TARGET_UNVERIFIED)

        # Step 4: Non-passive scanners require authorization
        if authz is None:
            return Decision.deny(Why.NO_AUTHORIZATION)

        # Step 5: Authorization must be live
        if not authz.is_live():
            return Decision.deny(Why.AUTHORIZATION_EXPIRED)

        # Step 6: The target itself must be an explicitly allowed origin.
        # RequestGate enforces every individual URL later; this prevents a
        # non-passive scanner from even starting on a target outside the ROE.
        target_origin = _origin(target.base_url)
        if target_origin not in authz.allowed_origins:
            return Decision.deny(
                Why.OUT_OF_SCOPE,
                f"target origin '{target_origin}' not in authorization scope",
            )

        # Step 7: ACTIVE scanners require active_testing flag
        if scanner.risk in (Risk.ACTIVE, Risk.DESTRUCTIVE) and not authz.active_testing:
            return Decision.deny(
                Why.SCANNER_RISK_TOO_HIGH,
                f"scanner '{scanner.id}' requires active_testing=true",
            )

        # Step 8: A destructive scanner cannot start unless mutations have
        # been expressly granted. RequestGate performs the stricter per-URL
        # ledger and snapshot checks before each write.
        if (scanner.destructive or scanner.risk is Risk.DESTRUCTIVE) and not authz.allow_mutations:
            return Decision.deny(
                Why.MUTATION_FORBIDDEN,
                f"scanner '{scanner.id}' requires allow_mutations=true",
            )

        return Decision.ok()


def _origin(url: str) -> str:
    """Return a normalized origin for a policy comparison."""
    parsed = urlsplit(url)
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
