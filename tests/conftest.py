"""Shared fixtures for SafeScope tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from safescope_core.policy.engine import (
    AuthorizationSpec,
    Mode,
    Risk,
    ScannerSpec,
    ScanPolicyEngine,
    TargetSpec,
)
from safescope_core.policy.gate import KillSwitch, RequestGate, SSRFGuard
from safescope_core.policy.ledger import ResourceLedger

NOW = datetime.now(UTC)


# ── Factories ────────────────────────────────────────────────────────


def make_authz(**overrides) -> AuthorizationSpec:
    """Create an AuthorizationSpec with sensible defaults."""
    defaults = {
        "id": "AUTH-1",
        "target_id": "T1",
        "valid_from": NOW - timedelta(hours=1),
        "valid_until": NOW + timedelta(days=7),
        "allowed_origins": ("https://acme.com.br",),
        "excluded": (),
        "allowed_verbs": ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"),
        "allow_mutations": True,
        "active_testing": True,
        "max_requests": 50_000,
        "max_rps": 3.0,
        "max_concurrency": 4,
        "allow_write_paths": (),
    }
    defaults.update(overrides)
    return AuthorizationSpec(**defaults)


def make_target(
    mode: Mode = Mode.AGGRESSIVE,
    verified: bool = True,
) -> TargetSpec:
    """Create a TargetSpec with sensible defaults."""
    return TargetSpec(
        base_url="https://acme.com.br",
        root_domain="acme.com.br",
        verified=verified,
        mode=mode,
    )


# ── Scanner specs ────────────────────────────────────────────────────

PASSIVE_SCANNER = ScannerSpec(id="tls-check", name="TLS Scanner", risk=Risk.PASSIVE)
LIGHT_SCANNER = ScannerSpec(id="zap-baseline", name="ZAP Baseline", risk=Risk.LIGHT)
ACTIVE_SCANNER = ScannerSpec(id="sqli-probe", name="SQLi Probe", risk=Risk.ACTIVE, requires_auth=True)
DESTRUCTIVE_SCANNER = ScannerSpec(id="race-condition", name="Race Condition", risk=Risk.DESTRUCTIVE, destructive=True)


# ── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
def engine() -> ScanPolicyEngine:
    return ScanPolicyEngine()


@pytest.fixture
def kill_switch() -> KillSwitch:
    return KillSwitch()


@pytest.fixture
def ledger() -> ResourceLedger:
    return ResourceLedger(scan_id="SCAN-001")


@pytest.fixture
def ssrf_guard() -> SSRFGuard:
    return SSRFGuard(allow_private=False)


@pytest.fixture
def gate(kill_switch: KillSwitch, ledger: ResourceLedger, ssrf_guard: SSRFGuard) -> RequestGate:
    """Gate with a standard AGGRESSIVE snapshot."""
    authz = make_authz()
    engine = ScanPolicyEngine()
    snapshot = engine.freeze(make_target(), authz, [ACTIVE_SCANNER])
    return RequestGate(
        snapshot=snapshot,
        ledger=ledger,
        kill_switch=kill_switch,
        ssrf_guard=ssrf_guard,
    )
