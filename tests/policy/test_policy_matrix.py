"""Policy matrix tests — 10 cases that prove the engine contains aggression.

These tests block merge. If any fails, the platform is unsafe to run.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from safescope_core.policy.engine import (
    Mode,
    Risk,
    ScannerSpec,
    ScanPolicyEngine,
    Why,
)

from ..conftest import (
    ACTIVE_SCANNER,
    DESTRUCTIVE_SCANNER,
    NOW,
    PASSIVE_SCANNER,
    make_authz,
    make_target,
)

engine = ScanPolicyEngine()


@pytest.mark.parametrize(
    ("scanner", "target", "authz", "expected_why"),
    [
        # Case 1: PASSIVE scanner on unverified target → ALLOW
        pytest.param(
            PASSIVE_SCANNER,
            make_target(verified=False),
            None,
            Why.OK,
            id="passive-unverified-allow",
        ),
        # Case 2: ACTIVE scanner on unverified target → DENY
        pytest.param(
            ACTIVE_SCANNER,
            make_target(verified=False),
            None,
            Why.TARGET_UNVERIFIED,
            id="active-unverified-deny",
        ),
        # Case 3: ACTIVE scanner on verified target, no authorization → DENY
        pytest.param(
            ACTIVE_SCANNER,
            make_target(),
            None,
            Why.NO_AUTHORIZATION,
            id="active-no-authz-deny",
        ),
        # Case 4: ACTIVE scanner, authorization expired → DENY
        pytest.param(
            ACTIVE_SCANNER,
            make_target(),
            make_authz(valid_until=NOW - timedelta(hours=1)),
            Why.AUTHORIZATION_EXPIRED,
            id="active-expired-deny",
        ),
        # Case 5: ACTIVE scanner on GUIDED mode → risk too high (ACTIVE > LIGHT ceiling)
        pytest.param(
            ACTIVE_SCANNER,
            make_target(Mode.GUIDED),
            make_authz(),
            Why.SCANNER_RISK_TOO_HIGH,
            id="active-guided-risk-deny",
        ),
        # Case 6: ACTIVE scanner, valid authz, in scope → ALLOW
        pytest.param(
            ACTIVE_SCANNER,
            make_target(Mode.AGGRESSIVE),
            make_authz(),
            Why.OK,
            id="active-aggressive-valid-allow",
        ),
        # Case 7: DESTRUCTIVE scanner, valid authz but allow_mutations=False → DENY
        # (DESTRUCTIVE risk > PASSIVE ceiling in non-AGGRESSIVE mode, but here
        #  AGGRESSIVE mode allows DESTRUCTIVE — the deny comes from active_testing=False)
        pytest.param(
            DESTRUCTIVE_SCANNER,
            make_target(Mode.AGGRESSIVE),
            make_authz(allow_mutations=False),
            Why.MUTATION_FORBIDDEN,
            id="destructive-without-mutations-deny",
        ),
        # Case 8: DESTRUCTIVE scanner + AGGRESSIVE + valid authz → ALLOW
        pytest.param(
            DESTRUCTIVE_SCANNER,
            make_target(Mode.AGGRESSIVE),
            make_authz(),
            Why.OK,
            id="destructive-aggressive-valid-allow",
        ),
        # Case 9: ACTIVE scanner, authz valid but active_testing=False → DENY
        pytest.param(
            ACTIVE_SCANNER,
            make_target(Mode.AGGRESSIVE),
            make_authz(active_testing=False),
            Why.SCANNER_RISK_TOO_HIGH,
            id="active-no-active-testing-deny",
        ),
        # Case 10: LIGHT scanner on GUIDED mode with valid authz → ALLOW
        pytest.param(
            ScannerSpec(id="zap-baseline", risk=Risk.LIGHT),
            make_target(Mode.GUIDED),
            make_authz(),
            Why.OK,
            id="light-guided-valid-allow",
        ),
        # Non-passive scans cannot start on an origin absent from the ROE.
        pytest.param(
            ACTIVE_SCANNER,
            make_target(Mode.AGGRESSIVE),
            make_authz(allowed_origins=("https://api.acme.com.br",)),
            Why.OUT_OF_SCOPE,
            id="active-outside-authorization-scope-deny",
        ),
    ],
)
def test_policy_matrix(
    scanner: ScannerSpec,
    target,
    authz,
    expected_why: Why,
) -> None:
    """The 10-case policy matrix. If any case fails, the gate is broken."""
    decision = engine.can_execute(scanner, target, authz)
    assert decision.why is expected_why, f"Expected {expected_why.value}, got {decision.why.value}: {decision.detail}"
    if expected_why is Why.OK:
        assert decision.allow is True
    else:
        assert decision.allow is False


class TestFreeze:
    """Snapshot tests — the frozen policy must be correct and serializable."""

    def test_freeze_captures_allowed_scanners(self) -> None:
        target = make_target()
        authz = make_authz()
        scanners = [PASSIVE_SCANNER, ACTIVE_SCANNER, DESTRUCTIVE_SCANNER]
        snap = engine.freeze(target, authz, scanners)

        assert PASSIVE_SCANNER.id in snap["scanners_allowed"]
        assert ACTIVE_SCANNER.id in snap["scanners_allowed"]
        assert DESTRUCTIVE_SCANNER.id in snap["scanners_allowed"]

    def test_freeze_excludes_high_risk_in_passive_mode(self) -> None:
        target = make_target(Mode.PASSIVE)
        scanners = [PASSIVE_SCANNER, ACTIVE_SCANNER, DESTRUCTIVE_SCANNER]
        snap = engine.freeze(target, None, scanners)

        assert PASSIVE_SCANNER.id in snap["scanners_allowed"]
        assert ACTIVE_SCANNER.id not in snap["scanners_allowed"]
        assert DESTRUCTIVE_SCANNER.id not in snap["scanners_allowed"]

    def test_freeze_is_json_serializable(self) -> None:
        import json

        target = make_target()
        authz = make_authz()
        snap = engine.freeze(target, authz, [PASSIVE_SCANNER])
        # Round-trip must work without exception
        assert json.loads(json.dumps(snap)) == snap

    def test_freeze_without_authz_defaults_to_passive(self) -> None:
        target = make_target(Mode.PASSIVE)
        snap = engine.freeze(target, None, [PASSIVE_SCANNER])

        assert snap["verbs"] == ["GET", "HEAD"]
        assert snap["allow_mutations"] is False
        assert snap["max_requests"] == 300
        assert snap["authorization_id"] is None
        assert snap["valid_from"] is None
        assert snap["valid_until"] is None
        assert snap["allowed_content_types"] == []
        assert snap["allowed_payloads"] == []


class TestAuthorizationLiveness:
    """Authorization window edge cases."""

    def test_authz_before_valid_from(self) -> None:
        authz = make_authz(valid_from=NOW + timedelta(hours=1))
        assert not authz.is_live()

    def test_authz_exactly_at_boundaries(self) -> None:
        authz = make_authz(valid_from=NOW, valid_until=NOW)
        assert authz.is_live(now=NOW)

    def test_authz_after_valid_until(self) -> None:
        authz = make_authz(valid_until=NOW - timedelta(seconds=1))
        assert not authz.is_live()
