"""RequestGate tests — scope, budget, kill switch, mutations, SSRF."""

from __future__ import annotations

from safescope_core.policy.engine import Why
from safescope_core.policy.gate import KillSwitch, RequestGate, SSRFGuard
from safescope_core.policy.request import RequestDescriptor

from ..conftest import ACTIVE_SCANNER, ResourceLedger, ScanPolicyEngine, make_authz, make_target


def _make_gate(
    *,
    kill_switch: KillSwitch | None = None,
    ledger: ResourceLedger | None = None,
    ssrf_guard: SSRFGuard | None = None,
    snapshot_overrides: dict | None = None,
) -> RequestGate:
    """Helper to build a gate with optional overrides."""
    ks = kill_switch or KillSwitch()
    lg = ledger or ResourceLedger("SCAN-001")
    sg = ssrf_guard or SSRFGuard(allow_private=False)
    engine = ScanPolicyEngine()
    target = make_target()
    authz = make_authz()
    snap = engine.freeze(target, authz, [ACTIVE_SCANNER])
    if snapshot_overrides:
        snap.update(snapshot_overrides)
    return RequestGate(snapshot=snap, ledger=lg, kill_switch=ks, ssrf_guard=sg)


class TestScopeEnforcement:
    """Gate blocks requests outside the authorized scope."""

    def test_allowed_origin_passes(self) -> None:
        gate = _make_gate()
        req = RequestDescriptor(method="GET", url="https://acme.com.br/api/users")
        decision = gate.evaluate(req)
        assert decision.allow is True

    def test_wrong_origin_denied(self) -> None:
        gate = _make_gate()
        req = RequestDescriptor(method="GET", url="https://evil.com/steal")
        decision = gate.evaluate(req)
        assert decision.allow is False
        assert decision.why is Why.OUT_OF_SCOPE

    def test_excluded_path_denied(self) -> None:
        gate = _make_gate(snapshot_overrides={"excluded": ["https://acme.com.br/checkout*"]})
        req = RequestDescriptor(method="GET", url="https://acme.com.br/checkout/pay")
        decision = gate.evaluate(req)
        assert decision.allow is False
        assert decision.why is Why.EXCLUDED_PATH

    def test_verb_not_allowed(self) -> None:
        gate = _make_gate(snapshot_overrides={"verbs": ["GET", "HEAD"]})
        req = RequestDescriptor(method="POST", url="https://acme.com.br/api/data")
        decision = gate.evaluate(req)
        assert decision.allow is False
        assert decision.why is Why.VERB_NOT_ALLOWED


class TestBudget:
    """Gate enforces request budget."""

    def test_budget_exhausted(self) -> None:
        gate = _make_gate(snapshot_overrides={"max_requests": 2})
        req = RequestDescriptor(method="GET", url="https://acme.com.br/1")

        assert gate.evaluate(req).allow is True  # 1st
        assert gate.evaluate(req).allow is True  # 2nd
        decision = gate.evaluate(req)  # 3rd — over budget
        assert decision.allow is False
        assert decision.why is Why.BUDGET_EXHAUSTED

    def test_budget_remaining_tracks(self) -> None:
        gate = _make_gate(snapshot_overrides={"max_requests": 5})
        assert gate.budget_remaining == 5
        gate.evaluate(RequestDescriptor(method="GET", url="https://acme.com.br/"))
        assert gate.budget_remaining == 4


class TestKillSwitch:
    """Gate halts everything when kill switch is engaged."""

    def test_kill_switch_blocks(self) -> None:
        ks = KillSwitch()
        gate = _make_gate(kill_switch=ks)
        ks.engage(reason="emergency", actor="wesley")

        req = RequestDescriptor(method="GET", url="https://acme.com.br/safe")
        decision = gate.evaluate(req)
        assert decision.allow is False
        assert decision.why is Why.KILL_SWITCH_ENGAGED

    def test_kill_switch_disengage_resumes(self) -> None:
        ks = KillSwitch()
        gate = _make_gate(kill_switch=ks)

        ks.engage(reason="test", actor="ci")
        assert gate.evaluate(RequestDescriptor(method="GET", url="https://acme.com.br/")).allow is False

        ks.disengage(actor="ci")
        assert gate.evaluate(RequestDescriptor(method="GET", url="https://acme.com.br/")).allow is True


class TestMutationControl:
    """Write operations require ledger or allow_write_paths."""

    def test_write_without_ledger_denied(self) -> None:
        gate = _make_gate()
        req = RequestDescriptor(method="DELETE", url="https://acme.com.br/api/orders/999")
        decision = gate.evaluate(req)
        assert decision.allow is False
        assert decision.why is Why.NOT_IN_LEDGER

    def test_write_on_ledgered_resource_passes(self) -> None:
        ledger = ResourceLedger("SCAN-001")
        gate = _make_gate(ledger=ledger)

        # First, register a created resource
        create_url = "https://acme.com.br/api/orders"
        ledger.record_create(create_url, "POST", "__SPROOF_001")

        req = RequestDescriptor(method="POST", url=create_url)
        decision = gate.evaluate(req)
        assert decision.allow is True

    def test_write_on_allow_write_path_with_snapshot_passes(self) -> None:
        ledger = ResourceLedger("SCAN-001")
        gate = _make_gate(
            ledger=ledger,
            snapshot_overrides={"allow_write_paths": ["https://acme.com.br/api/users/me"]},
        )
        url = "https://acme.com.br/api/users/me"
        # Must snapshot before mutation (case 9)
        ledger.snapshot(url, {"role": "user"})

        req = RequestDescriptor(method="PUT", url=url)
        decision = gate.evaluate(req)
        assert decision.allow is True

    def test_write_on_allow_write_path_without_snapshot_denied(self) -> None:
        """Case 9: mutating existing resource without snapshot() → DENY."""
        ledger = ResourceLedger("SCAN-001")
        gate = _make_gate(
            ledger=ledger,
            snapshot_overrides={"allow_write_paths": ["https://acme.com.br/api/users/me"]},
        )
        url = "https://acme.com.br/api/users/me"
        # No snapshot — must be denied

        req = RequestDescriptor(method="PUT", url=url)
        decision = gate.evaluate(req)
        assert decision.allow is False
        assert decision.why is Why.NOT_IN_LEDGER

    def test_mutations_denied_when_not_allowed(self) -> None:
        gate = _make_gate(snapshot_overrides={"allow_mutations": False})
        req = RequestDescriptor(method="POST", url="https://acme.com.br/api/data")
        decision = gate.evaluate(req)
        assert decision.allow is False
        assert decision.why is Why.MUTATION_FORBIDDEN

    def test_same_url_ledgered_twice_reuses_entry(self) -> None:
        """Case 10: same URL already ledgered → reuse, don't duplicate."""
        ledger = ResourceLedger("SCAN-001")
        url = "https://acme.com.br/api/test"
        ledger.record_create(url, "POST", "__SPROOF_001")
        ledger.record_create(url, "POST", "__SPROOF_002")  # second create, same URL
        assert ledger.created_count == 1  # reused, not duplicated


class TestSSRFGuard:
    """SSRFGuard blocks private/internal IPs."""

    def test_public_ip_allowed(self) -> None:
        guard = SSRFGuard()
        assert guard.check_ip("93.184.216.34").allow is True

    def test_loopback_blocked(self) -> None:
        guard = SSRFGuard()
        assert guard.check_ip("127.0.0.1").allow is False
        assert guard.check_ip("127.0.0.1").why is Why.SSRF_BLOCKED

    def test_private_rfc1918_blocked(self) -> None:
        guard = SSRFGuard()
        for ip in ("10.0.0.1", "172.16.0.1", "192.168.1.1"):
            assert guard.check_ip(ip).allow is False

    def test_link_local_blocked(self) -> None:
        guard = SSRFGuard()
        assert guard.check_ip("169.254.1.1").allow is False

    def test_metadata_endpoint_blocked(self) -> None:
        guard = SSRFGuard()
        assert guard.check_ip("169.254.169.254").allow is False

    def test_allow_private_flag(self) -> None:
        guard = SSRFGuard(allow_private=True)
        assert guard.check_ip("127.0.0.1").allow is True
        assert guard.check_ip("10.0.0.1").allow is True

    def test_scheme_validation(self) -> None:
        guard = SSRFGuard()
        assert guard.check_scheme("https").allow is True
        assert guard.check_scheme("http").allow is True
        assert guard.check_scheme("file").allow is False
        assert guard.check_scheme("gopher").allow is False
        assert guard.check_scheme("ftp").allow is False

    def test_ipv6_loopback_blocked(self) -> None:
        guard = SSRFGuard()
        assert guard.check_ip("::1").allow is False


class TestRedirectDepth:
    """Gate enforces maximum redirect depth."""

    def test_max_redirect_depth_denied(self) -> None:
        gate = _make_gate()
        req = RequestDescriptor(
            method="GET",
            url="https://acme.com.br/redir",
            redirect_depth=6,
        )
        decision = gate.evaluate(req)
        assert decision.allow is False
        assert decision.why is Why.OUT_OF_SCOPE

    def test_within_redirect_depth_allowed(self) -> None:
        gate = _make_gate()
        req = RequestDescriptor(
            method="GET",
            url="https://acme.com.br/redir",
            redirect_depth=3,
        )
        decision = gate.evaluate(req)
        assert decision.allow is True
