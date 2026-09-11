"""Apex/www redirects are permitted only for passive public assessments."""

from safescope_core.policy import (
    KillSwitch,
    Mode,
    RequestDescriptor,
    RequestGate,
    ResourceLedger,
    ScanPolicyEngine,
    SSRFGuard,
)

from ..conftest import PASSIVE_SCANNER, make_target


def test_passive_allows_only_www_alias_of_root_domain() -> None:
    snapshot = ScanPolicyEngine().freeze(make_target(mode=Mode.PASSIVE), None, [PASSIVE_SCANNER])
    gate = RequestGate(snapshot, ResourceLedger("scan"), KillSwitch(), SSRFGuard())
    assert gate.evaluate(RequestDescriptor("GET", "https://www.acme.com.br/")).allow is True
    assert gate.evaluate(RequestDescriptor("GET", "https://api.acme.com.br/")).allow is False
