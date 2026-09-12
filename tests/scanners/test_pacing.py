"""Adaptive pacing and bounded plan tests."""

from __future__ import annotations

import asyncio

import httpx

from safescope_core.policy import RequestDescriptor
from safescope_scanners.pacing import AdaptivePacer, RequestPlan
from safescope_scanners.transport import GatedTransport

from ..conftest import (
    ACTIVE_SCANNER,
    KillSwitch,
    RequestGate,
    ResourceLedger,
    ScanPolicyEngine,
    SSRFGuard,
    make_authz,
    make_target,
)


def test_repeated_waf_signals_halve_rate_and_count_soft_mode() -> None:
    pacer = AdaptivePacer(4.0, clock=lambda: 10.0, random_value=lambda: 0.0)
    pacer.observe(429)
    assert pacer.current_rps == 4.0
    pacer.observe(403)
    assert pacer.current_rps == 2.0
    assert pacer.soft_mode_entries == 1
    pacer.observe(200)
    pacer.observe(429)
    assert pacer.current_rps == 2.0


def test_jitter_is_bounded() -> None:
    pacer = AdaptivePacer(2.0, jitter_ratio=0.2, clock=lambda: 100.0, random_value=lambda: 1.0)
    assert pacer.compute_delay() == 0.1


def test_concurrent_plan_never_exceeds_authorized_limit(monkeypatch) -> None:
    async def run() -> None:
        active = peak = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1
            return httpx.Response(200, request=request)

        snapshot = ScanPolicyEngine().freeze(
            make_target(),
            make_authz(max_concurrency=2, max_rps=100_000),
            [ACTIVE_SCANNER],
        )
        gate = RequestGate(snapshot, ResourceLedger("plan"), KillSwitch(), SSRFGuard())
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        transport = GatedTransport(gate, client=client)

        async def public_dns(_hostname: str, _port: int) -> list[str]:
            return ["93.184.216.34"]

        monkeypatch.setattr(transport, "_validated_addresses", public_dns)
        try:
            plan = RequestPlan(
                tuple(RequestDescriptor("GET", f"https://acme.com.br/{index}") for index in range(6)),
                concurrent=True,
            )
            responses = await transport.execute_plan(plan)
        finally:
            await client.aclose()
        assert len(responses) == 6
        assert peak == 2

    asyncio.run(run())
