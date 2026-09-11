"""Tests for the policy-enforcing scanner transport."""

from __future__ import annotations

import asyncio

import httpx
import pytest

from safescope_core.policy import (
    KillSwitch,
    PolicyDeny,
    RequestDescriptor,
    RequestGate,
    ResourceLedger,
    ScanPolicyEngine,
    SSRFBlocked,
    SSRFGuard,
)
from safescope_scanners.transport import GatedTransport

from ..conftest import ACTIVE_SCANNER, make_authz, make_target


def _gate() -> RequestGate:
    engine = ScanPolicyEngine()
    snapshot = engine.freeze(make_target(), make_authz(max_rps=100_000), [ACTIVE_SCANNER])
    return RequestGate(snapshot, ResourceLedger("SCAN-TRANSPORT"), KillSwitch(), SSRFGuard())


def test_internal_redirect_is_rechecked_and_response_is_sanitized(monkeypatch) -> None:
    async def run() -> None:
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(str(request.url))
            if request.url.path == "/start":
                return httpx.Response(302, headers={"location": "/done"}, request=request)
            return httpx.Response(
                200,
                headers={"set-cookie": "session=secret", "server": "safe"},
                content=b"access_token=secret-value hello",
                request=request,
            )

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False)
        transport = GatedTransport(_gate(), client=client)

        async def public_dns(_hostname: str, _port: int | None = None) -> list[str]:
            return ["93.184.216.34"]

        monkeypatch.setattr(transport, "_validate_hostname", public_dns)
        try:
            result = await transport.request(RequestDescriptor("GET", "https://acme.com.br/start"))
        finally:
            await client.aclose()

        assert calls == ["https://acme.com.br/start", "https://acme.com.br/done"]
        assert result.headers["set-cookie"] == "[REDACTED]"
        assert b"secret-value" not in result.body

    asyncio.run(run())


def test_redirect_outside_scope_is_blocked_before_second_connection(monkeypatch) -> None:
    async def run() -> None:
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(str(request.url))
            return httpx.Response(302, headers={"location": "https://outside.example/"}, request=request)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False)
        transport = GatedTransport(_gate(), client=client)

        async def public_dns(_hostname: str, _port: int | None = None) -> list[str]:
            return ["93.184.216.34"]

        monkeypatch.setattr(transport, "_validate_hostname", public_dns)
        try:
            with pytest.raises(PolicyDeny, match="OUT_OF_SCOPE"):
                await transport.request(RequestDescriptor("GET", "https://acme.com.br/start"))
        finally:
            await client.aclose()

        assert calls == ["https://acme.com.br/start"]

    asyncio.run(run())


def test_private_dns_answer_is_blocked_before_http_request(monkeypatch) -> None:
    async def run() -> None:
        called = False

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal called
            called = True
            return httpx.Response(200, request=request)

        class FakeLoop:
            async def getaddrinfo(self, *_args, **_kwargs):
                return [(0, 0, 0, "", ("10.0.0.5", 443))]

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False)
        transport = GatedTransport(_gate(), client=client)
        monkeypatch.setattr("safescope_scanners.transport.asyncio.get_running_loop", lambda: FakeLoop())
        try:
            with pytest.raises(SSRFBlocked, match=r"10\.0\.0\.5"):
                await transport.request(RequestDescriptor("GET", "https://acme.com.br/"))
        finally:
            await client.aclose()

        assert called is False

    asyncio.run(run())
