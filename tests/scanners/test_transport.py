"""Tests for the policy-enforcing scanner transport."""

from __future__ import annotations

import asyncio

import httpcore
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
from safescope_scanners.pinned_http import PinnedNetworkBackend
from safescope_scanners.transport import GatedTransport, _request_port

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


def test_dns_result_is_frozen_and_not_resolved_twice(monkeypatch) -> None:
    async def run() -> None:
        client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, request=request)))
        transport = GatedTransport(_gate(), client=client)
        resolutions = 0

        async def public_dns(_hostname: str, _port: int) -> list[str]:
            nonlocal resolutions
            resolutions += 1
            return ["93.184.216.34"]

        monkeypatch.setattr(transport, "_validated_addresses", public_dns)
        try:
            descriptor = RequestDescriptor("GET", "https://acme.com.br/path")
            assert await transport._ensure_hostname_pin(descriptor) == ("93.184.216.34",)
            assert await transport._ensure_hostname_pin(descriptor) == ("93.184.216.34",)
        finally:
            await client.aclose()
        assert resolutions == 1

    asyncio.run(run())


def test_pinned_backend_connects_to_ip_instead_of_hostname() -> None:
    class RecordingBackend(httpcore.AsyncNetworkBackend):
        def __init__(self) -> None:
            self.hosts: list[str] = []

        async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            self.hosts.append(host)
            raise httpcore.ConnectError("stop after recording")

        async def connect_unix_socket(self, path, timeout=None, socket_options=None):
            raise AssertionError("unix socket must not be used")

        async def sleep(self, seconds):
            return None

    async def run() -> None:
        recording = RecordingBackend()
        backend = PinnedNetworkBackend(recording)
        backend.pin("acme.com.br", 443, ["93.184.216.34", "93.184.216.35"])
        with pytest.raises(httpcore.ConnectError):
            await backend.connect_tcp("acme.com.br", 443)
        assert recording.hosts == ["93.184.216.34", "93.184.216.35"]

    asyncio.run(run())


def test_unpinned_backend_fails_closed() -> None:
    async def run() -> None:
        backend = PinnedNetworkBackend()
        with pytest.raises(httpcore.ConnectError, match="no validated DNS pin"):
            await backend.connect_tcp("acme.com.br", 443)

    asyncio.run(run())


def test_request_port_uses_scheme_defaults_and_explicit_port() -> None:
    assert _request_port("https://acme.com.br/path") == 443
    assert _request_port("http://acme.com.br/path") == 80
    assert _request_port("https://acme.com.br:8443/path") == 8443
