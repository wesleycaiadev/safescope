"""HTTP and TLS transport guarded by SafeScope policy controls.

Scanners receive this transport (or its ``request`` method), never a raw
``httpx`` client.  It validates policy before network access and evaluates
every redirect as a new request.
"""

from __future__ import annotations

import asyncio
import re
import socket
import ssl
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

import httpx

from safescope_core.policy import (
    PolicyDeny,
    RequestDescriptor,
    RequestGate,
    ResponseData,
    SSRFBlocked,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

MAX_REDIRECTS = 5
MAX_RESPONSE_BYTES = 1_048_576
_SENSITIVE_HEADERS = frozenset({"authorization", "cookie", "set-cookie", "proxy-authorization"})
_SECRET_PATTERN = re.compile(r"(?i)(?:api[_-]?key|access[_-]?token|refresh[_-]?token|password)\s*[:=]\s*[^\s,;\"']+")


@dataclass(frozen=True)
class TLSProbe:
    """Raw TLS observations returned only after a gated, pinned connection."""

    protocol_version: str
    cipher_name: str
    cipher_bits: int
    certificate: dict[str, Any]


class GatedTransport:
    """Network boundary for scanners.

    The preflight DNS check protects ordinary HTTP use. The dedicated TLS
    probe additionally pins its connection to a validated resolved IP while
    keeping the requested hostname for certificate validation/SNI.
    """

    def __init__(
        self,
        gate: RequestGate,
        *,
        client: httpx.AsyncClient | None = None,
        timeout: float = 10.0,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        self._gate = gate
        self._client = client or httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout,
            trust_env=False,
        )
        self._owns_client = client is None
        self._max_response_bytes = max_response_bytes

    async def __aenter__(self) -> GatedTransport:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the owned HTTP client; injected clients remain caller-owned."""
        if self._owns_client:
            await self._client.aclose()

    async def request(self, descriptor: RequestDescriptor) -> ResponseData:
        """Execute a policy-checked HTTP request with bounded sanitized output."""
        current = descriptor
        for _ in range(MAX_REDIRECTS + 1):
            self._allow(current)
            await self._validate_hostname(current.hostname)
            delay = self._gate.compute_delay()
            if delay:
                await asyncio.sleep(delay)

            async with self._client.stream(
                current.method,
                current.url,
                headers=current.headers,
                content=current.body,
                follow_redirects=False,
            ) as response:
                body = await _bounded_body(response, self._max_response_bytes)
                headers = sanitize_headers(dict(response.headers))
                response_data = ResponseData(
                    status_code=response.status_code,
                    headers=headers,
                    body=sanitize_body(body),
                    url=str(response.url),
                )

                location = response.headers.get("location")
                if not response.is_redirect or not location:
                    return response_data

            current = _redirect_descriptor(current, location)

        raise PolicyDeny("REDIRECT_LIMIT", f"more than {MAX_REDIRECTS} redirects")

    async def probe_tls(self, hostname: str, port: int = 443) -> TLSProbe:
        """Collect TLS metadata through the same gate and SSRF validation path."""
        url = _https_url(hostname, port)
        descriptor = RequestDescriptor(method="HEAD", url=url)
        self._allow(descriptor)
        addresses = await self._validated_addresses(hostname, port)
        delay = self._gate.compute_delay()
        if delay:
            await asyncio.sleep(delay)

        context = ssl.create_default_context()
        last_error: OSError | ssl.SSLError | None = None
        for address in addresses:
            try:
                _reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(address, port, ssl=context, server_hostname=hostname),
                    timeout=10.0,
                )
                try:
                    ssl_object = writer.transport.get_extra_info("ssl_object")
                    if ssl_object is None:
                        raise ssl.SSLError("TLS object unavailable")
                    cipher = ssl_object.cipher() or ("", "", 0)
                    certificate: dict[str, Any] = ssl_object.getpeercert() or {}
                    return TLSProbe(
                        protocol_version=ssl_object.version() or "",
                        cipher_name=str(cipher[0]),
                        cipher_bits=int(cipher[2]),
                        certificate=certificate,
                    )
                finally:
                    writer.close()
                    await writer.wait_closed()
            except (OSError, ssl.SSLError) as error:
                last_error = error

        detail = str(last_error) if last_error else "no usable address returned by DNS"
        raise OSError(f"TLS connection to {hostname}:{port} failed: {detail}")

    def _allow(self, descriptor: RequestDescriptor) -> None:
        decision = self._gate.evaluate(descriptor)
        if not decision.allow:
            raise PolicyDeny(decision.why.value, decision.detail)

    async def _validate_hostname(self, hostname: str, port: int | None = None) -> list[str]:
        """Resolve hostname and reject every unsafe answer before connecting."""
        if not hostname:
            raise SSRFBlocked("", detail="URL has no hostname")
        resolved_port = port or 443
        try:
            records = await asyncio.get_running_loop().getaddrinfo(
                hostname,
                resolved_port,
                type=socket.SOCK_STREAM,
            )
        except OSError as error:
            raise SSRFBlocked(hostname, detail=f"DNS resolution failed: {error}") from error

        addresses = list(_unique_addresses(records))
        if not addresses:
            raise SSRFBlocked(hostname, detail="DNS returned no addresses")
        for address in addresses:
            decision = self._gate.ssrf_guard.check_ip(address)
            if not decision.allow:
                raise SSRFBlocked(hostname, address, decision.detail)
        return addresses

    async def _validated_addresses(self, hostname: str, port: int) -> list[str]:
        return await self._validate_hostname(hostname, port)


async def _bounded_body(response: httpx.Response, limit: int) -> bytes:
    """Read only a bounded response body to avoid storing unbounded evidence."""
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        remaining = limit - total
        if remaining <= 0:
            break
        chunks.append(chunk[:remaining])
        total += len(chunks[-1])
        if total >= limit:
            break
    return b"".join(chunks)


def _unique_addresses(records: Iterable[tuple[Any, ...]]) -> Iterable[str]:
    seen: set[str] = set()
    for record in records:
        address = str(record[4][0])
        if address not in seen:
            seen.add(address)
            yield address


def _redirect_descriptor(current: RequestDescriptor, location: str) -> RequestDescriptor:
    url = urljoin(current.url, location)
    method = current.method
    body = current.body
    # Browser-compatible redirect semantics, while retaining 307/308 bodies
    # is intentionally avoided because it could replay a mutation.
    if method.upper() not in ("GET", "HEAD"):
        method = "GET"
        body = None
    return RequestDescriptor(
        method=method,
        url=url,
        headers=current.headers,
        body=body,
        redirect_depth=current.redirect_depth + 1,
        is_probe=current.is_probe,
        payload_id=current.payload_id,
    )


def _https_url(hostname: str, port: int) -> str:
    authority = hostname if port == 443 else f"{hostname}:{port}"
    return f"https://{authority}/"


def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Lowercase header names and redact values unsafe for evidence storage."""
    return {
        name.lower(): "[REDACTED]" if name.lower() in _SENSITIVE_HEADERS else value for name, value in headers.items()
    }


def sanitize_body(body: bytes) -> bytes:
    """Best-effort token redaction before a response can become evidence."""
    text = body.decode("utf-8", errors="replace")
    return _SECRET_PATTERN.sub("[REDACTED]", text).encode("utf-8")
