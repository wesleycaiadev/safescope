"""HTTPX transport whose TCP sockets use prevalidated, immutable DNS pins."""

from __future__ import annotations

import ssl
from typing import TYPE_CHECKING, cast

import httpcore
import httpx

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterable


class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Replace an original hostname with an already validated IP at connect time.

    HTTP Core still owns the original URL origin, Host header and TLS hostname.
    Only ``connect_tcp`` receives the pinned address, preserving certificate
    verification and SNI while preventing a second DNS lookup.
    """

    def __init__(self, backend: httpcore.AsyncNetworkBackend | None = None) -> None:
        default_backend = cast("httpcore.AsyncNetworkBackend", httpcore.AnyIOBackend())
        self._backend = backend or default_backend
        self._pins: dict[tuple[str, int], tuple[str, ...]] = {}

    def pin(self, hostname: str, port: int, addresses: Iterable[str]) -> None:
        """Freeze validated addresses for one host/port pair.

        Replacing a pin during a scan is forbidden. A new scan creates a new
        transport and therefore a new pin set.
        """
        key = (_normalize_host(hostname), port)
        frozen = tuple(dict.fromkeys(addresses))
        if not frozen:
            raise ValueError(f"cannot pin {hostname}:{port} without an address")
        current = self._pins.get(key)
        if current is not None and current != frozen:
            raise ValueError(f"DNS pin for {hostname}:{port} cannot change during a scan")
        self._pins[key] = frozen

    def addresses_for(self, hostname: str, port: int) -> tuple[str, ...]:
        """Return the immutable pin, or an empty tuple when not established."""
        return self._pins.get((_normalize_host(hostname), port), ())

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        """Connect only to a pinned address, trying validated answers in order."""
        addresses = self.addresses_for(host, port)
        if not addresses:
            raise httpcore.ConnectError(f"no validated DNS pin for {host}:{port}")

        last_error: httpcore.ConnectError | httpcore.ConnectTimeout | None = None
        for address in addresses:
            try:
                return await self._backend.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as error:
                last_error = error
        assert last_error is not None
        raise last_error

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        """Unix sockets are never available to web scanners."""
        raise httpcore.ConnectError("unix sockets are disabled for scanner traffic")

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


class _ResponseStream(httpx.AsyncByteStream):
    def __init__(self, stream: AsyncIterator[bytes]) -> None:
        self._stream = stream

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for part in self._stream:
            yield part

    async def aclose(self) -> None:
        await self._stream.aclose()  # type: ignore[attr-defined]


class PinnedAsyncHTTPTransport(httpx.AsyncBaseTransport):
    """Small HTTPX adapter around an HTTP Core pool with a pinned backend."""

    def __init__(self, *, max_connections: int, verify: ssl.SSLContext | None = None) -> None:
        self.backend = PinnedNetworkBackend()
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=verify or ssl.create_default_context(),
            max_connections=max_connections,
            max_keepalive_connections=max_connections,
            http1=True,
            http2=False,
            network_backend=self.backend,
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Adapt an HTTPX request without changing its hostname or TLS identity."""
        request.extensions["sni_hostname"] = request.url.host
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        try:
            response = await self._pool.handle_async_request(core_request)
        except httpcore.TimeoutException as error:
            raise httpx.TimeoutException(str(error), request=request) from error
        except httpcore.NetworkError as error:
            raise httpx.NetworkError(str(error), request=request) from error
        except httpcore.ProtocolError as error:
            raise httpx.ProtocolError(str(error), request=request) from error

        stream: AsyncIterator[bytes] = response.stream  # type: ignore[assignment]
        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=_ResponseStream(stream),
            extensions=response.extensions,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()


def _normalize_host(hostname: str) -> str:
    return hostname.strip("[]").rstrip(".").lower()
