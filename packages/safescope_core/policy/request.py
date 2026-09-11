"""RequestDescriptor — pure data object for policy evaluation.

The core decides on this object. No httpx, no socket, no I/O.
The actual HTTP execution lives in GatedTransport (safescope_scanners.transport).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RequestDescriptor:
    """Describes an HTTP request for policy evaluation. Pure data, no I/O.

    The gate evaluates this and returns a Decision.
    The transport executes it only if the decision is ALLOW.
    """

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None
    redirect_depth: int = 0
    is_probe: bool = False
    payload_id: str | None = None

    @property
    def scheme(self) -> str:
        return self.url.split("://", 1)[0].lower() if "://" in self.url else ""

    @property
    def hostname(self) -> str:
        """Extract hostname from URL without importing urllib (keep it stdlib-minimal)."""
        after_scheme = self.url.split("://", 1)[1] if "://" in self.url else self.url
        host_port = after_scheme.split("/", 1)[0]
        # Handle [IPv6]:port
        if host_port.startswith("["):
            return host_port.split("]", 1)[0] + "]"
        return host_port.split(":", 1)[0]

    @property
    def origin(self) -> str:
        """scheme://host[:port] — used for scope checks."""
        after_scheme = self.url.split("://", 1)[1] if "://" in self.url else self.url
        host_port = after_scheme.split("/", 1)[0]
        return f"{self.scheme}://{host_port}"

    @property
    def content_type(self) -> str | None:
        """Return the normalized media type, without optional parameters."""
        for name, value in self.headers.items():
            if name.lower() == "content-type":
                return value.split(";", 1)[0].strip().lower() or None
        return None


@dataclass(frozen=True)
class ResponseData:
    """Minimal response descriptor returned by GatedTransport.

    Enough for policy re-evaluation on redirects. Full response
    details are available to the scanner through the transport.
    """

    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    url: str = ""
    redirect_url: str | None = None

    @property
    def is_redirect(self) -> bool:
        return self.status_code in (301, 302, 303, 307, 308) and bool(self.redirect_url)
