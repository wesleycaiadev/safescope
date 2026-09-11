"""CredentialVault — ephemeral, scoped credential storage.

SecretString uses bytearray (NOT str). Python str is immutable and interned;
wipe() on str is theater. bytearray allows zeroing, but this is BEST-EFFORT
against swap/dump post-hoc — not a memory protection guarantee.

What actually protects:
- TTL: credential expires after a fixed duration
- Scope: credential dies when the scan_run ends (even on exception)
- Masking: repr() and str() never show the value
- Logging filter: global filter masks password|token|cookie|api[-_]?key

See ADR for honest discussion of limitations.
"""

from __future__ import annotations

import time


class SecretString:
    """In-memory secret with masked repr, TTL, and best-effort wipe.

    Uses bytearray internally — the only mutable sequence type in Python
    that allows in-place zeroing. This is best-effort: the GC, swap,
    and core dumps can still leak the value. The TTL and scope-based
    lifecycle are the real protections.
    """

    __slots__ = ("_buf", "_expires", "_name", "_wiped")

    def __init__(self, value: str, *, ttl_seconds: int = 3600, name: str = "secret") -> None:
        self._buf: bytearray = bytearray(value.encode("utf-8"))
        self._expires: float = time.monotonic() + ttl_seconds
        self._name: str = name
        self._wiped: bool = False

    @property
    def value(self) -> str:
        """Access the secret value. Raises if expired or wiped."""
        if self._wiped:
            raise RuntimeError(f"SecretString '{self._name}' has been wiped")
        if time.monotonic() > self._expires:
            self.wipe()
            raise RuntimeError(f"SecretString '{self._name}' has expired")
        return self._buf.decode("utf-8")

    @property
    def is_alive(self) -> bool:
        """True if the secret is accessible (not expired, not wiped)."""
        return not self._wiped and time.monotonic() <= self._expires

    @property
    def is_wiped(self) -> bool:
        """Whether the in-memory buffer has already been cleared."""
        return self._wiped

    def wipe(self) -> None:
        """Best-effort zeroing of the buffer.

        Zeroes every byte in the bytearray, then replaces with empty.
        This is NOT a guarantee against forensic memory analysis,
        swap files, or core dumps. It IS a guarantee that casual
        access after wipe() returns empty, and that the buffer
        contents are overwritten in the process's address space.
        """
        for i in range(len(self._buf)):
            self._buf[i] = 0
        self._buf = bytearray()
        self._wiped = True

    def __repr__(self) -> str:
        status = "wiped" if self._wiped else "alive"
        return f"SecretString(name='{self._name}', status={status})"

    def __str__(self) -> str:
        return repr(self)

    # Prevent accidental serialization
    def __reduce__(self) -> None:  # type: ignore[override]
        raise TypeError(f"SecretString '{self._name}' cannot be pickled")


class CredentialVault:
    """Scoped credential storage. Credentials die when the scan run dies.

    Usage:
        vault = CredentialVault()
        vault.put("run-123", "user_password", SecretString("s3cret", ttl_seconds=1800))
        password = vault.get("run-123", "user_password")
        vault.drop("run-123")  # wipes all secrets for this run
    """

    def __init__(self) -> None:
        self._store: dict[str, dict[str, SecretString]] = {}

    def put(self, scan_run_id: str, label: str, secret: SecretString) -> None:
        """Store a secret for a scan run. Overwrites if label already exists."""
        self._store.setdefault(scan_run_id, {})[label] = secret

    def get(self, scan_run_id: str, label: str) -> str:
        """Retrieve a secret value. Raises KeyError or RuntimeError if unavailable."""
        return self._store[scan_run_id][label].value

    def has(self, scan_run_id: str, label: str) -> bool:
        """Check if a secret exists and is accessible."""
        if scan_run_id not in self._store or label not in self._store[scan_run_id]:
            return False
        return self._store[scan_run_id][label].is_alive

    def drop(self, scan_run_id: str) -> int:
        """Wipe and remove all secrets for a scan run. Returns count wiped."""
        secrets = self._store.pop(scan_run_id, {})
        for secret in secrets.values():
            if not secret.is_wiped:
                secret.wipe()
        return len(secrets)

    def active_runs(self) -> list[str]:
        """List scan run IDs with active credentials."""
        return list(self._store.keys())
