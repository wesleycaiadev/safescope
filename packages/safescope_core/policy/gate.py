"""RequestGate — the checkpoint every request passes through.

Operates on RequestDescriptor (pure data). Returns Decision.
Does NOT execute HTTP. The Transport layer handles that.

The gate evaluates:
1. Kill switch
2. Budget (max_requests)
3. Origin against allowed_origins
4. Exclusions
5. HTTP verb against allowed_verbs
6. Write operations: ledger or allow_write_paths
7. Rate limiting (tracking only — actual sleep is Transport's job)

SSRFGuard validates resolved IPs — DNS resolution happens in the Transport,
which passes the resolved IP to SSRFGuard before connecting.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from .engine import WRITE_VERBS, Decision, Why

if TYPE_CHECKING:
    from .ledger import ResourceLedger
    from .request import RequestDescriptor


class SSRFGuard:
    """Validates resolved IP addresses against a blocklist.

    This guard does NOT perform DNS resolution itself.
    The Transport resolves DNS, then passes the IP here for validation
    BEFORE connecting. This is the only way to prevent DNS rebinding
    and redirect-based SSRF.

    See ADR-0005 for the full rationale.
    """

    # IPs that are always blocked unless explicitly allowed
    _METADATA_PREFIXES = (
        "169.254.169.254",  # AWS/GCP metadata
        "100.100.100.200",  # Alibaba metadata
        "fd00:ec2::254",  # AWS IMDSv2 IPv6
    )

    def __init__(self, *, allow_private: bool = False) -> None:
        self.allow_private = allow_private

    def check_ip(self, ip_str: str) -> Decision:
        """Validate a resolved IP address. Called by Transport after DNS resolution."""
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return Decision.deny(Why.SSRF_BLOCKED, f"invalid IP: {ip_str}")

        # Always block metadata endpoints
        if ip_str in self._METADATA_PREFIXES:
            return Decision.deny(Why.SSRF_BLOCKED, f"metadata endpoint: {ip_str}")

        if self.allow_private:
            return Decision.ok()

        if addr.is_loopback:
            return Decision.deny(Why.SSRF_BLOCKED, f"loopback: {ip_str}")
        if addr.is_private:
            return Decision.deny(Why.SSRF_BLOCKED, f"private network: {ip_str}")
        if addr.is_link_local:
            return Decision.deny(Why.SSRF_BLOCKED, f"link-local: {ip_str}")
        if addr.is_multicast:
            return Decision.deny(Why.SSRF_BLOCKED, f"multicast: {ip_str}")
        if addr.is_unspecified:
            return Decision.deny(Why.SSRF_BLOCKED, f"unspecified: {ip_str}")
        if addr.is_reserved:
            return Decision.deny(Why.SSRF_BLOCKED, f"reserved: {ip_str}")

        # IPv6-specific checks
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            return self.check_ip(str(addr.ipv4_mapped))

        return Decision.ok()

    def check_scheme(self, scheme: str) -> Decision:
        """Only http and https are allowed."""
        if scheme not in ("http", "https"):
            return Decision.deny(Why.SCHEME_NOT_ALLOWED, f"scheme '{scheme}' blocked")
        return Decision.ok()


class RequestGate:
    """The checkpoint that every request must pass through.

    Operates on RequestDescriptor. Returns Decision or raises typed exceptions.
    Does NOT perform I/O.

    The snapshot (from ScanPolicyEngine.freeze()) captures the immutable policy.
    Mutable state is passed as references:
    - kill_switch: KillSwitch instance (mutable, checked live)
    - ledger: ResourceLedger instance (mutable, updated during scan)
    - budget counter: internal to this gate (mutable)

    Usage by Transport:
        decision = gate.evaluate(request_descriptor)
        if not decision.allow:
            raise ScopeViolation(decision.detail)
        # ... execute HTTP ...
        # On redirect:
        redirect_decision = gate.evaluate(redirect_descriptor)
    """

    MAX_REDIRECT_DEPTH = 5

    def __init__(
        self,
        snapshot: dict[str, Any],
        ledger: ResourceLedger,
        kill_switch: KillSwitch,
        ssrf_guard: SSRFGuard,
    ) -> None:
        self.snapshot = snapshot
        self.ledger = ledger
        self.kill_switch = kill_switch
        self.ssrf_guard = ssrf_guard
        self._requests_made: int = 0
        self._last_request_time: float = 0.0

    @property
    def requests_made(self) -> int:
        return self._requests_made

    @property
    def budget_remaining(self) -> int:
        return max(0, int(self.snapshot["max_requests"]) - self._requests_made)

    def evaluate(self, req: RequestDescriptor) -> Decision:
        """Evaluate whether a request is allowed. Pure logic, no I/O.

        Returns Decision. The Transport layer is responsible for:
        - Raising the appropriate exception on deny
        - Applying rate limiting (sleep)
        - Resolving DNS and calling ssrf_guard.check_ip()
        - Following redirects with re-evaluation
        """
        # 1. Kill switch — checked live (mutable reference)
        if self.kill_switch.engaged:
            return Decision.deny(Why.KILL_SWITCH_ENGAGED, self.kill_switch.reason)

        # 2. Budget
        max_req = int(self.snapshot["max_requests"])
        if self._requests_made >= max_req:
            return Decision.deny(
                Why.BUDGET_EXHAUSTED,
                f"{self._requests_made}/{max_req} requests used",
            )

        # Authorization validity is checked again before every request. A scan
        # that outlives its approved window stops at this boundary.
        valid_from = self.snapshot.get("valid_from")
        valid_until = self.snapshot.get("valid_until")
        if valid_from is not None or valid_until is not None:
            now = datetime.now(UTC)
            try:
                starts = datetime.fromisoformat(str(valid_from))
                ends = datetime.fromisoformat(str(valid_until))
            except TypeError, ValueError:
                return Decision.deny(Why.TIME_WINDOW_CLOSED, "invalid authorization window")
            if starts.tzinfo is None:
                starts = starts.replace(tzinfo=UTC)
            if ends.tzinfo is None:
                ends = ends.replace(tzinfo=UTC)
            if not starts <= now <= ends:
                return Decision.deny(Why.TIME_WINDOW_CLOSED, "request is outside the authorization window")

        # 3. Redirect depth
        if req.redirect_depth > self.MAX_REDIRECT_DEPTH:
            return Decision.deny(Why.OUT_OF_SCOPE, f"redirect depth {req.redirect_depth} exceeds limit")

        # 4. Scheme
        scheme_check = self.ssrf_guard.check_scheme(req.scheme)
        if not scheme_check.allow:
            return scheme_check

        # 5. Origin scope
        origin = req.origin
        allowed = self.snapshot["allowed_origins"]
        if origin not in allowed and not self._is_passive_root_alias(origin):
            return Decision.deny(Why.OUT_OF_SCOPE, f"origin '{origin}' not in allowed list")

        # 6. Exclusions
        for pattern in self.snapshot["excluded"]:
            if fnmatch.fnmatch(req.url, pattern):
                return Decision.deny(Why.EXCLUDED_PATH, f"URL matches exclusion '{pattern}'")

        # 7. HTTP verb
        method = req.method.upper()
        if method not in self.snapshot["verbs"]:
            return Decision.deny(Why.VERB_NOT_ALLOWED, f"verb '{method}' not allowed")

        # 8. Request body and probe payload controls. Baseline requests do not
        # need a payload identifier; every deliberate probe does.
        content_type = req.content_type
        if content_type is not None:
            allowed_content_types = {
                str(item).split(";", 1)[0].strip().lower() for item in self.snapshot.get("allowed_content_types", [])
            }
            if content_type not in allowed_content_types:
                return Decision.deny(
                    Why.CONTENT_TYPE_NOT_ALLOWED,
                    f"content type '{content_type}' not in authorization allowlist",
                )

        if req.is_probe:
            if not req.payload_id:
                return Decision.deny(Why.PAYLOAD_NOT_ALLOWED, "probe request has no payload identifier")
            if req.payload_id not in self.snapshot.get("allowed_payloads", []):
                return Decision.deny(
                    Why.PAYLOAD_NOT_ALLOWED,
                    f"payload '{req.payload_id}' not in authorization allowlist",
                )

        # 9. Write operations — mutation control
        if method in WRITE_VERBS:
            if not self.snapshot["allow_mutations"]:
                return Decision.deny(Why.MUTATION_FORBIDDEN, f"{method} requires allow_mutations=true")

            # DELETE is limited to resources created and owned by this scan.
            # A snapshot alone is not permission to remove an existing object.
            if method == "DELETE" and not self.ledger.owns(req.url):
                return Decision.deny(
                    Why.NOT_IN_LEDGER,
                    f"DELETE on '{req.url}': only scan-owned resources may be removed",
                )

            # Other writes must be in the ledger OR in allow_write_paths.
            if not self.ledger.owns(req.url):
                if not any(fnmatch.fnmatch(req.url, p) for p in self.snapshot["allow_write_paths"]):
                    return Decision.deny(
                        Why.NOT_IN_LEDGER,
                        f"{method} on '{req.url}': not in ledger and not in allow_write_paths",
                    )
                # In allow_write_paths but not ledgered — must have snapshot
                # (case 9: mutating existing resource requires state_before)
                if method in ("PUT", "PATCH") and not self.ledger.has_snapshot(req.url):
                    return Decision.deny(
                        Why.NOT_IN_LEDGER,
                        f"{method} on existing resource '{req.url}': snapshot() required before mutation",
                    )

        # 10. Rate limiting — compute delay, don't sleep
        #    Transport is responsible for applying the delay
        self._requests_made += 1

        return Decision.ok()

    def _is_passive_root_alias(self, origin: str) -> bool:
        """Allow only apex/www redirects for a public passive assessment.

        This handles the normal canonical redirect from example.com to
        www.example.com without broadening the scan to an unrelated subdomain.
        Authorization-backed scans remain exact-origin only.
        """
        if self.snapshot.get("mode") != "PASSIVE" or self.snapshot.get("authorization_id") is not None:
            return False
        parsed = urlsplit(origin)
        host = parsed.hostname or ""
        root = str(self.snapshot.get("root_domain", "")).lower()
        return host.lower() in {root, f"www.{root}"}

    def compute_delay(self) -> float:
        """Compute delay in seconds before next request. Transport applies the sleep."""
        max_rps = float(self.snapshot["max_rps"]) or 1.0
        min_interval = 1.0 / max_rps
        now = time.monotonic()
        elapsed = now - self._last_request_time
        delay = max(0.0, min_interval - elapsed)
        self._last_request_time = now if delay == 0.0 else now + delay
        return delay


class KillSwitch:
    """Atomic flag that halts all scanning. Checked by RequestGate before every request.

    When engaged:
    - Queued jobs → ABORTED
    - Running scans stop at next request boundary
    - Child processes (ZAP/Nuclei/SQLmap) receive SIGTERM→SIGKILL
    - Audit log records the event

    Thread-safe: engaged is a simple bool read (atomic on CPython due to GIL).
    """

    def __init__(self) -> None:
        self._engaged: bool = False
        self._reason: str = ""
        self._actor: str = ""
        self._at: str = ""

    @property
    def engaged(self) -> bool:
        return self._engaged

    @property
    def reason(self) -> str:
        return self._reason

    @property
    def actor(self) -> str:
        return self._actor

    def engage(self, reason: str, actor: str) -> None:
        """Activate the kill switch. Effect is immediate on next gate check."""
        self._engaged = True
        self._reason = reason
        self._actor = actor
        self._at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def disengage(self, actor: str) -> None:
        """Deactivate the kill switch."""
        self._engaged = False
        self._reason = ""
        self._actor = actor
        self._at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def state(self) -> dict[str, Any]:
        """Current state for API/audit purposes."""
        return {
            "engaged": self._engaged,
            "reason": self._reason,
            "actor": self._actor,
            "at": self._at,
        }
