"""Typed error hierarchy for SafeScope policy enforcement.

Every denial is traceable to a specific reason enum value.
No generic Exception escapes the policy layer.
"""

from __future__ import annotations


class SafeScopeError(Exception):
    """Base for all SafeScope errors."""


class PolicyError(SafeScopeError):
    """Base for policy-layer errors."""


class PolicyDeny(PolicyError):
    """Scanner or request denied by ScanPolicyEngine."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


class ScopeViolation(PolicyError):
    """Request targets a URL outside the authorized scope."""

    def __init__(self, detail: str = "") -> None:
        self.detail = detail
        super().__init__(f"scope violation: {detail}" if detail else "scope violation")


class BudgetExhausted(PolicyError):
    """Max request count for this scan run has been reached."""

    def __init__(self, made: int, limit: int | None = None) -> None:
        self.made = made
        self.limit = limit
        msg = f"budget exhausted: {made} requests made"
        if limit is not None:
            msg += f" (limit: {limit})"
        super().__init__(msg)


class KillSwitchEngaged(PolicyError):
    """Kill switch is active — all scanning operations are halted."""

    def __init__(self, reason: str = "", actor: str = "") -> None:
        self.reason = reason
        self.actor = actor
        super().__init__(f"kill switch engaged by {actor}: {reason}" if actor else "kill switch engaged")


class MutationForbidden(PolicyError):
    """Write operation attempted without proper authorization or ledger registration."""

    def __init__(self, verb: str, url: str, detail: str = "") -> None:
        self.verb = verb
        self.url = url
        self.detail = detail
        msg = f"{verb} {url}: mutation forbidden — {detail}" if detail else f"{verb} {url}: mutation forbidden"
        super().__init__(msg)


class SSRFBlocked(PolicyError):
    """Request targets a private/internal IP address."""

    def __init__(self, host: str, ip: str = "", detail: str = "") -> None:
        self.host = host
        self.ip = ip
        self.detail = detail
        super().__init__(f"SSRF blocked: {host} resolves to {ip}" if ip else f"SSRF blocked: {host}")
