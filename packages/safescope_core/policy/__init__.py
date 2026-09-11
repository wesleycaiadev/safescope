"""SafeScope Policy Engine — public API."""

from .engine import (
    AuthorizationSpec,
    Decision,
    Mode,
    Risk,
    ScannerSpec,
    ScanPolicyEngine,
    TargetSpec,
    Why,
)
from .errors import (
    BudgetExhausted,
    KillSwitchEngaged,
    MutationForbidden,
    PolicyDeny,
    PolicyError,
    SafeScopeError,
    ScopeViolation,
    SSRFBlocked,
)
from .gate import KillSwitch, RequestGate, SSRFGuard
from .ledger import ResourceLedger
from .request import RequestDescriptor, ResponseData

__all__ = [
    "AuthorizationSpec",
    "BudgetExhausted",
    "Decision",
    "KillSwitch",
    "KillSwitchEngaged",
    "Mode",
    "MutationForbidden",
    "PolicyDeny",
    "PolicyError",
    "RequestDescriptor",
    "RequestGate",
    "ResourceLedger",
    "ResponseData",
    "Risk",
    "SSRFBlocked",
    "SSRFGuard",
    "SafeScopeError",
    "ScanPolicyEngine",
    "ScannerSpec",
    "ScopeViolation",
    "TargetSpec",
    "Why",
]
