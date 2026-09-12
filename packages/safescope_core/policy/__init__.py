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
from .recovery import (
    RecoverySummary,
    RestoreAction,
    RestoreJournal,
    RestoreKind,
    replay_restore_journal,
)
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
    "RecoverySummary",
    "RequestDescriptor",
    "RequestGate",
    "ResourceLedger",
    "ResponseData",
    "RestoreAction",
    "RestoreJournal",
    "RestoreKind",
    "Risk",
    "SSRFBlocked",
    "SSRFGuard",
    "SafeScopeError",
    "ScanPolicyEngine",
    "ScannerSpec",
    "ScopeViolation",
    "TargetSpec",
    "Why",
    "replay_restore_journal",
]
