"""Evidence oracles that require a negative control before confirming a finding."""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from safescope_core.policy import ResponseData


class ProofState(enum.StrEnum):
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True)
class ResponseFingerprint:
    status_code: int
    body_length: int
    body_hash: str

    @classmethod
    def from_response(cls, response: ResponseData) -> ResponseFingerprint:
        return cls(
            response.status_code,
            len(response.body),
            hashlib.sha256(response.body).hexdigest(),
        )


@dataclass(frozen=True)
class ProofResult:
    state: ProofState
    reason: str
    baseline: ResponseFingerprint
    control: ResponseFingerprint
    probe: ResponseFingerprint

    def evidence(self) -> dict[str, object]:
        """Return comparison metadata only; response bodies never enter evidence."""
        return {
            "proof_state": self.state.value,
            "reason": self.reason,
            "baseline": _public(self.baseline),
            "negative_control": _public(self.control),
            "probe": _public(self.probe),
        }


class DifferentialOracle:
    """Confirm only stable, repeatable differences from a negative control."""

    @staticmethod
    def evaluate(
        baseline: ResponseData,
        negative_control: ResponseData,
        probe: ResponseData,
    ) -> ProofResult:
        base = ResponseFingerprint.from_response(baseline)
        control = ResponseFingerprint.from_response(negative_control)
        tested = ResponseFingerprint.from_response(probe)
        if not _equivalent(base, control):
            return ProofResult(
                ProofState.INCONCLUSIVE,
                "baseline and negative control are unstable",
                base,
                control,
                tested,
            )
        if _equivalent(base, tested):
            return ProofResult(
                ProofState.REJECTED,
                "probe is equivalent to the stable control",
                base,
                control,
                tested,
            )
        return ProofResult(
            ProofState.CONFIRMED,
            "probe differs from a stable negative control",
            base,
            control,
            tested,
        )


class AuthorizationOracle:
    """Evaluate access to the same canary object through two target identities."""

    @staticmethod
    def evaluate(
        owner_response: ResponseData,
        denied_control: ResponseData,
        cross_identity_response: ResponseData,
    ) -> ProofResult:
        owner = ResponseFingerprint.from_response(owner_response)
        denied = ResponseFingerprint.from_response(denied_control)
        cross = ResponseFingerprint.from_response(cross_identity_response)
        if owner.status_code >= 400:
            return ProofResult(ProofState.INCONCLUSIVE, "owner cannot read the canary", owner, denied, cross)
        if denied.status_code < 400:
            return ProofResult(
                ProofState.INCONCLUSIVE,
                "negative authorization control did not deny access",
                owner,
                denied,
                cross,
            )
        if cross.status_code >= 400:
            return ProofResult(ProofState.REJECTED, "cross-identity access was denied", owner, denied, cross)
        if _equivalent(owner, cross):
            return ProofResult(
                ProofState.CONFIRMED,
                "another identity received the owner canary response",
                owner,
                denied,
                cross,
            )
        return ProofResult(
            ProofState.INCONCLUSIVE,
            "cross-identity response succeeded but did not match the canary",
            owner,
            denied,
            cross,
        )


def _equivalent(left: ResponseFingerprint, right: ResponseFingerprint) -> bool:
    return left.status_code == right.status_code and left.body_hash == right.body_hash


def _public(item: ResponseFingerprint) -> dict[str, object]:
    return {
        "status_code": item.status_code,
        "body_length": item.body_length,
        "body_hash": item.body_hash,
    }
