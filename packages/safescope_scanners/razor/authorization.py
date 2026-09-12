"""Canary-only IDOR and authorization-matrix scanners."""

from __future__ import annotations

from dataclasses import dataclass, replace

from safescope_core.policy import RequestDescriptor, Risk
from safescope_scanners.base import RawObservation, ScanContext, Scanner, Severity
from safescope_scanners.oracles import AuthorizationOracle, ProofState


@dataclass(frozen=True)
class AuthorizationCandidate:
    """Three requests around one scan-created or dedicated test canary."""

    owner_identity: str
    other_identity: str
    owner_request: RequestDescriptor
    denied_control_request: RequestDescriptor
    cross_identity_request: RequestDescriptor
    canary: bool = False


class _AuthorizationScanner(Scanner):
    risk = Risk.ACTIVE
    requires_auth = True
    destructive = False
    payload_id = "authorization-canary-read"
    candidate_key = "authorization_candidates"
    finding_title = "Broken object-level authorization on test canary"

    async def scan(self, ctx: ScanContext) -> list[RawObservation]:
        """Compare owner, denied control and cross-identity canary reads."""
        if ctx.sessions is None:
            return []
        snapshot = ctx.metadata.get("policy_snapshot", {})
        if self.payload_id not in snapshot.get("allowed_payloads", []):
            return []
        candidates = ctx.metadata.get(self.candidate_key, [])
        observations: list[RawObservation] = []
        for candidate in candidates:
            if not isinstance(candidate, AuthorizationCandidate) or not candidate.canary:
                continue
            owner = await ctx.sessions.request(
                candidate.owner_identity,
                _probe(candidate.owner_request, self.payload_id),
            )
            denied = await ctx.sessions.request(
                candidate.other_identity,
                _probe(candidate.denied_control_request, self.payload_id),
            )
            cross = await ctx.sessions.request(
                candidate.other_identity,
                _probe(candidate.cross_identity_request, self.payload_id),
            )
            proof = AuthorizationOracle.evaluate(owner, denied, cross)
            if proof.state is not ProofState.CONFIRMED:
                continue
            observations.append(
                RawObservation(
                    title=self.finding_title,
                    severity=Severity.HIGH,
                    url=candidate.cross_identity_request.url,
                    detail=(
                        "A second authorized test identity read the first identity's "
                        "dedicated canary object while the negative control was denied."
                    ),
                    confidence=0.98,
                    evidence=proof.evidence(),
                    cwe="CWE-639",
                    owasp_wstg="WSTG-ATHZ-04",
                    remediation="Enforce object ownership and authorization on every server-side lookup.",
                )
            )
        return observations


class IdorScanner(_AuthorizationScanner):
    id = "razor-idor-canary"
    name = "IDOR Canary Scanner"
    candidate_key = "idor_candidates"


class AuthorizationMatrixScanner(_AuthorizationScanner):
    id = "razor-authorization-matrix"
    name = "Authorization Matrix Scanner"
    candidate_key = "authorization_matrix_candidates"
    finding_title = "Authorization matrix violation on test canary"


def _probe(request: RequestDescriptor, payload_id: str) -> RequestDescriptor:
    return replace(request, is_probe=True, payload_id=payload_id)
