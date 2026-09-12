"""Known-answer coverage for canary-only authorization scanners."""

from __future__ import annotations

import asyncio

from safescope_core.policy import RequestDescriptor, ResponseData
from safescope_scanners.base import ScanContext
from safescope_scanners.razor import AuthorizationCandidate, AuthorizationMatrixScanner, IdorScanner


class KnownAnswerSessions:
    async def request(self, identity: str, request: RequestDescriptor) -> ResponseData:
        assert request.is_probe is True
        assert request.payload_id == "authorization-canary-read"
        if request.url.endswith("/missing"):
            return ResponseData(404, body=b"not found")
        if request.url.endswith("/user_a") and identity in {"user_a", "user_b"}:
            return ResponseData(200, body=b'{"id":"canary-user-a"}')
        return ResponseData(403, body=b"forbidden")


def test_idor_scanner_confirms_only_a_declared_canary() -> None:
    async def run() -> None:
        candidate = AuthorizationCandidate(
            "user_a",
            "user_b",
            RequestDescriptor("GET", "https://lab.test/api/profiles/user_a"),
            RequestDescriptor("GET", "https://lab.test/api/profiles/missing"),
            RequestDescriptor("GET", "https://lab.test/api/profiles/user_a"),
            canary=True,
        )
        context = ScanContext(
            "https://lab.test",
            None,
            None,
            sessions=KnownAnswerSessions(),
            metadata={
                "policy_snapshot": {"allowed_payloads": ["authorization-canary-read"]},
                "idor_candidates": [candidate],
            },
        )
        observations = await IdorScanner().scan(context)
        assert len(observations) == 1
        assert observations[0].severity.value == "HIGH"
        assert observations[0].evidence["proof_state"] == "CONFIRMED"
        assert "body" not in observations[0].evidence["probe"]

        context.metadata["idor_candidates"] = [
            AuthorizationCandidate(
                candidate.owner_identity,
                candidate.other_identity,
                candidate.owner_request,
                candidate.denied_control_request,
                candidate.cross_identity_request,
                canary=False,
            )
        ]
        assert await IdorScanner().scan(context) == []

    asyncio.run(run())


def test_authorization_matrix_uses_its_explicit_candidate_list() -> None:
    async def run() -> None:
        candidate = AuthorizationCandidate(
            "user_a",
            "user_b",
            RequestDescriptor("GET", "https://lab.test/api/profiles/user_a"),
            RequestDescriptor("GET", "https://lab.test/api/profiles/missing"),
            RequestDescriptor("GET", "https://lab.test/api/profiles/user_a"),
            canary=True,
        )
        context = ScanContext(
            "https://lab.test",
            None,
            None,
            sessions=KnownAnswerSessions(),
            metadata={
                "policy_snapshot": {"allowed_payloads": ["authorization-canary-read"]},
                "authorization_matrix_candidates": [candidate],
            },
        )
        observations = await AuthorizationMatrixScanner().scan(context)
        assert len(observations) == 1
        assert observations[0].title == "Authorization matrix violation on test canary"

    asyncio.run(run())
