"""Proof oracle tests."""

from safescope_core.policy import ResponseData
from safescope_scanners.oracles import AuthorizationOracle, DifferentialOracle, ProofState


def test_differential_oracle_confirms_only_against_stable_control() -> None:
    result = DifferentialOracle.evaluate(
        ResponseData(200, body=b"normal"),
        ResponseData(200, body=b"normal"),
        ResponseData(500, body=b"different"),
    )
    assert result.state is ProofState.CONFIRMED
    assert "body" not in result.evidence()["probe"]


def test_differential_oracle_rejects_unstable_baseline() -> None:
    result = DifferentialOracle.evaluate(
        ResponseData(200, body=b"one"),
        ResponseData(200, body=b"two"),
        ResponseData(500, body=b"different"),
    )
    assert result.state is ProofState.INCONCLUSIVE


def test_authorization_oracle_confirms_matching_cross_identity_canary() -> None:
    result = AuthorizationOracle.evaluate(
        ResponseData(200, body=b'{"id":"canary-a"}'),
        ResponseData(404, body=b"not found"),
        ResponseData(200, body=b'{"id":"canary-a"}'),
    )
    assert result.state is ProofState.CONFIRMED


def test_authorization_oracle_rejects_denied_cross_identity_request() -> None:
    result = AuthorizationOracle.evaluate(
        ResponseData(200, body=b'{"id":"canary-a"}'),
        ResponseData(404, body=b"not found"),
        ResponseData(403, body=b"forbidden"),
    )
    assert result.state is ProofState.REJECTED
