"""Phase 2 passive-analysis tests."""

from safescope_core.models import normalize_observations
from safescope_core.scoring import Confidence, ScoreInput, calculate_security_score
from safescope_scanners.base import RawObservation, Severity
from safescope_scanners.cookies import analyze_cookies
from safescope_scanners.cors import analyze_cors
from safescope_scanners.javascript import extract_javascript_references
from safescope_scanners.technology import detect_technologies


def test_cookie_flags_are_observed_without_recording_cookie_value() -> None:
    observations = analyze_cookies("session=private; Path=/", "https://acme.example")
    assert {item.evidence["missing"] for item in observations} == {"secure", "httponly", "samesite"}
    assert all("private" not in str(item.evidence) for item in observations)


def test_cors_wildcard_with_credentials_is_high() -> None:
    observations = analyze_cors(
        {"access-control-allow-origin": "*", "access-control-allow-credentials": "true"},
        "https://acme.example",
    )
    assert observations[0].severity is Severity.HIGH


def test_frontend_references_and_technologies_are_passively_extracted() -> None:
    page = b'<script src="/_next/app.js"></script><a href="/api/v1/me">me</a>'
    references = extract_javascript_references(page, "https://acme.example")
    assert references["scripts"] == ["https://acme.example/_next/app.js"]
    assert references["endpoints"] == ["/api/v1/me"]
    assert detect_technologies({}, page) == {"Next.js"}


def test_normalization_redacts_and_deduplicates_evidence() -> None:
    observations = [
        RawObservation("Header", Severity.LOW, "https://acme.example", "detail", 0.5, {"token": "x"}),
        RawObservation("Header", Severity.LOW, "https://acme.example", "detail", 0.9, {"token": "y"}),
    ]
    findings = normalize_observations(observations)
    assert len(findings) == 1
    assert findings[0].confidence == 0.9
    assert findings[0].evidence == {"token": "[REDACTED]"}


def test_score_is_confidence_weighted_and_capped() -> None:
    score = calculate_security_score(
        [ScoreInput("HIGH", Confidence.CONFIRMED), ScoreInput("MEDIUM", Confidence.POTENTIAL)]
    )
    assert score.value == 76
