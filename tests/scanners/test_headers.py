"""Security Headers Scanner tests — pure parser, no I/O.

Tests feed synthetic header dicts to analyze_headers() and verify observations.
"""

from __future__ import annotations

from safescope_scanners.base import Severity
from safescope_scanners.headers import analyze_headers

URL = "https://example.com"


def _all_secure_headers() -> dict[str, str]:
    """Headers that represent a well-configured server."""
    return {
        "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
        "content-security-policy": "default-src 'self'; script-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=(), microphone=(), geolocation=()",
        "cache-control": "no-store",
    }


class TestMissingHeaders:
    def test_no_csp_is_high(self) -> None:
        headers = _all_secure_headers()
        del headers["content-security-policy"]
        obs = analyze_headers(headers, URL)
        assert any(o.severity == Severity.HIGH and "content-security-policy" in o.title.lower() for o in obs)

    def test_no_hsts_is_medium(self) -> None:
        headers = _all_secure_headers()
        del headers["strict-transport-security"]
        obs = analyze_headers(headers, URL)
        assert any(o.severity == Severity.MEDIUM and "hsts" in o.title.lower() for o in obs)

    def test_no_x_frame_options_is_medium(self) -> None:
        headers = _all_secure_headers()
        del headers["x-frame-options"]
        obs = analyze_headers(headers, URL)
        assert any(o.severity == Severity.MEDIUM and "x-frame-options" in o.title.lower() for o in obs)

    def test_no_x_content_type_options_is_low(self) -> None:
        headers = _all_secure_headers()
        del headers["x-content-type-options"]
        obs = analyze_headers(headers, URL)
        assert any(o.severity == Severity.LOW and "x-content-type-options" in o.title.lower() for o in obs)

    def test_all_missing_produces_multiple_observations(self) -> None:
        obs = analyze_headers({}, URL)
        # Should flag all missing security headers
        assert len(obs) >= 6  # 6 security headers + cache-control


class TestInfoLeakHeaders:
    def test_server_with_version_is_low(self) -> None:
        headers = _all_secure_headers()
        headers["server"] = "Apache/2.4.52 (Ubuntu)"
        obs = analyze_headers(headers, URL)
        assert any(o.severity == Severity.LOW and "server" in o.title.lower() for o in obs)

    def test_x_powered_by_is_low(self) -> None:
        headers = _all_secure_headers()
        headers["x-powered-by"] = "Express 4.18.2"
        obs = analyze_headers(headers, URL)
        assert any("x-powered-by" in o.title.lower() for o in obs)

    def test_server_without_version_not_flagged(self) -> None:
        headers = _all_secure_headers()
        headers["server"] = "nginx"  # no version number
        obs = analyze_headers(headers, URL)
        assert not any("server" in o.title.lower() and "exposes" in o.title.lower() for o in obs)


class TestCSPWeaknesses:
    def test_unsafe_inline_flagged(self) -> None:
        headers = _all_secure_headers()
        headers["content-security-policy"] = "default-src 'self'; script-src 'unsafe-inline'"
        obs = analyze_headers(headers, URL)
        assert any("unsafe-inline" in o.title.lower() for o in obs)

    def test_unsafe_eval_flagged(self) -> None:
        headers = _all_secure_headers()
        headers["content-security-policy"] = "default-src 'self'; script-src 'unsafe-eval'"
        obs = analyze_headers(headers, URL)
        assert any("unsafe-eval" in o.title.lower() for o in obs)

    def test_wildcard_source_flagged(self) -> None:
        headers = _all_secure_headers()
        headers["content-security-policy"] = "default-src *"
        obs = analyze_headers(headers, URL)
        assert any("*" in o.title for o in obs)


class TestDeprecatedHeaders:
    def test_xss_protection_enabled_flagged(self) -> None:
        headers = _all_secure_headers()
        headers["x-xss-protection"] = "1; mode=block"
        obs = analyze_headers(headers, URL)
        assert any("deprecated" in o.title.lower() and "xss" in o.title.lower() for o in obs)

    def test_xss_protection_zero_not_flagged(self) -> None:
        headers = _all_secure_headers()
        headers["x-xss-protection"] = "0"
        obs = analyze_headers(headers, URL)
        assert not any("xss-protection" in o.title.lower() for o in obs)


class TestAllSecure:
    def test_all_headers_present_returns_info(self) -> None:
        headers = _all_secure_headers()
        obs = analyze_headers(headers, URL)
        # Should only have INFO-level observations (all good)
        assert all(o.severity in (Severity.INFO,) for o in obs)
        assert any("adequate" in o.title.lower() for o in obs)


class TestCaseInsensitivity:
    def test_headers_are_case_insensitive(self) -> None:
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=()",
            "Cache-Control": "no-store",
        }
        obs = analyze_headers(headers, URL)
        # Mixed case headers should still be recognized
        missing = [o for o in obs if "missing" in o.title.lower() and o.severity != Severity.INFO]
        assert len(missing) == 0
