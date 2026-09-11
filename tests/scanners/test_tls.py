"""TLS Scanner tests — parser only, no real TLS connections.

Tests feed synthetic TLSInfo to analyze_tls() and verify observations.
Deterministic, offline, tests the logic.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from safescope_scanners.base import Severity
from safescope_scanners.tls import TLSInfo, analyze_tls

URL = "https://example.com"
NOW = datetime.now(UTC)


class TestTLSCertExpiration:
    def test_expired_cert_is_critical(self) -> None:
        info = TLSInfo(
            protocol_version="TLSv1.3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            cert_not_after=NOW - timedelta(days=10),
        )
        obs = analyze_tls(info, URL)
        critical = [o for o in obs if o.severity == Severity.CRITICAL]
        assert len(critical) == 1
        assert "expired" in critical[0].title.lower()

    def test_expiring_soon_is_medium(self) -> None:
        info = TLSInfo(
            protocol_version="TLSv1.3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            cert_not_after=NOW + timedelta(days=15),
        )
        obs = analyze_tls(info, URL)
        medium = [o for o in obs if o.severity == Severity.MEDIUM]
        assert any("expiring" in o.title.lower() for o in medium)

    def test_valid_cert_no_critical(self) -> None:
        info = TLSInfo(
            protocol_version="TLSv1.3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            cert_not_after=NOW + timedelta(days=365),
            has_hsts=True,
            hsts_max_age=31_536_000,
        )
        obs = analyze_tls(info, URL)
        critical = [o for o in obs if o.severity == Severity.CRITICAL]
        assert len(critical) == 0


class TestTLSProtocol:
    def test_tls10_is_high(self) -> None:
        info = TLSInfo(
            protocol_version="TLSv1.0",
            cipher_name="AES128-SHA",
            cipher_bits=128,
            cert_not_after=NOW + timedelta(days=365),
            has_hsts=True,
            hsts_max_age=31_536_000,
        )
        obs = analyze_tls(info, URL)
        high = [o for o in obs if o.severity == Severity.HIGH]
        assert any("weak" in o.title.lower() and "protocol" in o.title.lower() for o in high)

    def test_tls11_is_high(self) -> None:
        info = TLSInfo(protocol_version="TLSv1.1", has_hsts=True, hsts_max_age=31_536_000)
        obs = analyze_tls(info, URL)
        assert any(o.severity == Severity.HIGH and "protocol" in o.title.lower() for o in obs)

    def test_tls13_no_protocol_warning(self) -> None:
        info = TLSInfo(
            protocol_version="TLSv1.3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            cert_not_after=NOW + timedelta(days=365),
            has_hsts=True,
            hsts_max_age=31_536_000,
        )
        obs = analyze_tls(info, URL)
        assert not any("protocol" in o.title.lower() and o.severity == Severity.HIGH for o in obs)


class TestTLSCipher:
    def test_rc4_cipher_is_high(self) -> None:
        info = TLSInfo(
            protocol_version="TLSv1.2",
            cipher_name="RC4-SHA",
            cipher_bits=128,
            cert_not_after=NOW + timedelta(days=365),
            has_hsts=True,
            hsts_max_age=31_536_000,
        )
        obs = analyze_tls(info, URL)
        assert any("cipher" in o.title.lower() and o.severity == Severity.HIGH for o in obs)


class TestTLSHSTS:
    def test_missing_hsts_is_medium(self) -> None:
        info = TLSInfo(
            protocol_version="TLSv1.3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            cert_not_after=NOW + timedelta(days=365),
            has_hsts=False,
        )
        obs = analyze_tls(info, URL)
        assert any("hsts" in o.title.lower() and o.severity == Severity.MEDIUM for o in obs)

    def test_short_hsts_is_low(self) -> None:
        info = TLSInfo(
            protocol_version="TLSv1.3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            cert_not_after=NOW + timedelta(days=365),
            has_hsts=True,
            hsts_max_age=3600,  # 1 hour, too short
        )
        obs = analyze_tls(info, URL)
        assert any("hsts" in o.title.lower() and "short" in o.title.lower() for o in obs)


class TestTLSSelfSigned:
    def test_self_signed_is_high(self) -> None:
        info = TLSInfo(
            protocol_version="TLSv1.3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            cert_not_after=NOW + timedelta(days=365),
            cert_is_self_signed=True,
            cert_subject={"commonName": "localhost"},
            cert_issuer={"commonName": "localhost"},
            has_hsts=True,
            hsts_max_age=31_536_000,
        )
        obs = analyze_tls(info, URL)
        assert any("self-signed" in o.title.lower() for o in obs)


class TestTLSConnectionError:
    def test_connection_error_is_critical(self) -> None:
        info = TLSInfo(error="Connection refused")
        obs = analyze_tls(info, URL)
        assert len(obs) == 1
        assert obs[0].severity == Severity.CRITICAL
        assert "failed" in obs[0].title.lower()


class TestTLSAllGood:
    def test_all_good_returns_info(self) -> None:
        info = TLSInfo(
            protocol_version="TLSv1.3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            cert_not_after=NOW + timedelta(days=365),
            has_hsts=True,
            hsts_max_age=31_536_000,
        )
        obs = analyze_tls(info, URL)
        assert len(obs) == 1
        assert obs[0].severity == Severity.INFO
        assert "adequate" in obs[0].title.lower()
