"""CredentialVault tests — TTL, wipe, masking, drop."""

from __future__ import annotations

import time

import pytest

from safescope_core.vault.credential import CredentialVault, SecretString


class TestSecretString:
    def test_value_accessible(self) -> None:
        s = SecretString("hunter2", ttl_seconds=60, name="password")
        assert s.value == "hunter2"

    def test_repr_masked(self) -> None:
        s = SecretString("supersecret", name="api_key")
        assert "supersecret" not in repr(s)
        assert "api_key" in repr(s)
        assert "supersecret" not in str(s)

    def test_ttl_expired_raises(self) -> None:
        s = SecretString("temp", ttl_seconds=0, name="short")
        time.sleep(0.01)
        with pytest.raises(RuntimeError, match="expired"):
            _ = s.value

    def test_wipe_zeros_buffer(self) -> None:
        s = SecretString("sensitive_data", name="token")
        s.wipe()
        with pytest.raises(RuntimeError, match="wiped"):
            _ = s.value

    def test_wipe_clears_bytearray(self) -> None:
        s = SecretString("test123", name="pw")
        # Access the internal buffer before wipe
        assert len(s._buf) > 0
        s.wipe()
        assert len(s._buf) == 0
        assert s._wiped is True

    def test_is_alive(self) -> None:
        s = SecretString("alive", ttl_seconds=60, name="x")
        assert s.is_alive is True
        s.wipe()
        assert s.is_alive is False

    def test_pickle_prevention(self) -> None:
        s = SecretString("no_pickle", name="x")
        with pytest.raises(TypeError, match="cannot be pickled"):
            s.__reduce__()


class TestCredentialVault:
    def test_put_and_get(self) -> None:
        vault = CredentialVault()
        vault.put("run-1", "password", SecretString("s3cret", name="pw"))
        assert vault.get("run-1", "password") == "s3cret"

    def test_get_missing_raises(self) -> None:
        vault = CredentialVault()
        with pytest.raises(KeyError):
            vault.get("nonexistent", "label")

    def test_drop_wipes_all(self) -> None:
        vault = CredentialVault()
        s1 = SecretString("a", name="x")
        s2 = SecretString("b", name="y")
        vault.put("run-1", "x", s1)
        vault.put("run-1", "y", s2)

        count = vault.drop("run-1")
        assert count == 2
        assert s1._wiped is True
        assert s2._wiped is True
        assert "run-1" not in vault.active_runs()

    def test_has_checks_liveness(self) -> None:
        vault = CredentialVault()
        vault.put("run-1", "pw", SecretString("temp", ttl_seconds=0, name="pw"))
        time.sleep(0.01)
        assert vault.has("run-1", "pw") is False

    def test_overwrite_label(self) -> None:
        vault = CredentialVault()
        vault.put("run-1", "token", SecretString("old", name="t"))
        vault.put("run-1", "token", SecretString("new", name="t"))
        assert vault.get("run-1", "token") == "new"

    def test_active_runs(self) -> None:
        vault = CredentialVault()
        vault.put("run-1", "a", SecretString("x", name="a"))
        vault.put("run-2", "b", SecretString("y", name="b"))
        assert set(vault.active_runs()) == {"run-1", "run-2"}
