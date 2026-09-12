"""Target session runtime tests."""

from __future__ import annotations

import asyncio

import pytest

from safescope_core.policy import RequestDescriptor, ResponseData
from safescope_core.vault.credential import CredentialVault, SecretString
from safescope_scanners.session import (
    HealthProbe,
    LoginProfile,
    LoginStep,
    SessionRuntime,
    SessionUnavailable,
    SuccessPredicate,
)


class FakeChannel:
    def __init__(self) -> None:
        self.logged_in = False
        self.closed = False
        self.requests: list[RequestDescriptor] = []

    async def request(self, descriptor: RequestDescriptor) -> ResponseData:
        self.requests.append(descriptor)
        if descriptor.url.endswith("/login") and descriptor.body == b'{"password":"correct"}':
            self.logged_in = True
            return ResponseData(200, body=b"welcome")
        if descriptor.url.endswith("/me"):
            return ResponseData(200 if self.logged_in else 401, body=b"alive" if self.logged_in else b"")
        return ResponseData(200 if self.logged_in else 401)

    async def aclose(self) -> None:
        self.closed = True


def _profile() -> LoginProfile:
    return LoginProfile(
        identity="owner",
        role="analyst",
        steps=(
            LoginStep(
                "POST",
                "https://target.test/login",
                (("content-type", "application/json"),),
                '{"password":"${secret:owner_password}"}',
            ),
        ),
        success=SuccessPredicate((200,), "welcome"),
        health=HealthProbe("https://target.test/me", (200,), "alive"),
        max_relogins=1,
    )


def test_session_uses_vault_checks_health_and_wipes_on_close() -> None:
    async def run() -> None:
        vault = CredentialVault()
        secret = SecretString("correct")
        vault.put("run-1", "owner_password", secret)
        channel = FakeChannel()
        runtime = SessionRuntime("run-1", vault, lambda _identity: channel)
        await runtime.open(_profile())
        response = await runtime.request("owner", RequestDescriptor("GET", "https://target.test/private"))
        assert response.status_code == 200
        assert [item.url for item in channel.requests] == [
            "https://target.test/login",
            "https://target.test/me",
            "https://target.test/private",
        ]
        assert "correct" not in repr(runtime.session("owner"))
        await runtime.aclose()
        assert channel.closed is True
        assert secret.is_wiped is True

    asyncio.run(run())


def test_expired_session_relogs_in_once_then_fails_closed() -> None:
    async def run() -> None:
        vault = CredentialVault()
        vault.put("run-2", "owner_password", SecretString("correct"))
        channel = FakeChannel()
        runtime = SessionRuntime("run-2", vault, lambda _identity: channel)
        await runtime.open(_profile())

        channel.logged_in = False
        await runtime.assert_alive("owner")
        assert runtime.session("owner").relogins == 1

        channel.logged_in = False
        with pytest.raises(SessionUnavailable, match="re-login limit"):
            await runtime.assert_alive("owner")
        await runtime.aclose()

    asyncio.run(run())
