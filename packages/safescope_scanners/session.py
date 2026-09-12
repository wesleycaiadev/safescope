"""Declarative, scan-scoped sessions for authorized target accounts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from safescope_core.policy import RequestDescriptor, ResponseData

if TYPE_CHECKING:
    from collections.abc import Callable

    from safescope_core.vault.credential import CredentialVault

_SECRET_REF = re.compile(r"\$\{secret:([a-zA-Z0-9_.-]+)\}")


class SessionChannel(Protocol):
    """One isolated cookie jar/network channel for one target identity."""

    async def request(self, descriptor: RequestDescriptor) -> ResponseData: ...

    async def aclose(self) -> None: ...


@dataclass(frozen=True)
class LoginStep:
    method: str
    url: str
    headers: tuple[tuple[str, str], ...] = ()
    body_template: str | None = None
    payload_id: str | None = None


@dataclass(frozen=True)
class SuccessPredicate:
    statuses: tuple[int, ...] = (200,)
    body_marker: str | None = None

    def matches(self, response: ResponseData) -> bool:
        if response.status_code not in self.statuses:
            return False
        if self.body_marker is None:
            return True
        return self.body_marker.encode() in response.body


@dataclass(frozen=True)
class HealthProbe:
    url: str
    statuses: tuple[int, ...] = (200,)
    body_marker: str | None = None


@dataclass(frozen=True)
class LoginProfile:
    identity: str
    role: str
    steps: tuple[LoginStep, ...]
    success: SuccessPredicate
    health: HealthProbe
    max_relogins: int = 3


@dataclass
class AuthContext:
    """Live target session metadata; never contains credential values."""

    profile: LoginProfile
    channel: SessionChannel
    relogins: int = 0


class SessionUnavailable(RuntimeError):
    """A target identity cannot establish or retain an authorized session."""


class SessionRuntime:
    """Own isolated target sessions and assert their health before every use."""

    def __init__(
        self,
        scan_run_id: str,
        vault: CredentialVault,
        channel_factory: Callable[[str], SessionChannel],
    ) -> None:
        self._scan_run_id = scan_run_id
        self._vault = vault
        self._channel_factory = channel_factory
        self._contexts: dict[str, AuthContext] = {}

    async def open(self, profile: LoginProfile) -> AuthContext:
        """Establish one identity without exposing secrets in errors or state."""
        current = self._contexts.pop(profile.identity, None)
        if current is not None:
            await current.channel.aclose()
        channel = self._channel_factory(profile.identity)
        context = AuthContext(profile, channel)
        try:
            await self._login(context)
        except BaseException:
            await channel.aclose()
            raise
        self._contexts[profile.identity] = context
        return context

    def session(self, identity: str) -> AuthContext:
        try:
            return self._contexts[identity]
        except KeyError as error:
            raise SessionUnavailable(f"target identity '{identity}' is not open") from error

    async def assert_alive(self, identity: str) -> None:
        """Health-check a session and perform a bounded re-login when needed."""
        context = self.session(identity)
        probe = context.profile.health
        response = await context.channel.request(RequestDescriptor("GET", probe.url))
        predicate = SuccessPredicate(probe.statuses, probe.body_marker)
        if predicate.matches(response):
            return
        if context.relogins >= context.profile.max_relogins:
            raise SessionUnavailable(f"target identity '{identity}' exceeded its re-login limit")
        context.relogins += 1
        await self._login(context)

    async def request(self, identity: str, descriptor: RequestDescriptor) -> ResponseData:
        """Assert session health immediately before a scanner request."""
        await self.assert_alive(identity)
        return await self.session(identity).channel.request(descriptor)

    async def aclose(self) -> None:
        """Close all cookie jars and wipe every secret scoped to this run."""
        contexts = list(self._contexts.values())
        self._contexts.clear()
        for context in contexts:
            await context.channel.aclose()
        self._vault.drop(self._scan_run_id)

    async def _login(self, context: AuthContext) -> None:
        last_response: ResponseData | None = None
        for step in context.profile.steps:
            headers = {name: self._render(value) for name, value in step.headers}
            body = self._render(step.body_template).encode() if step.body_template is not None else None
            last_response = await context.channel.request(
                RequestDescriptor(
                    method=step.method,
                    url=step.url,
                    headers=headers,
                    body=body,
                    is_probe=step.payload_id is not None,
                    payload_id=step.payload_id,
                )
            )
        if last_response is None or not context.profile.success.matches(last_response):
            raise SessionUnavailable(f"login failed for target identity '{context.profile.identity}'")

    def _render(self, template: str) -> str:
        def replace(match: re.Match[str]) -> str:
            return self._vault.get(self._scan_run_id, match.group(1))

        return _SECRET_REF.sub(replace, template)
