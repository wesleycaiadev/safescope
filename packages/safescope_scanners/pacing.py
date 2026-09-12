"""Bounded request plans and adaptive, observable scan pacing."""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from safescope_core.policy import RequestDescriptor


@dataclass(frozen=True)
class RequestPlan:
    requests: tuple[RequestDescriptor, ...]
    concurrent: bool = False


class AdaptivePacer:
    """Add jitter and halve request rate after repeated WAF/throttle signals."""

    def __init__(
        self,
        max_rps: float,
        *,
        jitter_ratio: float = 0.20,
        clock: Callable[[], float] = time.monotonic,
        random_value: Callable[[], float] = random.random,
    ) -> None:
        self.initial_rps = max(0.1, max_rps)
        self.current_rps = self.initial_rps
        self.jitter_ratio = max(0.0, min(jitter_ratio, 1.0))
        self.soft_mode_entries = 0
        self._signals = 0
        self._clock = clock
        self._random = random_value
        self._last_request_at = 0.0

    def compute_delay(self) -> float:
        interval = 1.0 / self.current_rps
        now = self._clock()
        base = max(0.0, interval - (now - self._last_request_at))
        jitter = interval * self.jitter_ratio * self._random()
        delay = base + jitter
        self._last_request_at = now + delay
        return delay

    def observe(self, status_code: int) -> None:
        if status_code not in {403, 429}:
            self._signals = 0
            return
        self._signals += 1
        if self._signals < 2:
            return
        self.current_rps = max(0.1, self.current_rps / 2.0)
        self.soft_mode_entries += 1
        self._signals = 0
