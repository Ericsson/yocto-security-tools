# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""One monotonic deadline shared by native backend host operations."""
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Optional


class RuntimeTimeoutError(TimeoutError):
    """A native operation exhausted its allowed share of the session time."""

    def __init__(self, message: str,
                 payload: Optional[dict[str, object]] = None) -> None:
        super().__init__(message)
        self.payload = payload


@dataclass(frozen=True)
class SessionDeadline:
    """Immutable end time backed by an injectable monotonic clock."""

    expires_at: float
    clock: Callable[[], float] = time.monotonic

    @classmethod
    def from_timeout(cls, timeout_seconds: float,
                     clock: Callable[[], float] = time.monotonic) -> "SessionDeadline":
        """Create one deadline without refreshing it on later operations."""
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
            raise ValueError("session timeout must be a number")
        if timeout_seconds <= 0:
            raise ValueError("session timeout must be positive")
        return cls(clock() + float(timeout_seconds), clock)

    def remaining(self) -> float:
        """Return nonnegative seconds left in the original session budget."""
        return max(0.0, self.expires_at - self.clock())

    @property
    def expired(self) -> bool:
        """Return whether no session time remains."""
        return self.remaining() <= 0.0

    def require(self, operation: str) -> float:
        """Return remaining seconds or reject new work after expiry."""
        remaining = self.remaining()
        if remaining <= 0.0:
            raise RuntimeTimeoutError(
                f"session deadline exhausted before {operation}")
        return remaining
