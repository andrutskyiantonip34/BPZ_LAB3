from __future__ import annotations

import dataclasses


@dataclasses.dataclass
class _State:
    failures: int = 0
    locked_until: float = 0.0


class ProgressiveLockout:
    def __init__(self, free_attempts: int = 3, base_delay: float = 30.0,
                 max_delay: float = 3600.0) -> None:
        self.free_attempts = free_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self._accounts: dict[str, _State] = {}

    def delay_for(self, failures: int) -> float:
        if failures < self.free_attempts:
            return 0.0
        exponent = min(failures - self.free_attempts, 64)
        return min(self.base_delay * 2 ** exponent, self.max_delay)

    def record_attempt(self, account: str, ok: bool, now: float) -> None:
        state = self._accounts.setdefault(account, _State())
        if ok:
            state.failures = 0
            state.locked_until = 0.0
            return
        state.failures += 1
        state.locked_until = now + self.delay_for(state.failures)

    def is_allowed(self, account: str, now: float) -> bool:
        state = self._accounts.get(account)
        return state is None or now >= state.locked_until

    def remaining(self, account: str, now: float) -> float:
        state = self._accounts.get(account)
        return 0.0 if state is None else max(0.0, state.locked_until - now)


_default = ProgressiveLockout()


def record_attempt(account: str, ok: bool, now: float) -> None:
    _default.record_attempt(account, ok, now)


def is_allowed(account: str, now: float) -> bool:
    return _default.is_allowed(account, now)
