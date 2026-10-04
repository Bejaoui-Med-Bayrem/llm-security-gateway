import threading
import time
from collections import deque


class LoginRateLimiter:
    """
    Counts failed logins in a sliding window.

    Two limits:
        - per (client IP, email): stops guessing one account's password
        - per client IP: stops trying one password across many accounts

    Both keys include the client IP, so an attacker cannot lock a victim
    out of their own account from the victim's address.

    State is in memory: it resets on restart and is not shared between
    worker processes. Behind a reverse proxy, the client IP is the
    proxy's unless uvicorn is started with --proxy-headers.
    """

    def __init__(
        self,
        max_failures_per_account: int = 5,
        max_failures_per_ip: int = 20,
        window_seconds: int = 15 * 60,
    ):
        self.max_failures_per_account = max_failures_per_account
        self.max_failures_per_ip = max_failures_per_ip
        self.window_seconds = window_seconds

        self._failures: dict[tuple, deque[float]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _keys(client_ip: str, email: str) -> tuple[tuple, tuple]:
        return ("account", client_ip, email.lower()), ("ip", client_ip)

    def _recent(self, key: tuple, now: float) -> deque[float]:
        failures = self._failures.get(key)

        if failures is None:
            return deque()

        while failures and failures[0] <= now - self.window_seconds:
            failures.popleft()

        if not failures:
            del self._failures[key]

        return failures

    def retry_after(self, client_ip: str, email: str) -> int | None:
        """Seconds until a new attempt is allowed, or None if allowed now."""

        now = time.monotonic()
        account_key, ip_key = self._keys(client_ip, email)

        with self._lock:
            for key, limit in (
                (account_key, self.max_failures_per_account),
                (ip_key, self.max_failures_per_ip),
            ):
                failures = self._recent(key, now)

                if len(failures) >= limit:
                    return int(failures[0] + self.window_seconds - now) + 1

        return None

    def record_failure(self, client_ip: str, email: str) -> None:
        now = time.monotonic()

        with self._lock:
            for key in self._keys(client_ip, email):
                self._failures.setdefault(key, deque()).append(now)

    def reset(self, client_ip: str, email: str) -> None:
        """Clear the account counter after a successful login."""

        account_key, _ = self._keys(client_ip, email)

        with self._lock:
            self._failures.pop(account_key, None)


login_rate_limiter = LoginRateLimiter()
