"""Bounded, safety-gated HTTP execution for the audit engine.

Two guarantees the probes rely on:

* **Budget**: every audit has a hard request ceiling. A probe that asks for
  one more request than the budget allows gets :class:`BudgetExhausted`, not a
  silently skipped check, so the report can say what was not run.
* **Safety**: a request whose method can change server state is refused
  unless the caller explicitly opted in. Probes mark themselves ``mutating``;
  the executor is the single place that decides whether they may run.
"""
from __future__ import annotations

import time

import httpx

from ..discovery import check_headers, check_url, read_bounded
from .model import Exchange

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
MAX_RESPONSE_BYTES = 512 * 1024


class BudgetExhausted(RuntimeError):
    """Raised when a probe asks for a request the audit budget cannot fund."""


class MutationRefused(RuntimeError):
    """Raised when a state-changing request is attempted without consent."""


class Budget:
    def __init__(self, limit: int) -> None:
        self.limit = max(1, int(limit))
        self.spent = 0
        self.refused = 0
        # Probes check affordability before asking, so a skipped probe never
        # raises. Count the refusals too, or the report cannot say what was cut.
        self.declined = 0

    def take(self, count: int = 1) -> None:
        if self.spent + count > self.limit:
            self.refused += count
            raise BudgetExhausted(f"Audit request budget of {self.limit} is exhausted")
        self.spent += count

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.spent)

    def can_afford(self, count: int = 1) -> bool:
        affordable = self.spent + count <= self.limit
        if not affordable:
            self.declined += 1
        return affordable


class Executor:
    """Sends audit probes over one httpx client with a shared budget."""

    def __init__(self, client: httpx.Client, budget: Budget, *, timeout: float = 15.0,
                 allow_mutating: bool = False) -> None:
        self.client = client
        self.budget = budget
        self.timeout = timeout
        self.allow_mutating = allow_mutating
        self.exchanges: list[Exchange] = []

    def affordable(self, count: int = 1) -> bool:
        return self.budget.can_afford(count)

    def send(self, method: str, url: str, *, label: str, headers: dict | None = None,
             body: str | bytes | None = None, content_type: str | None = None,
             identity: str = "anonymous", mutating: bool | None = None,
             follow_redirects: bool = False) -> Exchange:
        method = method.upper()
        is_mutating = (method not in SAFE_METHODS) if mutating is None else bool(mutating)
        if is_mutating and not self.allow_mutating:
            raise MutationRefused(
                f"{method} probes change server state; enable write probes to run “{label}”."
            )
        url = check_url(url)
        sent_headers = check_headers(dict(headers or {}))
        if body is not None and content_type and not any(
            name.lower() == "content-type" for name in sent_headers
        ):
            sent_headers["Content-Type"] = content_type

        payload: dict = {}
        if body is not None:
            payload["content"] = body.encode("utf-8") if isinstance(body, str) else body

        exchange = Exchange(
            label=label, method=method, url=url,
            request_headers=sent_headers,
            request_body=body if isinstance(body, str) else None,
            mutating=is_mutating, identity=identity,
        )
        self.budget.take()
        started = time.monotonic()
        try:
            request = httpx.Request(
                method, url, headers=sent_headers, **payload,
                extensions={"timeout": dict.fromkeys(("connect", "read", "write", "pool"), self.timeout)},
            )
            response = self.client.send(request, stream=True, follow_redirects=follow_redirects, auth=None)
            try:
                raw, truncated = read_bounded(response, MAX_RESPONSE_BYTES, deadline=started + self.timeout)
                exchange.status = response.status_code
                exchange.headers = dict(response.headers)
                exchange.truncated = truncated
                encoding = response.encoding or "utf-8"
            finally:
                response.close()
            try:
                exchange.body = raw.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                exchange.body = raw.decode("utf-8", errors="replace")
            # Record what actually went on the wire, including httpx defaults.
            exchange.request_headers = dict(request.headers)
        except httpx.HTTPError as exc:
            exchange.error = _transport_error(exc)
        except ValueError as exc:
            exchange.error = str(exc)
        exchange.elapsed_ms = round((time.monotonic() - started) * 1000, 2)
        self.exchanges.append(exchange)
        return exchange


def _transport_error(exc: httpx.HTTPError) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return "request timed out"
    if isinstance(exc, httpx.ConnectError):
        return "could not connect"
    return f"transport error: {type(exc).__name__}"


def build_client(verify_tls: bool = True) -> httpx.Client:
    return httpx.Client(verify=verify_tls, trust_env=False)
