"""Bounded, safety-gated HTTP execution for the audit engine.

Three guarantees the probes rely on:

* **Budget**: every audit has a hard request ceiling. A probe that asks for
  one more request than the budget allows gets :class:`BudgetExhausted`, not a
  silently skipped check, so the report can say what was not run. The ceiling
  holds under concurrency: the counter is behind a lock, so two threads cannot
  both be sold the last request.
* **Safety**: a request whose method can change server state is refused
  unless the caller explicitly opted in. Probes mark themselves ``mutating``;
  the executor is the single place that decides whether they may run.
* **Order**: :meth:`Executor.fan_out` sends independent probes in parallel but
  merges their exchanges back in submission order, so the request log reads
  identically whether the audit ran with one worker or six. A fan-out is also
  read-only by construction, because a sequence whose steps depend on each
  other, such as writing an object and reading it back, is not safe to
  reorder.
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

import httpx

from ..discovery import (
    Connection,
    check_headers,
    check_url,
    connection_for,
    read_bounded,
)
from ..signature import Signature
from .model import Exchange

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
MAX_RESPONSE_BYTES = 512 * 1024
# A ceiling on workers per audit. This is a security tool pointed at someone
# else's API under an authorisation that covers testing, not load testing, so
# the cap stays low enough that a run cannot be mistaken for an attack.
MAX_CONCURRENCY = 16


class BudgetExhausted(RuntimeError):
    """Raised when a probe asks for a request the audit budget cannot fund."""


class MutationRefused(RuntimeError):
    """Raised when a state-changing request is attempted without consent."""


class RateLimited(MutationRefused):
    """Further requests stopped after an explicit target rate-limit response."""


class Cancelled(BaseException):
    """A run was stopped; no further request may be dispatched.

    Deliberately a :class:`BaseException`, not an :class:`Exception`, so it is
    not swallowed by the broad ``except Exception`` a probe family uses to turn
    an individual probe error into a recorded execution-error. Cancellation is
    not one probe failing: it stops the operation, which then assembles the
    partial evidence it has already captured. ``fan_out`` still catches it
    (``except BaseException``), so exchanges from concurrent workers already in
    flight are merged back before it propagates: a response that arrives after
    the stop is preserved, never discarded.
    """


class Pace:
    """Shared across branches; rate limits apply to the whole run, not a worker.

    When a run passes one :class:`Pace` to every operation's executor, a 429 in
    any operation sets :attr:`stopped` once and stops dispatch everywhere after
    it, and ``cancel`` set on that shared instance interrupts a probe waiting
    out the rate interval instead of letting it sleep to completion.
    """

    def __init__(self, requests_per_second: float | None = None,
                 cancel: threading.Event | None = None):
        self.interval = 1 / requests_per_second if requests_per_second else 0
        self.last = 0.0
        self.stopped = False
        self.cancel = cancel
        self.lock = threading.Lock()

    def wait(self):
        with self.lock:
            if self.cancel is not None and self.cancel.is_set():
                raise Cancelled("The run was stopped; the rate-limit wait was abandoned.")
            if self.stopped:
                raise RateLimited("Target returned HTTP 429; remaining probes are blocked by the rate limit.")
            delay = self.interval - (time.monotonic() - self.last)
            if delay > 0:
                if self.cancel is None:
                    time.sleep(delay)
                else:
                    # With a run-scoped stop signal, sleep in short slices so a
                    # stop set while a probe is pacing is honoured promptly
                    # rather than after a full interval (up to 10s).
                    deadline = time.monotonic() + delay
                    while (remaining := deadline - time.monotonic()) > 0:
                        if self.cancel.is_set():
                            raise Cancelled("The run was stopped; the rate-limit wait was abandoned.")
                        time.sleep(min(remaining, 0.1))
            self.last = time.monotonic()


class Budget:
    """The request ceiling for one audit, shared by every probe in it.

    Every method is atomic. Probes running in parallel draw on the same
    counter, and a ceiling that can be overshot by a race is not a ceiling.

    ``parent`` chains a per-operation budget to one run-wide budget. A take
    succeeds only if both this budget and the parent can fund it, so the run's
    total holds across the inventory sweep, every operation and every worker,
    while each operation still keeps its own smaller per-operation ceiling. The
    parent is charged only when the child take succeeds, so a child that is
    already full never consumes the shared total.
    """

    def __init__(self, limit: int, parent: Budget | None = None) -> None:
        self.limit = max(1, int(limit))
        self.spent = 0
        self.refused = 0
        # Probes check affordability before asking, so a skipped probe never
        # raises. Count the refusals too, or the report cannot say what was cut.
        self.declined = 0
        self.parent = parent
        self._lock = threading.Lock()

    def take(self, count: int = 1) -> None:
        with self._lock:
            if self.spent + count > self.limit:
                self.refused += count
                raise BudgetExhausted(f"Audit request budget of {self.limit} is exhausted")
            if self.parent is not None:
                try:
                    self.parent.take(count)
                except BudgetExhausted:
                    # The operation could still afford it; the run as a whole
                    # could not. Record it here too so the operation's report
                    # shows the request was cut.
                    self.refused += count
                    raise
            self.spent += count

    @property
    def remaining(self) -> int:
        with self._lock:
            own = max(0, self.limit - self.spent)
        if self.parent is not None:
            return min(own, self.parent.remaining)
        return own

    def can_afford(self, count: int = 1) -> bool:
        with self._lock:
            affordable = self.spent + count <= self.limit
        if affordable and self.parent is not None:
            affordable = self.parent.can_afford(count)
        if not affordable:
            with self._lock:
                self.declined += 1
        return affordable


class Executor:
    """Sends audit probes over one httpx client with a shared budget."""

    def __init__(self, client: httpx.Client, budget: Budget, *, timeout: float = 15.0,
                 allow_mutating: bool = False, concurrency: int = 1,
                 signature: Signature | None = None, scope_url: str | None = None,
                 requests_per_second: float | None = None,
                 pace: Pace | None = None,
                 cancel: threading.Event | None = None,
                 write_withdrawn: threading.Event | None = None,
                 receipts: object | None = None) -> None:
        self.client = client
        self.budget = budget
        self.timeout = timeout
        self.allow_mutating = allow_mutating
        self.concurrency = max(1, min(int(concurrency or 1), MAX_CONCURRENCY))
        # What the probes put their name on. Every probe already receives the
        # executor, so this is how one decision reaches all of them, and why a
        # branch shares the instance rather than making its own: a control and
        # its probe have to carry the same marker.
        self.signature = signature or Signature()
        self.exchanges: list[Exchange] = []
        self.probe_results: list[dict] = []
        # Per-branch affordability failures let a probe distinguish its own
        # budget gap from a concurrent sibling's refused request.
        self.budget_declines = 0
        self.scope_url = scope_url
        # A run passes ONE Pace so the rate limit and the 429 kill-switch are
        # shared across every operation; a single operation builds its own.
        self.pace = pace or Pace(requests_per_second, cancel=cancel)
        # A run-scoped stop signal, checked before every dispatch so a stop is
        # honoured inside an operation, not only between operations.
        self.cancel = cancel
        # Set when write authorisation is withdrawn mid-run: already-authorised
        # write probes are refused from that point, the run keeps going.
        self.write_withdrawn = write_withdrawn
        # A durable receipt sink. ``dispatch`` is called with the Exchange just
        # before it goes on the wire (returns a stable id); ``settle`` is called
        # once the outcome is known. A process death between the two leaves a
        # dispatched-but-unsettled receipt: honestly interrupted, never replayed.
        self.receipts = receipts
        self.redacted_names: set[str] = set()

    def affordable(self, count: int = 1) -> bool:
        affordable = self.budget.can_afford(count)
        if not affordable:
            self.budget_declines += 1
        return affordable

    def branch(self) -> Executor:
        """A child executor sharing this one's client and budget.

        Each branch keeps its own exchange list, so one thread owns it and no
        lock is needed to record a request. Branches never mutate and never
        fan out again, which bounds a run to ``concurrency`` requests in
        flight no matter how deeply the probes nest.
        """
        child = Executor(self.client, self.budget, timeout=self.timeout,
                         allow_mutating=False, concurrency=1, signature=self.signature,
                         scope_url=self.scope_url)
        child.pace = self.pace
        child.cancel = self.cancel
        child.write_withdrawn = self.write_withdrawn
        child.receipts = self.receipts
        child.redacted_names = self.redacted_names
        return child

    def fan_out(self, items, worker):
        """Run ``worker(executor, item)`` over independent items, in parallel.

        Returns one result per item, in item order, with ``None`` where the
        budget ran out before that item could run. Exchanges are merged into
        this executor in item order too: a concurrent run and a serial run
        produce the same request log, so a finding's evidence reads the same
        either way.

        Only for work whose items do not depend on each other. Branches refuse
        state-changing requests, so a write sequence cannot be parallelised by
        accident.
        """
        items = list(items)
        if not items:
            return []
        if self.concurrency == 1 or len(items) == 1:
            results = []
            for item in items:
                branch = self.branch()
                try:
                    results.append(worker(branch, item))
                except BudgetExhausted:
                    results.append(None)
                finally:
                    self.exchanges.extend(branch.exchanges)
                    self.probe_results.extend(branch.probe_results)
            return results

        branches = [self.branch() for _ in items]
        results: list = [None] * len(items)
        failure: BaseException | None = None
        workers = min(self.concurrency, len(items))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="namazu-probe") as pool:
            futures = [pool.submit(worker, branches[index], item)
                       for index, item in enumerate(items)]
            for index, future in enumerate(futures):
                try:
                    results[index] = future.result()
                except BudgetExhausted:
                    results[index] = None
                except BaseException as exc:
                    failure = failure or exc
        # Merge after every worker has finished, in item order.
        for branch in branches:
            self.exchanges.extend(branch.exchanges)
            self.probe_results.extend(branch.probe_results)
        if failure is not None:
            raise failure
        return results

    def send(self, method: str, url: str, *, label: str, headers: dict | None = None,
             body: str | bytes | None = None, content_type: str | None = None,
             identity: str = "anonymous", mutating: bool | None = None,
             follow_redirects: bool = False) -> Exchange:
        method = method.upper()
        # Checked before anything is built or counted, so a stop prevents a new
        # dispatch even in the middle of an operation. A request already on the
        # wire is not touched: its response is still captured below.
        if self.cancel is not None and self.cancel.is_set():
            raise Cancelled("The run was stopped; no further requests were dispatched.")
        is_mutating = (method not in SAFE_METHODS) if mutating is None else bool(mutating)
        if is_mutating and not self.allow_mutating:
            raise MutationRefused(
                f"{method} probes change server state; enable write probes to run “{label}”."
            )
        if is_mutating and self.write_withdrawn is not None and self.write_withdrawn.is_set():
            raise MutationRefused(
                f"Write authorisation was withdrawn during the run; “{label}” was not dispatched."
            )
        url = check_url(url)
        if self.scope_url:
            scoped, target = urlsplit(self.scope_url), urlsplit(url)
            if (scoped.scheme, scoped.hostname, scoped.port) != (target.scheme, target.hostname, target.port):
                raise MutationRefused("Request is outside the selected target origin.")
        self.pace.wait()
        sent_headers = check_headers(dict(headers or {}))
        # The Request is built by hand so a client cookie jar cannot follow a
        # probe, which also means the client's default headers do not apply. The
        # identity has to be stamped on here, and a User-Agent an operator set
        # on the Headers tab still wins.
        if not any(name.lower() == "user-agent" for name in sent_headers):
            carried = self.client.headers.get("user-agent")
            if carried:
                sent_headers["User-Agent"] = carried
        if body is not None and content_type and not any(
            name.lower() == "content-type" for name in sent_headers
        ):
            sent_headers["Content-Type"] = content_type

        payload: dict = {}
        if body is not None:
            payload["content"] = body.encode("utf-8") if isinstance(body, str) else body

        # Workspace clients enforce the reviewed credential origin/base-path
        # after pacing and before budget/receipts, so removal of an assignment
        # while a probe waits cannot dispatch the old credential afterwards.
        scope_guard = getattr(self.client, "check_request_scope", None)
        if scope_guard is not None:
            scope_guard(url, sent_headers)
        # Scope review can wait for a workspace edit/import lock. Honour any
        # stop, 429 or write withdrawal that arrived while that guard waited.
        if self.cancel is not None and self.cancel.is_set():
            raise Cancelled("The run was stopped before dispatch.")
        if self.pace.stopped:
            raise RateLimited("Target returned HTTP 429; no further request was dispatched.")
        if is_mutating and self.write_withdrawn is not None and self.write_withdrawn.is_set():
            raise MutationRefused("Write authorisation was withdrawn before dispatch.")

        exchange = Exchange(
            label=label, method=method, url=url,
            request_headers=sent_headers,
            request_body=body if isinstance(body, str) else None,
            mutating=is_mutating, identity=identity,
        )
        exchange.redacted_names = self.redacted_names
        self.budget.take()
        # The receipt is written here, before the request leaves, and marked
        # ``dispatched``. If the process dies before the outcome is recorded,
        # that receipt stays dispatched-with-no-outcome: on restart the run is
        # interrupted and this request is "outcome unknown", never re-sent.
        exchange.outcome = "dispatched"
        if self.receipts is not None:
            exchange.exchange_id = self.receipts.dispatch(exchange) or exchange.exchange_id
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
                if response.status_code == 429:
                    self.pace.stopped = True
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
            exchange.outcome = "responded"
        except httpx.HTTPError as exc:
            exchange.error = _transport_error(exc)
            exchange.outcome = "timed-out" if isinstance(exc, httpx.TimeoutException) else "transport-error"
        except ValueError as exc:
            exchange.error = str(exc)
            exchange.outcome = "transport-error"
        exchange.elapsed_ms = round((time.monotonic() - started) * 1000, 2)
        if self.receipts is not None:
            self.receipts.settle(exchange.exchange_id, exchange)
        self.exchanges.append(exchange)
        return exchange


def _transport_error(exc: httpx.HTTPError) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return "request timed out"
    if isinstance(exc, httpx.ConnectError):
        return "could not connect"
    return f"transport error: {type(exc).__name__}"


def build_client(verify_tls: bool = True, user_agent: str | None = None,
                 connection: Connection | None = None) -> httpx.Client:
    """One client per audit, carrying Namazu's outbound identity and route.

    A header set on an individual probe still wins over this, so an operator
    who puts a User-Agent on the Headers tab keeps it.
    """
    return connection_for(connection, verify_tls, user_agent).open()
