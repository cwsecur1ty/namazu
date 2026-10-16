"""Private in-memory capability belonging to one native desktop instance."""
from __future__ import annotations

import secrets
import threading
from collections.abc import Callable

SESSION_HEADER = "X-Namazu-Session"
NATIVE_HEADER = "X-Namazu-Native"
_secret: str | None = None
_native_secret: str | None = None
_shutdown: Callable[[], None] | None = None
_lock = threading.Lock()


def configure(secret: str, shutdown: Callable[[], None], *, native_secret: str | None = None) -> None:
    if not isinstance(secret, str) or len(secret) < 32 or len(secret) > 256 or not secret.isascii() or not secret.isalnum():
        raise ValueError("Invalid desktop instance capability")
    if native_secret is not None and (not isinstance(native_secret, str) or not 32 <= len(native_secret) <= 256
            or not native_secret.isascii() or not native_secret.isalnum() or secrets.compare_digest(secret, native_secret)):
        raise ValueError("Invalid native desktop capability")
    global _secret, _native_secret, _shutdown
    with _lock:
        _secret, _native_secret, _shutdown = secret, native_secret, shutdown


def authorize_native(value: str | None) -> bool:
    """Authorize a native picker request; renderer session authority is insufficient."""
    with _lock:
        expected = _native_secret
    return bool(expected and isinstance(value, str) and value.isascii() and secrets.compare_digest(expected, value))


def is_desktop() -> bool:
    return _secret is not None


def session_secret() -> str:
    return _secret or ""


def request_shutdown() -> None:
    with _lock:
        callback = _shutdown
    if callback is not None:
        callback()
