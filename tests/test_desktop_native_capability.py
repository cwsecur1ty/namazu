"""Native picker authority is separate from the web session capability."""
import pytest

from namazu import desktop_runtime


@pytest.fixture(autouse=True)
def isolated_runtime(monkeypatch):
    monkeypatch.setattr(desktop_runtime, "_secret", None)
    monkeypatch.setattr(desktop_runtime, "_native_secret", None)
    monkeypatch.setattr(desktop_runtime, "_shutdown", None)


def test_native_authority_never_follows_session_authority():
    desktop_runtime.configure("s" * 64, lambda: None, native_secret="n" * 64)
    assert desktop_runtime.authorize_native("n" * 64)
    assert not desktop_runtime.authorize_native("s" * 64)
    assert not desktop_runtime.authorize_native(None)
    assert not desktop_runtime.authorize_native("é" * 64)
    assert not desktop_runtime.authorize_native("n" * 63)
    assert desktop_runtime.session_secret() == "s" * 64


def test_legacy_handshake_does_not_grant_filesystem_authority():
    desktop_runtime.configure("s" * 64, lambda: None)
    assert desktop_runtime.is_desktop()
    assert not desktop_runtime.authorize_native("s" * 64)
    assert not desktop_runtime.authorize_native("")


def test_new_instance_revokes_previous_native_capability():
    desktop_runtime.configure("s" * 64, lambda: None, native_secret="n" * 64)
    desktop_runtime.configure("t" * 64, lambda: None)
    assert not desktop_runtime.authorize_native("n" * 64)


@pytest.mark.parametrize("native", ["s" * 64, "short", "n" * 257, "é" * 64, "n/" * 32, 12])
def test_invalid_or_shared_capability_fails_before_configuration(native):
    with pytest.raises(ValueError, match="Invalid native desktop capability"):
        desktop_runtime.configure("s" * 64, lambda: None, native_secret=native)
    assert not desktop_runtime.is_desktop()
    assert not desktop_runtime.authorize_native("s" * 64)
