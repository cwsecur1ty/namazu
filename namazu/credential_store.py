"""Explicit session or current-user Windows DPAPI credential storage.

Only encrypted DPAPI blobs and opaque references are written to disk. There is
no plaintext fallback, token acquisition or network access. Windows protection
uses CryptProtectData/UnprotectData with UI forbidden and without the machine
scope flag: https://learn.microsoft.com/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
"""
from __future__ import annotations

import base64
import ctypes
import json
import os
import threading
from pathlib import Path

from .desktop_state import atomic_write, data_paths, file_lock

FORMAT = "namazu-credentials"
VERSION = 1


class CredentialStoreError(RuntimeError):
    """Unavailable or unreadable storage, with no secret material in messages."""


class DPAPIProvider:
    name = "windows-dpapi"

    def _transform(self, data: bytes, context: bytes, *, decrypt=False) -> bytes:
        if os.name != "nt":
            raise CredentialStoreError("Windows credential persistence is unavailable on this platform; choose session-only storage.")
        from ctypes import wintypes
        class Blob(ctypes.Structure):
            _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]
        buffer = ctypes.create_string_buffer(data)
        entropy = ctypes.create_string_buffer(context)
        source = Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
        binding = Blob(len(context), ctypes.cast(entropy, ctypes.POINTER(ctypes.c_ubyte)))
        target = Blob()
        crypt = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        function = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
        function.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p if decrypt else wintypes.LPCWSTR,
                             ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
                             wintypes.DWORD, ctypes.POINTER(Blob)]
        function.restype = wintypes.BOOL
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        if not function(ctypes.byref(source), None, ctypes.byref(binding), None, None, 1, ctypes.byref(target)):
            raise CredentialStoreError("Windows could not unlock this credential for the current user; re-enter it or choose session-only storage.")
        try:
            return ctypes.string_at(target.data, target.size)
        finally:
            if target.data:
                # Clear decrypted buffers before releasing Windows-owned memory.
                if decrypt:
                    ctypes.memset(target.data, 0, target.size)
                kernel.LocalFree(target.data)

    def protect(self, data, context):
        return self._transform(data, context)

    def unprotect(self, data, context):
        return self._transform(data, context, decrypt=True)


class CredentialStore:
    def __init__(self, directory: str | Path | None = None, *, provider=None):
        self.directory = Path(directory) if directory else data_paths().secrets
        self.path = self.directory / "credentials.json"
        self.provider = provider or DPAPIProvider()
        self._session: dict[str, str] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _reference(reference):
        if not isinstance(reference, str) or not reference or len(reference) > 256 or any(char in reference for char in "\r\n\0"):
            raise ValueError("Choose a non-empty credential reference of at most 256 characters.")
        return reference

    def _read(self):
        if not self.path.exists():
            return {"format": FORMAT, "version": VERSION, "entries": {}}
        try:
            envelope = json.loads(self.path.read_text(encoding="utf-8"))
            if envelope.get("format") != FORMAT or envelope.get("version") != VERSION or not isinstance(envelope.get("entries"), dict):
                raise ValueError("Unsupported credential envelope")
            return envelope
        except (OSError, ValueError, AttributeError) as exc:
            raise CredentialStoreError("Saved credentials are unreadable or use an unsupported format; the encrypted file has been preserved.") from exc

    def _write(self, envelope):
        try:
            # Do not retain old credential blobs in rolling backups: switching
            # to session-only or deleting a credential removes its saved entry.
            atomic_write(self.path, json.dumps(envelope, separators=(",", ":")).encode(), backup=False)
        except OSError as exc:
            raise CredentialStoreError("The encrypted credential could not be saved; existing credentials were retained.") from exc

    def put(self, reference, value, *, mode="session"):
        reference = self._reference(reference)
        if mode not in {"session", "windows"}:
            raise ValueError("Choose session or windows credential persistence explicitly.")
        if not isinstance(value, str) or not value or len(value.encode()) > 65536 or "\0" in value:
            raise ValueError("Credential values must contain between 1 and 65536 UTF-8 bytes.")
        with self._lock:
            if mode == "session":
                if self.path.exists():
                    with file_lock(self.directory / ".credentials.lock"):
                        envelope = self._read()
                        if reference in envelope["entries"]:
                            del envelope["entries"][reference]
                            self._write(envelope)
                self._session[reference] = value
            else:
                raw = json.dumps({"version": VERSION, "reference": reference, "value": value}, separators=(",", ":")).encode()
                encrypted = self.provider.protect(raw, (FORMAT + ":" + reference).encode())
                with file_lock(self.directory / ".credentials.lock"):
                    envelope = self._read()
                    envelope["entries"][reference] = {"provider": self.provider.name, "ciphertext": base64.b64encode(encrypted).decode("ascii")}
                    self._write(envelope)
                self._session.pop(reference, None)
            return {"reference": reference, "persistence": mode, "available": True}

    def get(self, reference):
        reference = self._reference(reference)
        with self._lock:
            if reference in self._session:
                return self._session[reference]
            if not self.path.exists():
                return None
            with file_lock(self.directory / ".credentials.lock"):
                entry = self._read()["entries"].get(reference)
            if entry is None:
                return None
            try:
                if entry.get("provider") != self.provider.name:
                    raise ValueError("Unsupported credential provider")
                encrypted = base64.b64decode(entry["ciphertext"], validate=True)
                raw = self.provider.unprotect(encrypted, (FORMAT + ":" + reference).encode())
                value = json.loads(raw)
                if value.get("version") != VERSION or value.get("reference") != reference or not isinstance(value.get("value"), str):
                    raise ValueError("Credential binding is invalid")
                return value["value"]
            except CredentialStoreError:
                raise
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                raise CredentialStoreError("The saved credential could not be unlocked; re-enter it for this user.") from exc

    def delete(self, reference):
        reference = self._reference(reference)
        with self._lock:
            if self.path.exists():
                with file_lock(self.directory / ".credentials.lock"):
                    envelope = self._read()
                    if reference in envelope["entries"]:
                        del envelope["entries"][reference]
                        self._write(envelope)
            self._session.pop(reference, None)

    def available(self, reference):
        try:
            return self.get(reference) is not None
        except CredentialStoreError:
            return False

    def capabilities(self):
        return {"session": True, "windows": os.name == "nt", "provider": self.provider.name,
                "default": "session", "automatic_token_acquisition": False}


_STORE: CredentialStore | None = None
_LOCK = threading.Lock()


def store() -> CredentialStore:
    global _STORE
    with _LOCK:
        if _STORE is None:
            _STORE = CredentialStore()
        return _STORE


def set_store(instance: CredentialStore | None):
    global _STORE
    with _LOCK:
        _STORE = instance
