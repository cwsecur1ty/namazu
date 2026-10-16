"""Private desktop process/loopback tests; never scan or contact remote targets."""
from __future__ import annotations

import contextlib
import json
import os
import queue
import secrets
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest


class Host:
    def __init__(self, root, *, secret=None, state=None, expected_build_id=None, native_secret=None):
        root = Path(root).resolve()
        self.secret = secret or secrets.token_hex(32)
        self.state = Path(state).resolve() if state else root / "workspace data with spaces"
        environment = os.environ.copy()
        environment["USERPROFILE"] = str(root / "fixture user")
        environment["HOME"] = environment["USERPROFILE"]
        environment.pop("NAMAZU_DESKTOP", None)
        executable = os.environ.get("NAMAZU_PACKAGED_BACKEND")
        working_directory = Path(__file__).resolve().parents[1]
        if executable:
            # A shipped app must not accidentally use a developer's Python,
            # Node, .NET SDK or global tool installation.
            environment["PATH"] = str(Path(os.environ["SYSTEMROOT"]) / "System32")
            working_directory = root / "launch directory with spaces"
            working_directory.mkdir(parents=True, exist_ok=True)
        command = [executable] if executable else [sys.executable, "-m", "namazu.desktop_host"]
        self.process = subprocess.Popen([*command, "--desktop-host", "--state-dir", str(self.state)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            cwd=working_directory, env=environment,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        handshake = {"session_secret": self.secret, "parent_pid": os.getpid()}
        if expected_build_id is not None:
            handshake["expected_build_id"] = expected_build_id
        if native_secret is not None:
            handshake["native_secret"] = native_secret
        self.process.stdin.write(json.dumps(handshake) + "\n")
        self.process.stdin.flush()
        output = queue.Queue()
        threading.Thread(target=lambda: output.put(self.process.stdout.readline()), daemon=True).start()
        try:
            line = output.get(timeout=30)
            self.reply = json.loads(line)
        except (queue.Empty, ValueError):
            self.process.kill()
            _out, errors = self.process.communicate(timeout=5)
            raise AssertionError("Desktop handshake failed: " + errors[-1500:]) from None
        assert self.secret not in line
        assert not native_secret or native_secret not in line

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.process.stdout.close()
        self.process.stderr.close()


@pytest.fixture
def host(tmp_path):
    instance = Host(tmp_path)
    try:
        assert instance.reply["ready"] is True, instance.reply
        yield instance
    finally:
        instance.close()


def test_private_loopback_requires_header_and_never_exports_capability(host):
    origin = host.reply["origin"]
    assert origin.startswith("http://127.0.0.1:")
    with httpx.Client(base_url=origin, trust_env=False) as client:
        assert client.get("/api/health").status_code == 401
        assert client.get("/", params={"session": host.secret}).status_code == 401
        assert client.get("/api/health", headers={"X-Namazu-Session": "wrong"}).status_code == 401
        client.headers["X-Namazu-Session"] = host.secret
        response = client.get("/")
        assert response.status_code == 200 and host.secret not in response.text
        health = client.get("/api/health").json()
        assert health["build_id"] == host.reply["build_id"]
        assert health["frontend_build_id"] == health["build_id"]
        assert health["resources_verified"] is True
        assert f'name="namazu-build-id" content="{health["build_id"]}"' in response.text
        assert client.get("/api/health", headers={"Host": "localhost"}).status_code == 403
        state = client.get("/api/desktop/status").json()
        assert state["desktop"] and state["active_runs"] == state["active_requests"] == 0


def test_second_backend_cannot_recover_or_interrupt_active_first(host, tmp_path):
    other = Host(tmp_path, state=host.state)
    try:
        assert other.reply["ready"] is False
        assert host.process.poll() is None
        response = httpx.get(host.reply["origin"] + "/api/desktop/status",
                            headers={"X-Namazu-Session": host.secret}, trust_env=False)
        assert response.status_code == 200
    finally:
        other.close()


def test_parent_pipe_close_stops_owned_backend(host):
    host.process.stdin.close()
    assert host.process.wait(timeout=20) == 0


def test_authenticated_shutdown_stops_backend_and_preserves_state(host):
    headers = {"X-Namazu-Session": host.secret}
    origin = host.reply["origin"]
    response = httpx.post(origin + "/api/desktop/shutdown", json={"stop_runs": True}, headers=headers, trust_env=False)
    assert response.status_code == 200
    assert host.process.wait(timeout=20) == 0
    assert (host.state / "evidence" / "runs.db").is_file()
    assert (host.state / "config").is_dir()


def test_invalid_startup_capability_fails_without_opening_a_listener(tmp_path):
    instance = Host(tmp_path, secret="short")
    try:
        assert instance.reply["ready"] is False
        assert instance.process.wait(timeout=10) == 1
        assert not instance.state.exists()
    finally:
        instance.close()


def test_mismatched_native_build_fails_before_state_or_listener(tmp_path):
    instance = Host(tmp_path, expected_build_id="namazu-" + "f" * 24)
    try:
        assert instance.reply["ready"] is False
        assert instance.reply["code"] == "native-backend-build-mismatch"
        assert "origin" not in instance.reply
        assert instance.process.wait(timeout=10) == 1
        assert not instance.state.exists()
    finally:
        instance.close()


def test_bundled_bruno_parser_works_offline_without_developer_path(host):
    response = httpx.post(host.reply["origin"] + "/api/bruno/collection",
        headers={"X-Namazu-Session": host.secret}, trust_env=False,
        json={"files": [{"path": "Read.bru", "content": "meta {\n  name: Read\n  type: http\n  seq: 1\n}\nget {\n  url: http://127.0.0.1:9/never-dispatched\n  body: none\n  auth: none\n}\n"}]})
    assert response.status_code == 200, response.text
    assert response.json()["requests"][0]["request"]["url"] == "http://127.0.0.1:9/never-dispatched"


def test_bundled_schemathesis_help_requires_no_python_installation():
    executable = os.environ.get("NAMAZU_PACKAGED_BACKEND")
    if not executable:
        pytest.skip("Release artifact check; set NAMAZU_PACKAGED_BACKEND.")
    environment = {**os.environ, "PATH": str(Path(os.environ["SYSTEMROOT"]) / "System32")}
    result = subprocess.run([executable, "--bundled-schemathesis", "--help"],
        capture_output=True, text=True, timeout=30, env=environment,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    assert result.returncode == 0, result.stderr
    assert "Usage:" in result.stdout and "run" in result.stdout


@pytest.fixture
def local_target():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            self.server.attempts.append(self.path)
            self.server.arrived.set()
            self.server.release.wait(timeout=10)
            data = b'{"id":17,"sample":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            with contextlib.suppress(OSError):
                self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.attempts, server.arrived, server.release = [], threading.Event(), threading.Event()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.release.set()
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def start_local_audit(host, server):
    base = f"http://127.0.0.1:{server.server_port}"
    spec = {"openapi": "3.0.3", "info": {"title": "Lifecycle fixture", "version": "1"},
            "servers": [{"url": base}], "paths": {"/item": {"get": {
                "responses": {"200": {"description": "Local response"}}}}}}
    response = httpx.post(host.reply["origin"] + "/api/runs", trust_env=False,
        headers={"X-Namazu-Session": host.secret}, json={"spec": spec, "base_url": base,
            "operations": [{"operation_id": "GET /item"}], "profile": "readonly",
            "budget": 100, "requests_per_second": 0.2, "concurrency": 1, "inventory": False,
            "identities": {}, "allow_mutating": False})
    assert response.status_code == 200, response.text
    assert server.arrived.wait(timeout=10)
    return response.json()["run_id"]


def test_active_audit_shutdown_stops_new_dispatch_and_retains_partial_evidence(host, local_target):
    run_id = start_local_audit(host, local_target)
    headers = {"X-Namazu-Session": host.secret}
    state = httpx.get(host.reply["origin"] + "/api/desktop/status", headers=headers, trust_env=False).json()
    assert state["active_runs"] == 1
    response = httpx.post(host.reply["origin"] + "/api/desktop/shutdown", trust_env=False,
                         headers=headers, json={"stop_runs": True})
    assert response.status_code == 200
    local_target.release.set()
    assert host.process.wait(timeout=20) == 0
    assert len(local_target.attempts) == 1
    from namazu.audit.run_store import RunStore
    store = RunStore(host.state / "evidence/runs.db")
    try:
        run = store.get_run(run_id)
        assert run["status"] == "incomplete"
        assert len(store.exchanges(run_id)) == 1
    finally:
        store.close()


def test_crashed_active_audit_reopens_interrupted_without_replay(host, local_target, tmp_path):
    run_id = start_local_audit(host, local_target)
    host.process.kill()
    host.process.wait(timeout=5)
    local_target.release.set()
    restored = Host(tmp_path, state=host.state)
    try:
        assert restored.reply["ready"] is True
        response = httpx.get(restored.reply["origin"] + f"/api/runs/{run_id}", trust_env=False,
                             headers={"X-Namazu-Session": restored.secret})
        assert response.status_code == 200
        assert response.json()["status"] == "interrupted" and not response.json()["active"]
        time.sleep(0.4)
        assert len(local_target.attempts) == 1
    finally:
        restored.close()
