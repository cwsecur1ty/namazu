"""Packaged desktop backend; only its owning native process can authenticate."""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import socket
import sys
import threading
from pathlib import Path

from . import desktop_build, desktop_runtime


def _configure_process(state_dir: str | None):
    os.environ["NAMAZU_DESKTOP"] = "1"
    if state_dir:
        os.environ["NAMAZU_STATE_DIR"] = str(Path(state_dir).resolve())
    # Child tools resolve the bundled Node executable before the user's PATH.
    executable_root = Path(sys.executable).resolve().parent
    bundled_node = executable_root.parent / "runtime"
    if (bundled_node / "node.exe").is_file():
        os.environ["PATH"] = str(bundled_node) + os.pathsep + os.environ.get("PATH", "")
    from .desktop_state import data_paths, initialize_data
    root = data_paths().root
    root.mkdir(parents=True, exist_ok=True)
    ownership = (root / ".desktop-instance.lock").open("a+b")
    ownership.seek(0, os.SEEK_END)
    if ownership.tell() == 0:
        ownership.write(b"0")
        ownership.flush()
    ownership.seek(0)
    try:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(ownership.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(ownership.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return initialize_data(), ownership
    except BaseException:
        ownership.close()
        raise


def _stop_owned_work():
    from .bruno_sources import service as source_jobs
    source_jobs().stop_all()
    from .identity_profiles import current_manager
    if acquisitions := current_manager():
        acquisitions.stop_all()
    from . import desktop_requests
    from .audit import run_service
    instance = run_service._MANAGER
    if instance is not None:
        for run in instance.list_runs():
            if instance.is_active(run["run_id"]):
                instance.stop(run["run_id"])
    instance = getattr(desktop_requests, "_manager", None)
    if instance is not None:
        with contextlib.suppress(Exception):
            instance.stop_all()


async def _serve(listener: socket.socket, stop: threading.Event, state: dict):
    import uvicorn

    from .app import app
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, access_log=False,
                           log_level="warning", timeout_graceful_shutdown=15))
    task = asyncio.create_task(server.serve(sockets=[listener]))
    while not server.started:
        if task.done():
            await task
            raise RuntimeError("Desktop service did not start")
        await asyncio.sleep(0.025)
    origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
    print(json.dumps({"ready": True, "origin": origin, "pid": os.getpid(),
                      "data_root": str(state.get("root", "")), **desktop_build.public_identity()}), flush=True)
    while not task.done() and not stop.is_set():
        await asyncio.sleep(0.1)
    if stop.is_set():
        _stop_owned_work()
        # Let already dispatched exchanges settle and retain evidence before
        # the server exits. The native shell owns a final bounded timeout.
        from . import desktop_requests
        from .audit import run_service
        deadline = asyncio.get_running_loop().time() + 12
        def active():
            from .identity_profiles import current_manager
            acquisitions = current_manager()
            audit = run_service._MANAGER
            requests = desktop_requests._manager
            return ((acquisitions is not None and acquisitions.active_count() > 0)
                    or (audit is not None and any(thread.is_alive() for thread in list(audit._threads.values())))
                    or (requests is not None and requests.active_count() > 0))
        while active() and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.1)
        server.should_exit = True
    await task


def main(argv=None):
    parser = argparse.ArgumentParser(description="Namazu private desktop service")
    parser.add_argument("--desktop-host", action="store_true")
    parser.add_argument("--state-dir")
    args = parser.parse_args(argv)
    stop = threading.Event()
    ownership = None
    try:
        # The capability never appears in arguments, URLs, environment, files,
        # browser storage, logs or the handshake. It travels over inherited stdin.
        line = sys.stdin.readline(4097)
        if len(line) > 4096 or not line.endswith("\n"):
            raise ValueError("Missing private desktop startup handshake")
        handshake = json.loads(line)
        desktop_runtime.configure(handshake.get("session_secret"), stop.set, native_secret=handshake.get("native_secret"))
        desktop_build.preflight(handshake.get("expected_build_id"))
        state, ownership = _configure_process(args.state_dir)
        # Parent death closes this pipe even if it happened before the native
        # process attached our child to its kill-on-close Windows job object.
        threading.Thread(target=lambda: (sys.stdin.read(), stop.set()), daemon=True,
                         name="namazu-desktop-owner").start()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(128)
            listener.setblocking(False)
            asyncio.run(_serve(listener, stop, state))
    except desktop_build.DesktopBuildError as exc:
        print(json.dumps({"ready": False, "error": "DesktopBuildError", "code": exc.code, "detail": str(exc)}), flush=True)
        return 1
    except Exception as exc:
        # Startup errors are actionable, but traceback/request/secret material
        # never travels over the parent's private handshake output.
        print(json.dumps({"ready": False, "error": type(exc).__name__,
                          "detail": "Namazu could not open its local workspace. Check folder permissions and available disk space."}), flush=True)
        return 1
    finally:
        if ownership is not None:
            ownership.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
