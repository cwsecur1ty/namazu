"""Headless journeys against the shipped backend/resources, with no native window input.

The capability stays in test memory and is attached only to the private app
origin. Targets are loopback fixtures. Developer runtimes are removed from the
packaged child PATH, and its working directory contains spaces outside source.
"""
from __future__ import annotations

import argparse
import json
import os
import site
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
site.addsitedir(str(ROOT / ".venv/Lib/site-packages"))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import desktop_advanced_ui  # noqa: E402
import desktop_detection_ui  # noqa: E402
import desktop_ui  # noqa: E402
import workspace_ui  # noqa: E402
from test_desktop_host import Host  # noqa: E402
from workspace_fixture_server import WorkspaceFixture  # noqa: E402


def main(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    original = os.environ.get("NAMAZU_PACKAGED_BACKEND")
    os.environ["NAMAZU_PACKAGED_BACKEND"] = str(args.backend.resolve())
    results = []
    try:
        for mode in args.modes:
            directory = output / mode
            directory.mkdir(parents=True, exist_ok=True)
            began = time.perf_counter()
            host = Host(directory)
            assert host.reply["ready"] is True, host.reply
            handshake_ms = round((time.perf_counter() - began) * 1000, 2)
            origin = host.reply["origin"].rstrip("/")
            port = urlsplit(origin).port
            try:
                if mode == "main":
                    fixture = ThreadingHTTPServer(("127.0.0.1", 0), desktop_ui.Handler)
                    fixture.daemon_threads = True
                    fixture.base = f"http://127.0.0.1:{fixture.server_port}"
                    fixture.attempts = []
                    threading.Thread(target=fixture.serve_forever, daemon=True).start()
                    try:
                        with sync_playwright() as playwright:
                            browser = playwright.chromium.launch(headless=True)
                            page = browser.new_page(viewport={"width": 1440, "height": 1000},
                                extra_http_headers={"X-Namazu-Session": host.secret})
                            def local_only(route, _request, origin=origin):
                                if route.request.url.startswith(origin + "/") or route.request.url.startswith("blob:"):
                                    route.continue_()
                                else:
                                    route.abort()
                            page.route("**/*", local_only)
                            page.goto(origin)
                            desktop_ui.journey(page, directory, "packaged-renderer", fixture)
                            browser.close()
                    finally:
                        fixture.shutdown()
                        fixture.server_close()
                elif mode == "workspace":
                    fixture = WorkspaceFixture(0)
                    threading.Thread(target=fixture.serve_forever, daemon=True).start()
                    try:
                        workspace_ui.run(port, fixture.server_port, directory, session_secret=host.secret)
                    finally:
                        fixture.shutdown()
                        fixture.server_close()
                elif mode == "advanced":
                    desktop_advanced_ui.run(port, directory, external_origin=origin, session_secret=host.secret)
                else:
                    options = SimpleNamespace(output=directory, port=port, url=origin, cdp=None)
                    desktop_detection_ui.run(options, external_origin=origin, session_secret=host.secret)
            finally:
                host.close()
            # These are inert local test secrets, never real credentials. Files
            # include SQLite/WAL and config; screenshots have only masked input.
            forbidden = [host.secret.encode(), b"Bearer local-shared", b"Bearer local-primary",
                         b"legacy-import-secret", b"never-save-this"]
            for path in host.state.rglob("*"):
                if path.is_file():
                    assert not any(secret in path.read_bytes() for secret in forbidden), f"Sensitive fixture value persisted in {path.name}"
            results.append({"journey": mode, "passed": True, "backend_handshake_ms": handshake_ms,
                            "seconds": round(time.perf_counter() - began, 2), "persisted_secret_scan": "passed",
                            "surface": "headless Chromium using packaged backend and static resources; native window untouched"})
    finally:
        if original is None:
            os.environ.pop("NAMAZU_PACKAGED_BACKEND", None)
        else:
            os.environ["NAMAZU_PACKAGED_BACKEND"] = original
    (output / "packaged-journeys.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(".local-reports/packaged-final"))
    parser.add_argument("--modes", nargs="+", choices=["main", "workspace", "advanced", "detection"],
                        default=["main", "workspace", "advanced", "detection"])
    main(parser.parse_args())
