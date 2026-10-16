"""Headless startup failure receipts; no native window or API target is used."""
from __future__ import annotations

import argparse
import json
import os
import site
import sys
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
site.addsitedir(str(ROOT / ".venv/Lib/site-packages"))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from test_desktop_host import Host  # noqa: E402


def run(output):
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    prior = os.environ.get("PYTHONPATH")
    os.environ["PYTHONPATH"] = str(ROOT / ".venv/Lib/site-packages") + os.pathsep + str(ROOT)
    host = Host(output)
    origin = host.reply["origin"].rstrip("/")
    observations, external, dispatches = [], [], []
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            for case, expected in [
                ("normal", "ready"), ("model-missing", "failed"), ("css-missing", "failed"),
                ("startup-exception", "failed"), ("state-api-failure", "failed"),
                ("collapsed-workbench", "failed"), ("transparent-body", "failed"),
                ("unbound-controls", "failed"), ("helper-missing", "unavailable"),
            ]:
                context = browser.new_context(viewport={"width": 1280, "height": 800}, extra_http_headers={"X-Namazu-Session": host.secret})
                page = context.new_page()
                failures = []
                page.on("pageerror", lambda error, collected=failures: collected.append(str(error)))

                def route_request(route, _request=None, scenario=case):
                    path = urlsplit(route.request.url).path
                    if not route.request.url.startswith(origin + "/"):
                        external.append(route.request.url)
                        route.abort()
                    elif path == "/api/desktop/requests" and route.request.method == "POST":
                        dispatches.append(path)
                        route.abort()
                    elif (scenario, path) in {
                        ("model-missing", "/static/desktop-model.js"),
                        ("helper-missing", "/static/desktop-readiness.js"),
                        ("css-missing", "/static/desktop-workbench.css"),
                    }:
                        route.fulfill(status=404, body="missing", content_type="text/plain")
                    elif scenario == "startup-exception" and path == "/static/desktop-workbench.js":
                        route.fulfill(body="throw Error('Do not expose fixture-token-123 in startup receipts');", content_type="text/javascript")
                    elif scenario == "state-api-failure" and path == "/api/desktop/state":
                        route.fulfill(status=500, json={"detail": "Do not expose fixture-token-123 in startup receipts"})
                    else:
                        route.continue_()

                context.route("**/*", route_request)
                if case in {"collapsed-workbench", "transparent-body", "unbound-controls"}:
                    page.add_init_script("""window.addEventListener('DOMContentLoaded', () => {
                        if (CASE === 'collapsed-workbench') {
                            document.getElementById('desktop-workbench').style.display='none';
                        } else if (CASE === 'transparent-body') {
                            document.body.style.opacity='0';
                        } else document.getElementById('desktop-import').onclick=null;
                    });""".replace("CASE", json.dumps(case)))
                response = page.goto(origin)
                assert response.ok, "The HTML loads even when the usable frontend does not"
                if expected == "unavailable":
                    expect(page.locator("#desktop-workbench")).to_have_attribute("data-ready", "false")
                    assert page.evaluate("typeof window.NamazuStartup") == "undefined"
                    receipt = {"status": "unavailable"}
                else:
                    try:
                        page.wait_for_function("expected => window.NamazuStartup?.snapshot().status === expected", arg=expected)
                    except Exception:
                        print(json.dumps({"case": case, "receipt": page.evaluate("window.NamazuStartup?.snapshot()"), "errors": failures}), flush=True)
                        raise
                    receipt = page.evaluate("window.NamazuStartup.snapshot()")
                    assert "fixture-token-123" not in json.dumps(receipt)
                    assert set(receipt) == {"version", "status", "code", "buildId", "checks"}
                    assert receipt["buildId"] == "source"
                    assert all(isinstance(value, bool) for value in receipt["checks"].values())
                    if expected == "ready":
                        assert all(receipt["checks"].values())
                        expect(page.locator("#desktop-workbench")).to_have_attribute("data-ready", "true")
                        page.locator("#desktop-import").click()
                        expect(page.locator("#desktop-import-dialog")).to_be_visible()
                        page.keyboard.press("Escape")
                        assert failures == []
                    else:
                        assert page.locator("#desktop-workbench").get_attribute("data-ready") != "true"
                        if case in {"collapsed-workbench", "transparent-body"}:
                            assert receipt["code"] == "render-not-visible" and not receipt["checks"]["layout"], receipt
                        if case == "state-api-failure":
                            assert page.evaluate("async () => {try {await NamazuDesktop.openImport();return false;}catch{return true;}}")
                            page.keyboard.press("Control+o")
                            expect(page.locator("#desktop-import-dialog")).to_be_hidden()
                page.screenshot(path=str(output / (case + ".png")))
                observations.append({"case": case, "html_status": response.status, "expected": expected, "receipt": receipt})
                context.close()
            browser.close()
        assert external == dispatches == []
        report = {"passed": True, "surface": "headless Chromium source backend; no native window", "cases": observations,
            "api_target_dispatches": 0, "external_requests": 0, "native_rendering_verified": False}
        (output / "startup-journey.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report, indent=2))
    finally:
        host.close()
        if prior is None:
            os.environ.pop("PYTHONPATH", None)
        else:
            os.environ["PYTHONPATH"] = prior


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(".local-reports/frontend-startup"))
    run(parser.parse_args().output)
