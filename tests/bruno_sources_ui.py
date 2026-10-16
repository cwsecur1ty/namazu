"""Headless local source-import and neutral-theme journeys, never native GUI.

Sources are deterministic local files. No target dispatch, token acquisition or
external navigation is allowed. Discovery/parsing/import and preview rendering
are measured separately; measurements are observations, not performance gates.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import site
import sys
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
site.addsitedir(str(ROOT / ".venv/Lib/site-packages"))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from test_desktop_host import Host  # noqa: E402


def request(name, path, *, auth="none"):
    return f"meta {{\n  name: {name}\n  type: http\n  seq: 1\n}}\nget {{\n  url: {{{{base}}}}/{path}\n  body: none\n  auth: {auth}\n}}\n"


def manifest(name):
    return json.dumps({"version": "1", "name": name, "type": "collection", "ignore": ["node_modules", ".git"]})


def archive(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as result:
        for name, content in files.items():
            result.writestr(name, content)
    return output.getvalue()


def run(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    previous = os.environ.get("PYTHONPATH"), os.environ.get("NAMAZU_PACKAGED_BACKEND")
    os.environ["PYTHONPATH"] = str(ROOT / ".venv/Lib/site-packages") + os.pathsep + str(ROOT)
    if args.backend:
        os.environ["NAMAZU_PACKAGED_BACKEND"] = str(args.backend.resolve())
    else:
        os.environ.pop("NAMAZU_PACKAGED_BACKEND", None)
    host = Host(output)
    origin = host.reply["origin"].rstrip("/")
    checks, forbidden, errors, measurements, screenshots = [], [], [], [], []
    source = {
        "workspace.yml": "opencollection: 1.0.0\ninfo:\n  name: Local import fixture\n  type: workspace\ncollections:\n  - name: Accounts\n    path: accounts\n  - name: Unresolved\n    path: unresolved\n  - name: Broken\n    path: broken\n",
        "environments/global.bru": "vars {\n  globalFlag: explicit-global\n}\n",
        "accounts/bruno.json": manifest("Accounts"),
        "accounts/environments/local.bru": "vars {\n  base: http://127.0.0.1:9/api\n  opaque: local-secret-value\n}\n",
        "accounts/Nested/one.bru": request("Duplicate name", "one", auth="bearer") + "auth:bearer {\n  token: {{opaque}}\n}\n",
        "accounts/Nested/Deep/two.bru": request("Duplicate name", "two"),
        "accounts/Other/three.bru": request("Other request", "three"),
        "unresolved/bruno.json": manifest("Unresolved"),
        "unresolved/read.bru": request("Needs input", "{{missing}}"),
        "broken/bruno.json": manifest("Broken"),
        "broken/invalid.bru": "not a valid Bruno definition {",
    }
    source_file = output / "workspace fixture.zip"
    source_file.write_bytes(archive(source))
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1440, "height": 1000}, extra_http_headers={"X-Namazu-Session": host.secret})
            page.on("pageerror", lambda failure: errors.append(str(failure)))

            def route_local(route):
                path = urlsplit(route.request.url).path
                if not route.request.url.startswith(origin + "/") or (route.request.method == "POST" and path in {"/api/desktop/requests", "/api/auth/token", "/api/auth/browser/start"}):
                    forbidden.append(route.request.url)
                    route.abort()
                else:
                    route.continue_()

            page.route("**/*", route_local)

            def api(path, value=None, method="GET"):
                response = page.request.fetch(origin + path, method=method, data=value, headers={"X-Namazu-Session": host.secret, "Content-Type": "application/json"})
                assert response.ok, response.text()
                return response.json()

            def screenshot(label):
                for theme in ("dark", "light"):
                    page.evaluate("theme => window.NamazuWorkbench.setTheme(theme)", theme)
                    for width in (1440, 390):
                        page.set_viewport_size({"width": width, "height": 1000 if width == 1440 else 844})
                        page.screenshot(path=str(output / f"{label}-{theme}-{width}.png"))
                        screenshots.append(f"{label}-{theme}-{width}.png")
                        sizes = page.locator("#desktop-workbench, #bruno-dialog:visible, #bruno-source-tree:visible").evaluate_all("nodes => nodes.map(n=>({id:n.id,width:n.clientWidth,scroll:n.scrollWidth}))")
                        assert all(item["scroll"] <= item["width"] + 1 for item in sizes), sizes
                        measurements.append({"screen": label, "theme": theme, "width": width, "elements": sizes})
                page.set_viewport_size({"width": 1440, "height": 1000})

            def open_import():
                if page.locator("#bruno-dialog").is_visible():
                    page.locator("#bruno-dialog").get_by_role("button", name="Close", exact=True).click()
                page.locator("#desktop-import").click()
                page.locator('[data-import-kind="bruno-definitions"]').click()
                expect(page.locator("#bruno-import-flow")).to_be_visible()

            def upload(file):
                with page.expect_response(lambda response: urlsplit(response.url).path == "/api/bruno/sources" and response.request.method == "POST") as response:
                    page.locator("#bruno-source-zip").set_input_files(file)
                assert response.value.ok, response.value.text()
                job_id = response.value.json()["id"]
                expect(page.locator("#bruno-import-flow")).to_have_attribute("aria-busy", "false", timeout=60000)
                expect(page.locator("#bruno-source-tree")).to_be_visible()
                return job_id

            def review():
                page.locator("#bruno-source-review").click()
                expect(page.locator("#bruno-import-flow")).to_have_attribute("aria-busy", "false", timeout=90000)

            page.goto(origin)
            expect(page.locator("#desktop-workbench")).to_have_attribute("data-ready", "true")
            expect(page.locator("#desktop-window-controls")).to_be_hidden()
            assert page.evaluate("typeof window.NamazuNative") == "undefined"
            for name in ("Import Bruno workspace or collection", "Import API contracts", "Open Namazu workspace", "Configure authentication"):
                expect(page.locator("#desktop-welcome").get_by_role("button", name=name, exact=True)).to_be_visible()
            screenshot("01-home")
            page.locator("#desktop-welcome-bruno").click()
            expect(page.locator("#bruno-choose-folder")).to_be_visible()
            expect(page.locator("#bruno-choose-zip")).to_be_visible()
            page.locator(".bruno-export-help summary").click()
            expect(page.locator(".bruno-export-help")).to_contain_text("Export Workspace")
            screenshot("02-choose-help")
            page.locator("#bruno-dialog").get_by_role("button", name="Close", exact=True).click()

            workspace = api("/api/workspaces", {"title": "Preserved workspace"}, "POST")
            wid = workspace["id"]
            spec = {"openapi": "3.0.3", "info": {"title": "Original contract", "version": "1"}, "servers": [{"url": "http://127.0.0.1:9/api"}], "paths": {"/keep": {"get": {"responses": {"200": {"description": "fixture"}}}}}}
            workspace = api(f"/api/workspaces/{wid}/contracts/import", {"items": [{"raw_spec": spec}]}, "POST")
            original_contract = workspace["contracts"][0]
            page.reload()
            expect(page.locator("#desktop-workbench")).to_have_attribute("data-ready", "true")
            page.locator("#desktop-workspace").select_option(wid)
            page.locator(f'[data-operation-key="{original_contract["operations"][0]["id"]}"]').click()
            page.locator("#desktop-request-url").fill("http://127.0.0.1:9/api/keep?draft=preserved")
            page.evaluate("() => window.NamazuDesktop.flush()")
            original_state = api("/api/desktop/state")["state"]

            def preserved():
                page.evaluate("() => window.NamazuDesktop.flush()")
                state = api("/api/desktop/state")["state"]
                assert state["tabs"] == original_state["tabs"]
                assert state["selectedTab"] == original_state["selectedTab"]
                assert api(f"/api/workspaces/{wid}")["contracts"] == [original_contract]

            open_import()
            job_id = upload(source_file)
            expect(page.locator(".bruno-source-collection")).to_have_count(3)
            accounts = page.locator(".bruno-source-collection").filter(has=page.get_by_role("checkbox", name="Select collection Accounts", exact=True))
            accounts.locator(":scope > summary").click()
            accounts.get_by_label("Environment for Accounts", exact=True).select_option("local")
            page.get_by_label("Workspace environment", exact=True).select_option("global")
            review()
            expect(page.locator("#bruno-import-flow [role=alert]")).to_contain_text("failed review")
            expect(page.locator("#bruno-source-import")).to_be_disabled()
            preserved()
            assert api(f"/api/workspaces/{wid}").get("request_collections", []) == []
            checks.append("selected malformed sibling fails atomically, while successful preview and current draft remain")
            screenshot("03-review-error")
            page.get_by_role("checkbox", name="Select collection Broken", exact=True).uncheck()
            review()
            expect(page.locator("#bruno-source-import")).to_be_enabled()
            assert "local-secret-value" not in page.locator("#bruno-dialog").inner_text()
            page.get_by_role("checkbox", name="Select collection Unresolved", exact=True).uncheck()
            page.get_by_role("checkbox", name="Select collection Accounts", exact=True).uncheck()
            page.get_by_role("checkbox", name="Select folder Accounts/Nested", exact=True).check()
            review()
            job = api(f"/api/bruno/sources/{job_id}")
            assert len(next(item for item in job["collections"] if item["title"] == "Accounts")["requests"]) == 3, "Unselected source requests must remain available for review changes"
            screenshot("04-reviewed-subtree")
            page.locator("#bruno-source-import").click()
            expect(page.locator("#bruno-import-flow")).to_have_attribute("aria-busy", "false", timeout=60000)
            expect(page.locator("#bruno-import-flow")).to_contain_text("Import complete")
            preserved()
            current = api(f"/api/workspaces/{wid}")
            assert len(current["request_collections"]) == 1
            assert len(current["request_collections"][0]["operations"]) == 2
            assert all("Nested/" in item["local_id"] for item in current["request_collections"][0]["operations"])
            checks.append("folder selection imports only descendants with environment metadata, preserving contract, active tab and draft")
            screenshot("05-import-complete")

            # Cancel while the source-create HTTP request is still pending. The
            # late-created job must be cancelled rather than reopening review.
            page.locator("#bruno-import-flow").get_by_role("button", name="Import another source", exact=True).click()
            held = []
            page.route("**/api/bruno/sources", lambda route: held.append(route))
            page.locator("#bruno-source-zip").set_input_files(source_file)
            expect(page.locator("#bruno-source-cancel")).to_be_visible()
            assert held
            page.locator("#bruno-source-cancel").click()
            held[0].continue_()
            page.unroute("**/api/bruno/sources")
            expect(page.locator("#bruno-source-status")).to_contain_text("cancelled")
            page.wait_for_timeout(500)
            expect(page.locator("#bruno-choose-folder")).to_be_visible()
            preserved()
            checks.append("cancellation before source creation settles does not reopen or mutate workspace")

            large = {"bruno.json": manifest("Large collection"), "collection.bru": "vars {\n  base: http://127.0.0.1:9\n}\n"}
            for index in range(1200):
                large[f"Group{index:04d}/request.bru"] = request(f"Operation {index:04d}", f"item/{index}")
            large_file = output / "large workspace.zip"
            large_file.write_bytes(archive(large))
            large_id = upload(large_file)
            assert page.locator(".bruno-source-request").count() <= 160
            review()
            assert page.locator(".bruno-source-request").count() <= 160
            page.locator("#bruno-source-search").fill("Operation 1199")
            expect(page.locator(".bruno-source-request")).to_have_count(1)
            expect(page.locator(".bruno-source-request")).to_contain_text("Operation 1199")
            page.locator("#bruno-source-search").fill("")
            render_ms = float(page.locator("#bruno-import-flow").get_attribute("data-preview-render-ms"))
            job = api(f"/api/bruno/sources/{large_id}")
            measurements.append({"large_requests": 1200, "rendered_requests": page.locator(".bruno-source-request").count(), "preview_render_ms": render_ms, "timings": job["timings"]})
            screenshot("06-large-bounded-preview")
            checks.append("1200 distinct folders stay bounded to 160 request rows and search reaches hidden rows")
            page.locator("#bruno-dialog").get_by_role("button", name="Close", exact=True).click()
            preserved()
            page.locator("#desktop-identity").click()
            expect(page.locator("#identity-dialog")).to_be_visible()
            checks.append("shared Configure authentication entry is reachable without token acquisition")
            assert not forbidden, forbidden
            assert not errors, errors
            browser.close()
    finally:
        host.close()
        for name, value in zip(("PYTHONPATH", "NAMAZU_PACKAGED_BACKEND"), previous, strict=True):
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        report = {"kind": "headless browser with private backend; no native GUI", "checks": checks, "measurements": measurements, "screenshots": screenshots, "external_or_target_requests": forbidden, "page_errors": errors}
        (output / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"checks": len(checks), "screenshots": len(screenshots), "target_requests": len(forbidden), "output": str(output)}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path(".local-reports/bruno-sources-ui"))
    parser.add_argument("--backend", type=Path)
    run(parser.parse_args())
