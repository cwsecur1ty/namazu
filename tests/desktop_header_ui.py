"""Headless header journeys; never opens or controls a native application window.

Browser device-scale factors exercise renderer layout, not Windows DPI or snap.
All backend state is isolated. No API target is dispatched by this journey.
"""
from __future__ import annotations

import argparse
import json
import os
import site
import sys
from itertools import pairwise
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
site.addsitedir(str(ROOT / ".venv/Lib/site-packages"))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from desktop_ui import api, ready  # noqa: E402
from test_desktop_host import Host  # noqa: E402


def run(origin, secret, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    origin = origin.rstrip("/")
    workspace_name = "Long workspace: " + "accounts-orders-review-" * 9
    identity_name = "Explicit local reader: " + "selected-contracts-only-" * 7
    target = ("http://127.0.0.1:9/never-dispatched/" + "versioned-base-path/" * 8).rstrip("/")
    state = {"desktop": True, "active_runs": 0, "active_requests": 0, "stopping": False, "interrupted": False}
    observations, errors, stops = [], [], []
    workspace = None

    def route_request(route):
        request = route.request
        if not request.url.startswith(origin + "/"):
            route.abort()
            return
        path = urlsplit(request.url).path
        if path == "/api/desktop/status":
            route.fulfill(json=state)
        elif path == "/api/desktop/stop":
            stops.append(True)
            state["stopping"] = True
            route.fulfill(json={"stopping": True})
        else:
            route.continue_(headers={**request.headers, "X-Namazu-Session": secret})

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            for scale in (1, 1.5, 2):
                context = browser.new_context(viewport={"width": 1440, "height": 1000}, device_scale_factor=scale)
                context.route("**/*", route_request)
                page = context.new_page()
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.goto(origin)
                ready(page)
                if workspace is None:
                    workspace = api(page, "/api/workspaces", {"title": workspace_name}, "POST")
                    base = "/api/workspaces/" + workspace["id"]
                    document = {"openapi": "3.0.3", "info": {"title": "Header fixture", "version": "1"},
                        "servers": [{"url": target}], "paths": {"/items/{id}": {"get": {
                            "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                            "responses": {"200": {"description": "Local fixture only"}}}}}}
                    workspace = api(page, base + "/contracts/import", {"items": [{"raw_spec": document}]}, "POST")
                    contract = workspace["contracts"][0]
                    api(page, base + "/profiles", {"id": "header-reader", "name": identity_name, "token": "inert-header-fixture-token"}, "POST")
                    workspace = api(page, base + f"/contracts/{contract['id']}/identity",
                        {"profile_id": "header-reader", "allowed_scopes": [target]}, "PUT")
                    page.reload()
                    ready(page)
                page.locator("#desktop-workspace").select_option(workspace["id"])
                page.get_by_role("button", name="Open Header fixture: GET /items/{id}", exact=True).click()
                expect(page.locator("#desktop-request")).to_be_visible()
                expect(page.locator("#desktop-workspace")).to_have_attribute("title", workspace_name)
                assert page.evaluate("typeof window.NamazuNative") == "undefined"
                expect(page.locator("#desktop-window-controls")).to_be_hidden()
                for width in (1440, 900, 540, 390):
                    page.set_viewport_size({"width": width, "height": 900})
                    for theme in ("dark", "light"):
                        if page.locator("html").get_attribute("data-theme") != theme:
                            page.locator("#desktop-menu-open").click()
                            page.locator("#desktop-theme").click()
                            expect(page.locator("html")).to_have_attribute("data-theme", theme)
                        bounds = page.evaluate("""() => {
                          const header=document.querySelector('.desktop-toolbar'), h=header.getBoundingClientRect();
                          const rows=[...header.children].filter(e=>e.getClientRects().length && getComputedStyle(e).visibility!=='hidden').map(e=>({id:e.id||e.className, ...Object.fromEntries(['x','y','right','bottom','width','height'].map(k=>[k,e.getBoundingClientRect()[k]]))}));
                          return {height:h.height,right:h.right,width:innerWidth,rows,overflow:document.documentElement.scrollWidth>innerWidth};
                        }""")
                        assert bounds["height"] == 48, bounds
                        assert not bounds["overflow"], bounds
                        for rect in bounds["rows"]:
                            assert rect["x"] >= -0.5 and rect["right"] <= width + 0.5 and rect["bottom"] <= 48.5, bounds
                        ordered = sorted(bounds["rows"], key=lambda rect: rect["x"])
                        assert all(left["right"] <= right["x"] + 0.5 for left, right in pairwise(ordered)), bounds
                        page.locator("#desktop-menu-open").click()
                        expect(page.locator("#desktop-menu-context-description")).to_contain_text(workspace_name)
                        expect(page.locator("#desktop-menu-context-description")).to_contain_text(target)
                        expect(page.locator("#desktop-menu-context-description")).to_contain_text(identity_name)
                        expect(page.locator("#desktop-native-menu")).to_be_hidden()
                        if width <= 1180:
                            expect(page.locator("#desktop-menu-context-slot #desktop-target")).to_be_visible()
                            expect(page.locator("#desktop-target")).to_have_attribute("title", "Active target: " + target)
                        if width == 390 and scale == 1:
                            page.screenshot(path=str(output / f"header-overflow-narrow-{theme}.png"))
                        page.keyboard.press("Escape")
                        expect(page.locator("#desktop-menu")).to_be_hidden()
                        expect(page.locator("#desktop-menu-open")).to_be_focused()
                        page.screenshot(path=str(output / f"header-{width}-{theme}-scale-{scale}.png"))
                        observations.append({"width": width, "theme": theme, "browser_device_scale_factor": scale,
                            "header_height_css_px": bounds["height"], "no_overlap": True})
                if scale == 1:
                    page.set_viewport_size({"width": 1440, "height": 1000})
                    _exercise_actions(page, state, stops, output)
                page.evaluate("window.NamazuDesktop.flush()")
                context.close()
            assert not errors, errors
        finally:
            browser.close()
    result = {"passed": True, "surface": "headless Chromium; native window untouched; no fake native bridge",
        "layout_cases": observations, "status_cases": ["ready", "running", "stopping", "interrupted", "disconnected"],
        "import_choices": ["openapi", "bruno-definitions", "bruno-results", "workspace", "evidence"],
        "native_gui_verified": False, "windows_dpi_verified": False, "api_target_dispatches": 0}
    (output / "header-journey.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def _exercise_actions(page, state, stops, output):
    expect(page.locator("#desktop-execution-state")).to_have_attribute("data-state", "ready")
    state.update(active_runs=2, active_requests=1)
    expect(page.locator("#desktop-execution-label")).to_have_text("Running 3", timeout=7000)
    page.locator("#desktop-stop-work").click()
    expect(page.locator("#desktop-execution-label")).to_have_text("Stopping")
    expect(page.locator("#desktop-stop-work")).to_be_disabled()
    assert len(stops) == 1
    state.update(active_runs=0, active_requests=0, stopping=False, interrupted=True)
    expect(page.locator("#desktop-execution-label")).to_have_text("Interrupted", timeout=7000)
    expect(page.locator("#desktop-execution-state")).to_have_attribute("title", "Interrupted evidence is retained. Nothing was replayed; open history to inspect it.")
    page.screenshot(path=str(output / "header-interrupted.png"))
    state.update(interrupted=False)
    expect(page.locator("#desktop-execution-label")).to_have_text("Ready", timeout=7000)
    page.route("**/api/desktop/status", lambda route: route.abort())
    expect(page.locator("#desktop-execution-label")).to_have_text("Disconnected", timeout=7000)
    page.unroute("**/api/desktop/status")
    expect(page.locator("#desktop-execution-label")).to_have_text("Ready", timeout=7000)
    page.locator("#desktop-home").click()
    page.keyboard.press("Control+o")
    expect(page.locator("#desktop-import-dialog")).to_be_visible()
    expect(page.locator("[data-import-kind]")).to_have_count(5)
    page.screenshot(path=str(output / "header-import-chooser.png"))
    page.locator('[data-import-kind="openapi"]').click()
    expect(page.locator("#desktop-workspace-review")).to_be_visible()
    for kind, text in (("bruno-definitions", "Scripts remain inert"), ("bruno-results", "historical records")):
        page.locator("#desktop-import").click()
        page.locator(f'[data-import-kind="{kind}"]').click()
        dialog = page.locator("#bruno-dialog")
        expect(dialog).to_be_visible()
        expect(dialog).to_contain_text(text)
        dialog.get_by_role("button", name="Close", exact=True).click()
        expect(dialog).to_be_hidden()
    page.locator("#desktop-import").click()
    with page.expect_file_chooser(timeout=5000) as chooser:
        page.locator('[data-import-kind="workspace"]').click()
    assert not chooser.value.is_multiple()
    chooser.value.set_files([])
    page.locator("#desktop-import").click()
    page.locator('[data-import-kind="evidence"]').click()
    saved_report = page.locator("#saved-report-dialog")
    expect(saved_report).to_be_visible()
    with page.expect_file_chooser(timeout=5000) as chooser:
        page.locator("#saved-report-file").click()
    assert not chooser.value.is_multiple()
    chooser.value.set_files([])
    page.keyboard.press("Escape")
    expect(saved_report).to_be_hidden()
    page.locator("#desktop-home").click()
    page.locator("#desktop-menu-open").focus()
    page.keyboard.press("Enter")
    expect(page.locator("#desktop-menu")).to_be_visible()
    page.keyboard.press("Tab")
    assert page.evaluate("document.querySelector('#desktop-menu').contains(document.activeElement)")
    page.keyboard.press("Escape")
    expect(page.locator("#desktop-menu-open")).to_be_focused()
    assert api(page, "/api/desktop/requests")["requests"] == []


def main(args):
    original = os.environ.get("NAMAZU_PACKAGED_BACKEND")
    if args.backend:
        os.environ["NAMAZU_PACKAGED_BACKEND"] = str(args.backend.resolve())
    host = None
    try:
        interpreter = sys.executable
        try:
            if not os.environ.get("NAMAZU_PACKAGED_BACKEND"):
                sys.executable = str(ROOT / ".venv/Scripts/python.exe")
            host = Host(args.output.resolve())
        finally:
            sys.executable = interpreter
        assert host.reply["ready"] is True, host.reply
        result = run(host.reply["origin"], host.secret, args.output)
        print(json.dumps({"passed": result["passed"], "layout_cases": len(result["layout_cases"]), "surface": result["surface"]}))
    finally:
        if host:
            host.close()
        if original is None:
            os.environ.pop("NAMAZU_PACKAGED_BACKEND", None)
        else:
            os.environ["NAMAZU_PACKAGED_BACKEND"] = original


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", type=Path)
    parser.add_argument("--output", type=Path, default=Path(".local-reports/header-source"))
    main(parser.parse_args())
