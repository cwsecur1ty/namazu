"""Main workbench journeys and measurements; supports the packaged WebView2 via CDP.

Only local fixtures are imported or contacted. This tests product behavior,
not API security coverage. Diagnostic CDP must be explicitly enabled at launch.
"""
from __future__ import annotations

import argparse
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from playwright.sync_api import expect, sync_playwright


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.server.attempts.append({"path": self.path, "credential": "authorization" in self.headers})
        if self.path == "/slow":
            time.sleep(1.2)
        body = ("<script>window.localHtmlExecuted=true</script><img src='file:///C:/unsafe'>" if self.path == "/html"
                else json.dumps({"local": True, "padding": "x" * (1500000 if self.path == "/large" else 1)}))
        raw = body.encode()
        self.send_response(200)
        self.send_header("content-type", "text/html" if self.path == "/html" else "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def api(page, path, body=None, method="GET"):
    return page.evaluate("""async ({path,body,method}) => {
      const r=await fetch(path,{method,headers:{'Content-Type':'application/json'},...(method==='GET'?{}:{body:JSON.stringify(body)})});
      const result=await r.json(); if(!r.ok) throw Error(JSON.stringify(result)); return result;
    }""", {"path": path, "body": body, "method": method})


def ready(page):
    expect(page.locator("#desktop-workbench")).to_have_attribute("data-ready", "true", timeout=20000)


def click_tree(page, title, method="GET", path="/widgets/{id}"):
    if not page.locator("#desktop-sidebar").is_visible():
        page.locator("#desktop-sidebar-toggle").click()
    page.locator("#desktop-search").fill("")
    page.get_by_role("button", name=f"Open {title}: {method} {path}", exact=True).click()
    expect(page.locator("#desktop-request")).to_be_visible()


def journey(page, output, label, fixture):
    output.mkdir(parents=True, exist_ok=True)
    ready(page)
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    metrics = {"surface": label, "startup_frontend_ms": page.evaluate("window.NamazuDesktop.diagnostics().startupMs")}
    page.locator("#desktop-home").click()
    page.screenshot(path=str(output / f"{label}-first-launch.png"))
    page.locator("#desktop-welcome-sample").click()
    expect(page.locator("#desktop-request-url")).to_have_value(re.compile(r"/widgets/17$"))
    ws = api(page, "/api/workspaces/" + page.locator("#desktop-workspace").input_value())
    first, second = ws["contracts"]
    assert not fixture.attempts
    page.locator("#desktop-request-url").fill(first["target"] + "/widgets/17?draft=accounts")
    page.locator("#desktop-editor-tabs").get_by_role("tab", name="Assertions", exact=True).click()
    page.get_by_label("Response assertions JSON").fill('{"status":"200","pointer":"/id","pointer_equals":"17"}')
    page.locator("#desktop-save-draft").click()
    click_tree(page, second["title"])
    page.locator("#desktop-editor-tabs").get_by_role("tab", name="Assertions", exact=True).click()
    expect(page.get_by_label("Response assertions JSON")).to_have_value("{}")
    page.locator("#desktop-request-url").fill(second["target"] + "/widgets/17?draft=orders")
    started = time.perf_counter()
    page.locator(".desktop-tab-label").first.click()
    expect(page.locator("#desktop-request-url")).to_have_value(first["target"] + "/widgets/17?draft=accounts")
    metrics["tab_switch_ms"] = round((time.perf_counter() - started) * 1000, 2)
    page.locator("#desktop-send").click()
    expect(page.locator("#desktop-response-meta")).to_contain_text("HTTP 200", timeout=15000)
    page.locator("#desktop-response-tabs").get_by_role("tab", name="Validation", exact=True).click()
    expect(page.locator("#desktop-response")).to_contain_text('"valid": true')
    page.locator("#desktop-response-tabs").get_by_role("tab", name="Exchange", exact=True).click()
    expect(page.locator("#desktop-response")).to_contain_text(first["hash"])
    page.screenshot(path=str(output / f"{label}-request-evidence.png"))
    history = api(page, "/api/desktop/requests")["requests"]
    record = api(page, "/api/desktop/requests/" + history[0]["request_id"])
    assert record["requests_sent"] == 1
    assert record["result"]["request"]["has_body"] is False
    assert record["result"]["assertions"]["valid"] is True
    assert "result" not in history[0]
    page.locator("#desktop-menu-open").click()
    page.locator("#desktop-environments").click()
    page.get_by_label("Environment name", exact=True).fill("Local variables")
    page.get_by_label("Variables (JSON object, no credentials)").fill('{"widget":"17"}')
    page.get_by_role("button", name="Save environment", exact=True).click()
    expect(page.locator("#desktop-environment").locator("option")).to_have_count(2)
    page.locator("#desktop-environment").select_option(label="Local variables")
    expect(page.locator("#desktop-request-url")).not_to_have_value(re.compile("draft=accounts"))
    page.locator("#desktop-layout-toggle").click()
    page.locator("#desktop-menu-open").click()
    page.locator("#desktop-theme").click()
    expected_layout = page.locator("#desktop-workbench").get_attribute("class")
    page.evaluate("window.NamazuDesktop.flush()")
    before = len(api(page, "/api/desktop/requests")["requests"])
    page.reload()
    ready(page)
    assert len(api(page, "/api/desktop/requests")["requests"]) == before
    expect(page.locator("#desktop-workbench")).to_have_class(expected_layout)
    page.screenshot(path=str(output / f"{label}-restored-light.png"))

    # Inert response markup, cancellation and large response capture use one
    # dedicated loopback fixture, separate from the example sample server.
    doc = {"openapi": "3.0.3", "info": {"title": "Local response boundaries", "version": "1"},
           "servers": [{"url": fixture.base}], "paths": {path: {"get": {"responses": {"200": {"description": "Local only"}}}} for path in ("/html", "/slow", "/large")}}
    api(page, f"/api/workspaces/{ws['id']}/contracts/import", {"items": [{"raw_spec": doc}]}, "POST")
    page.reload()
    ready(page)
    for path in ("/html", "/slow", "/large"):
        click_tree(page, "Local response boundaries", path=path)
        started = time.perf_counter()
        page.locator("#desktop-send").click()
        if path == "/slow":
            deadline = time.monotonic() + 5
            while not any(attempt["path"] == path for attempt in fixture.attempts) and time.monotonic() < deadline:
                page.wait_for_timeout(20)
            assert any(attempt["path"] == path for attempt in fixture.attempts), "Slow exchange never dispatched"
            expect(page.locator("#desktop-cancel")).to_be_visible()
            page.locator("#desktop-cancel").click()
        expect(page.locator("#desktop-response-meta")).to_contain_text("HTTP 200", timeout=20000)
        if path == "/html":
            assert page.evaluate("window.localHtmlExecuted === undefined")
            expect(page.locator("#desktop-response")).to_contain_text("<script>")
        if path == "/large":
            metrics["large_response_send_and_display_ms"] = round((time.perf_counter() - started) * 1000, 2)
            metrics["large_response_bytes"] = 1500030
            page.screenshot(path=str(output / f"{label}-large-response.png"))
    assert len(fixture.attempts) == 3, fixture.attempts
    assert not any(attempt["credential"] for attempt in fixture.attempts)

    # A 1,200-operation contract exercises a bounded collection tree. Import
    # setup through the same API is offline; navigation itself uses the UI.
    large = {"openapi": "3.0.3", "info": {"title": "Large local contract", "version": "1"},
             "servers": [{"url": fixture.base}], "paths": {f"/items/{index:04d}": {"get": {
                 "tags": ["Items"], "summary": f"Operation {index:04d}", "responses": {"200": {"description": "Fixture"}}}}
                 for index in range(1200)}}
    started = time.perf_counter()
    api(page, f"/api/workspaces/{ws['id']}/contracts/import", {"items": [{"raw_spec": large}]}, "POST")
    metrics["large_contract_import_ms"] = round((time.perf_counter() - started) * 1000, 2)
    page.reload()
    ready(page)
    metrics["large_tree_render_ms"] = page.evaluate("window.NamazuDesktop.diagnostics().treeRenderMs")
    assert page.locator(".desktop-operation").count() < 150
    if not page.locator("#desktop-sidebar").is_visible():
        page.locator("#desktop-sidebar-toggle").click()
    started = time.perf_counter()
    page.locator("#desktop-search").fill("Operation 1199")
    page.get_by_role("button", name="Open Large local contract: GET /items/1199", exact=True).click()
    metrics["large_tree_search_and_open_ms"] = round((time.perf_counter() - started) * 1000, 2)
    page.screenshot(path=str(output / f"{label}-large-contract.png"))
    assert len(fixture.attempts) == 3
    # Historical fixture: 1,200 retained cases, no new dispatch. Exact evidence
    # loads only when its outcome group is opened, then in visible pages.
    capture = {"label": "baseline", "method": "POST", "url": fixture.base + "/saved-only",
               "request_headers": {}, "request_body": '{"enabled":true}', "status": 403,
               "response_headers": {"Content-Type": "application/json"},
               "response_body": '{"error":"not entitled"}'}
    plans = [{"id": f"retained-{i}", "operation": "POST /saved-only", "field_pointer": "/enabled",
              "location": "body", "mutation": f"local-fixture-{i}", "status": "planned", "planned_requests": 1}
             for i in range(1200)]
    probes = [{**plan, "status": "same-denial-as-baseline", "request_sent": True,
               "exchange": {**capture, "label": plan["id"], "request_body": '{"enabled":null}'}} for plan in plans]
    report = {"application": "Namazu", "export": "security-audit", "started_at": "2026-10-09T08:20:43Z",
              "api": {"title": "Large local historical fixture", "base_url": fixture.base, "version": "1"},
              "scope": {"requests_sent": 1201, "endpoints_audited": 1, "endpoints_in_scope": 1}, "findings": [],
              "test_plans": [{"endpoint": "POST /saved-only", "operation_id": "POST /saved-only",
                              "test_plan": {"operation": "POST /saved-only", "probes": plans}}],
              "coverage": {"probes": probes, "baselines": [{"endpoint": "POST /saved-only", "exchange": capture}]},
              "requests": [capture, *[probe["exchange"] for probe in probes]]}
    page.locator("#desktop-advanced").click()
    page.locator("#desktop-expert-nav").get_by_role("button", name="Audit / tools", exact=True).click()
    started = time.perf_counter()
    page.locator("#import-audit-file").set_input_files({"name": "large-retained.json", "mimeType": "application/json",
                                                       "buffer": json.dumps(report).encode()})
    expect(page.locator("#toast")).to_contain_text("Opened historical evidence from large-retained.json", timeout=30000)
    metrics["large_report_import_and_render_ms"] = round((time.perf_counter() - started) * 1000, 2)
    results = page.locator("#audit-report-body .test-results")
    assert results.locator("tbody tr").count() == 0
    results.locator(".test-field > summary").first.click()
    started = time.perf_counter()
    results.locator(".test-response-group > summary").first.click()
    expect(results.locator(".test-case-table tbody tr")).to_have_count(100)
    metrics["large_report_group_open_ms"] = round((time.perf_counter() - started) * 1000, 2)
    results.get_by_role("button", name="Show next 100 cases", exact=True).click()
    expect(results.locator(".test-case-table tbody tr")).to_have_count(200)
    page.screenshot(path=str(output / f"{label}-large-saved-report.png"))
    assert len(fixture.attempts) == 3
    metrics["large_report_retained_cases"] = 1200
    metrics.update(page_errors=errors, fixture_attempts=len(fixture.attempts), large_contract_operations=1200,
                   restore_replayed_requests=0, schema_names_isolated=True)
    assert not errors, errors
    (output / f"{label}-metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))


def run(args):
    fixture = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    fixture.daemon_threads = True
    fixture.base = f"http://127.0.0.1:{fixture.server_port}"
    fixture.attempts = []
    threading.Thread(target=fixture.serve_forever, daemon=True).start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.connect_over_cdp(args.cdp) if args.cdp else playwright.chromium.launch(headless=True)
            page = browser.contexts[0].pages[0] if args.cdp else browser.new_page(viewport={"width": 1440, "height": 1000})
            if not args.cdp:
                page.goto(args.url)
            try:
                journey(page, args.output, "packaged" if args.cdp else "browser", fixture)
            except Exception:
                page.screenshot(path=str(args.output / "failure.png"))
                print(json.dumps({"fixture_attempts": fixture.attempts,
                                  "desktop_error": page.locator("#desktop-error").text_content(),
                                  "status": page.locator("#desktop-status").text_content()}))
                raise
            if not args.cdp:
                browser.close()
    finally:
        fixture.shutdown()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8811")
    parser.add_argument("--cdp")
    parser.add_argument("--output", type=Path, default=Path(".local-reports/desktop-main"))
    run(parser.parse_args())
