"""Offline detection journeys: isolated source host or explicitly enabled CDP.

Only the loopback application is contacted. A local target counts unexpected
dispatches; the supplied callback.test host is never contacted or resolved.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.server.attempts.append(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"local":true}')

    do_POST = do_GET


def api(page, path, body=None, method="GET"):
    return page.evaluate("""async ({path,body,method}) => {
      const r=await fetch(path,{method,headers:{'Content-Type':'application/json'},...(method==='GET'?{}:{body:JSON.stringify(body)})});
      const result=await r.json(); if(!r.ok) throw Error(JSON.stringify(result)); return result;
    }""", {"path": path, "body": body, "method": method})


def run(args, *, external_origin=None, session_secret=None):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    fixture = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    fixture.attempts = []
    fixture.daemon_threads = True
    threading.Thread(target=fixture.serve_forever, daemon=True).start()
    process = log = None
    base = external_origin or args.url or f"http://127.0.0.1:{args.port}"
    errors, blocked, checks, widths = [], [], [], []
    started = time.monotonic()
    try:
        if not external_origin and not args.url and not args.cdp:
            log = (output / "backend.log").open("w", encoding="utf-8")
            env = {**os.environ, "NAMAZU_STATE_DIR": str(output / ("state-" + uuid.uuid4().hex)), "NAMAZU_DESKTOP": "1"}
            executable = ROOT / ".venv/Scripts/python.exe"
            process = subprocess.Popen([str(executable) if executable.exists() else sys.executable, "-m", "uvicorn", "namazu.app:app", "--host", "127.0.0.1", "--port", str(args.port)],
                                       cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
                                       creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            for _ in range(150):
                try:
                    with urlopen(base + "/api/health", timeout=1):
                        break
                except OSError:
                    if process.poll() is not None:
                        raise RuntimeError("Isolated backend failed; inspect backend.log") from None
                    time.sleep(0.1)
            else:
                raise RuntimeError("Isolated backend did not become ready")
        with sync_playwright() as playwright:
            browser = playwright.chromium.connect_over_cdp(args.cdp) if args.cdp else playwright.chromium.launch(headless=True)
            page = browser.contexts[0].pages[0] if args.cdp else browser.new_page(viewport={"width": 1440, "height": 1000},
                extra_http_headers={"X-Namazu-Session": session_secret} if session_secret else {})
            if args.cdp:
                base = page.url.split("?")[0].rstrip("/")
            origin = urlsplit(base)
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.set_default_timeout(15000)
            def route_request(route):
                url = urlsplit(route.request.url)
                if url.scheme == "blob" or (url.hostname == origin.hostname and url.port == origin.port):
                    route.continue_()
                else:
                    blocked.append(route.request.url)
                    route.abort()
            page.route("**/*", route_request)
            if not args.cdp:
                page.goto(base)
            expect(page.locator("#desktop-workbench")).to_have_attribute("data-ready", "true", timeout=20000)

            target = f"http://127.0.0.1:{fixture.server_port}/v1"
            schema = {"type": "object", "required": ["callbackUrl"], "properties": {"callbackUrl": {"type": "string", "example": "local-placeholder"}, "count": {"type": "integer", "minimum": 1, "maximum": 3}}}
            document = {"openapi": "3.0.3", "info": {"title": "Local detection fixture", "version": "1"}, "servers": [{"url": target}], "paths": {
                "/deliver": {"post": {"operationId": "same", "requestBody": {"required": True, "content": {"application/json": {"schema": schema}}}, "responses": {"200": {"description": "Mock"}}}},
                "/inspect": {"get": {"parameters": [{"in": "query", "name": "count", "schema": {"type": "integer", "minimum": 1}}], "responses": {"200": {"description": "Mock"}}}}}}
            ws = api(page, "/api/workspaces", {"title": "Offline detection journey"}, "POST")
            ws = api(page, f"/api/workspaces/{ws['id']}/contracts/import", {"items": [{"raw_spec": document}]}, "POST")
            contract = ws["contracts"][0]
            api(page, f"/api/workspaces/{ws['id']}/profiles", {"id": "local-shared", "token": "local-oob-secret"}, "POST")
            api(page, f"/api/workspaces/{ws['id']}/contracts/{contract['id']}/identity", {"profile_id": "local-shared", "allowed_scopes": [target]}, "PUT")
            initial_requests = len(api(page, "/api/desktop/requests")["requests"])
            page.reload()
            expect(page.locator("#desktop-workbench")).to_have_attribute("data-ready", "true", timeout=20000)
            page.locator("#desktop-workspace").select_option(ws["id"])
            page.get_by_role("button", name="Open Local detection fixture: POST /deliver", exact=True).click()
            page.locator("#desktop-write-consent").check()

            def shot(name):
                page.screenshot(path=str(output / (name + ".png")), full_page=False)
                page.set_viewport_size({"width": 390, "height": 844})
                page.screenshot(path=str(output / (name + "-narrow.png")), full_page=False)
                measured = page.locator("#desktop-workbench, #desktop-testing, #desktop-workspace-review").evaluate_all(
                    "nodes=>nodes.filter(n=>n.getClientRects().length).map(n=>({id:n.id,width:n.clientWidth,scroll:n.scrollWidth}))")
                assert all(row["scroll"] <= row["width"] + 1 for row in measured), measured
                widths.append({"screen": name, "elements": measured})
                page.set_viewport_size({"width": 1440, "height": 1000})

            def open_testing():
                with page.expect_response(lambda response: "/api/oob/cases?workspace_id=" in response.url and response.request.method == "GET") as loaded:
                    page.locator("#desktop-testing-open").click()
                loaded.value.body()
                page.evaluate("() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))")

            open_testing()
            pane = page.locator("#desktop-testing")
            pane.get_by_label("Explicit callback base URL", exact=True).fill("https://session123.callback.test")
            pane.get_by_label("Field name or JSON pointer", exact=True).fill("/callbackUrl")
            pane.get_by_label("I control this callback session and authorise its use", exact=True).check()
            pane.get_by_role("button", name="Prepare OOB case in this request", exact=True).click()
            expect(pane.locator(".desktop-oob-case")).to_have_count(1)
            case = api(page, "/api/oob/cases?workspace_id=" + ws["id"])["cases"][0]
            assert case["can_use_payload"] and case["context"]["snapshot_hash"] == contract["hash"]
            assert case["accounting"]["new_target_requests"] == 0
            shot("01-prepared-callback-case")
            pane.get_by_role("button", name="Review current request", exact=True).click()
            expect(page.locator("#desktop-write-consent")).not_to_be_checked()
            page.locator("#desktop-editor-tabs").get_by_role("tab", name="Body", exact=True).click()
            assert json.loads(page.locator("#desktop-request-body").input_value())["callbackUrl"] == case["payload"]
            assert not fixture.attempts
            checks.append("explicit callback preparation inserts exact scoped draft without dispatch or write consent")

            open_testing()
            details = pane.locator(".desktop-oob-case").first
            if details.get_attribute("open") is None:
                details.locator("summary").first.click()
            matching = {"protocol": "http", "full-id": case["correlation_full_id"], "unique-id": "session123", "timestamp": case["created_at"],
                        "raw-request": "GET / HTTP/1.1\r\nHost: " + case["callback_host"] + "\r\nAuthorization: Bearer local-oob-secret\r\n\r\n",
                        "raw-response": "<script>window.oobMarkupExecuted=true</script> local-oob-secret"}
            other = {**matching, "full-id": "n-other.session123", "raw-request": "GET / HTTP/1.1\r\nHost: n-other.session123.callback.test\r\n\r\n"}
            details.get_by_label("Interactsh events (JSONL)", exact=True).fill("\n".join(map(json.dumps, [matching, other, matching])))
            details.get_by_label("Collector source name", exact=True).fill("Local synthetic Interactsh fixture")
            details.get_by_role("button", name="Correlate imported events", exact=True).click()
            expect(pane).to_contain_text("1 imported interactions")
            details = pane.locator(".desktop-oob-case").first
            details.get_by_text("Matched interaction records (1)", exact=True).click()
            expect(details).to_contain_text("imported-unverified")
            expect(details).to_contain_text("sanitised-structured-json")
            assert "local-oob-secret" not in details.inner_text()
            assert page.evaluate("window.oobMarkupExecuted === undefined")
            current = api(page, "/api/oob/cases/" + case["id"])
            assert current["accounting"] == {"linked_existing_attempts": 0, "imported_interactions": 1, "unmatched_interactions": 1, "new_target_requests": 0, "demonstrated_vulnerabilities": 0}
            assert current["imports"][0]["duplicates"] == 1 and current["interactions"][0]["redacted"]
            shot("02-correlated-unverified-evidence")
            checks.append("exact and other-case imports separate, repeated event deduplicates, credentials mask and markup stays inert")

            with page.expect_download() as download:
                details.get_by_role("button", name="Export OOB evidence", exact=True).click()
            export_path = output / "local-oob-evidence.json"
            download.value.save_as(export_path)
            exported = json.loads(export_path.read_text(encoding="utf-8"))
            assert exported["format"] == "namazu-oob-evidence" and "local-oob-secret" not in export_path.read_text(encoding="utf-8")
            pane.locator(".desktop-testing-evidence > input[type=file]").set_input_files(str(export_path))
            expect(pane.locator(".desktop-oob-case")).to_have_count(2)
            historical = api(page, "/api/oob/cases?workspace_id=" + ws["id"])["cases"]
            restored = next(item for item in historical if item["historical"])
            assert not restored["can_use_payload"] and restored["retired"]
            checks.append("export opens as separate read-only historical unverified evidence without replay")

            pane.get_by_label("Native campaign profile", exact=True).select_option("readonly")
            pane.get_by_label("Campaign shared request limit", exact=True).fill("17")
            pane.get_by_label("Campaign requests per second", exact=True).fill("1")
            pane.get_by_label("Campaign shared concurrency", exact=True).fill("2")
            with page.expect_response(lambda response: response.url.endswith(f"/api/workspaces/{ws['id']}/plan") and response.request.method == "POST") as response:
                pane.get_by_role("button", name="Review native fuzzing plan", exact=True).click()
            plan = response.value.json()
            plan = plan.get("plan", plan)
            expect(page.locator("#desktop-workspace-review")).to_be_visible()
            assert plan["options"]["profile"] == "readonly" and plan["traffic"]["shared_request_budget"] == 17
            assert plan["traffic"]["concurrency"] == 2 and not plan["traffic"]["inventory"]
            assert any(row.get("engine_plan", {}).get("test_plan", {}).get("probes") for row in plan["operations"])
            assert not api(page, f"/api/workspaces/{ws['id']}")["runs"]
            shot("03-offline-native-campaign-plan")
            checks.append("native schema fuzzing uses existing offline field/case plan, shared limits and no automatic start")
            assert not fixture.attempts and not blocked and not errors, (fixture.attempts, blocked, errors)
            assert len(api(page, "/api/desktop/requests")["requests"]) == initial_requests
            report = {"status": "passed", "surface": "native-cdp" if args.cdp else "packaged-backend-headless" if external_origin else "source-browser", "checks": checks,
                      "target_requests": 0, "external_browser_requests": blocked, "page_errors": errors,
                      "narrow_widths": widths, "duration_seconds": round(time.monotonic() - started, 2)}
            (output / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(json.dumps(report, indent=2))
            if not args.cdp:
                browser.close()
    finally:
        fixture.shutdown()
        fixture.server_close()
        if process:
            process.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=10)
            if process.poll() is None:
                process.kill()
        if log:
            log.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8865)
    parser.add_argument("--url")
    parser.add_argument("--cdp")
    parser.add_argument("--output", type=Path, default=ROOT / ".local-reports/desktop-detection")
    run(parser.parse_args())
