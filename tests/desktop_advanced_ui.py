"""Advanced desktop journeys against isolated loopback fixtures only.

Run from the repository: python tests/desktop_advanced_ui.py
Use --cdp http://127.0.0.1:PORT to inspect an already running native WebView2.
Source mode owns and terminates its backend, keeping state under its output.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import site
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
if (ROOT / ".venv/Lib/site-packages").is_dir():
    site.addsitedir(str(ROOT / ".venv/Lib/site-packages"))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from ux_fixture_server import (  # noqa: E402
    ASSERTIONS,
    FixtureServer,
    known_good,
    old_mixed_report,
    permission_matrix,
    receipt,
    successful_report,
)


def run(port, output, cdp=None, *, external_origin=None, session_secret=None):
    output.mkdir(parents=True, exist_ok=True)
    fixture = FixtureServer(0)
    threading.Thread(target=fixture.serve_forever, daemon=True).start()
    process = None
    host_log = None
    base = external_origin or f"http://127.0.0.1:{port}"
    if external_origin:
        port = urlsplit(external_origin).port
    checks, errors, prohibited, narrow_overflows = [], [], [], []
    started = time.monotonic()
    try:
        if not cdp and not external_origin:
            host_log = (output / "backend.log").open("w", encoding="utf-8")
            environment = {**os.environ, "NAMAZU_STATE_DIR": str(output / ("state-" + uuid.uuid4().hex)), "NAMAZU_DESKTOP": "1"}
            backend_python = ROOT / ".venv/Scripts/python.exe"
            process = subprocess.Popen([str(backend_python) if backend_python.exists() else sys.executable, "-m", "uvicorn", "namazu.app:app", "--host", "127.0.0.1", "--port", str(port)],
                                       cwd=ROOT, env=environment, stdout=host_log, stderr=subprocess.STDOUT,
                                       creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            for _ in range(120):
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
            browser = playwright.chromium.connect_over_cdp(cdp) if cdp else playwright.chromium.launch(headless=True)
            page = browser.contexts[0].pages[0] if cdp else browser.new_page(viewport={"width": 1440, "height": 1000},
                extra_http_headers={"X-Namazu-Session": session_secret} if session_secret else {})
            if cdp:
                base = page.url.split("?")[0].rstrip("/")
                port = urlsplit(base).port
            page.set_default_timeout(12000)
            page.on("pageerror", lambda error: errors.append(str(error)))
            def route_request(route):
                parts = urlsplit(route.request.url)
                if parts.scheme == "blob" or (parts.hostname == "127.0.0.1" and parts.port == port):
                    route.continue_()
                else:
                    prohibited.append(route.request.url)
                    route.abort()
            page.route("**/*", route_request)
            if not cdp:
                page.goto(base)
            expect(page.locator("#desktop-workbench")).to_have_attribute("data-ready", "true", timeout=20000)

            def shot(name):
                page.screenshot(path=str(output / (name + ".png")), full_page=False)

            def narrow_shot(name):
                page.set_viewport_size({"width": 390, "height": 844})
                shot(name + "-narrow")
                narrow_overflows.append({"screen": name, "elements": page.locator("#desktop-expert .view:not([hidden]), #desktop-expert .report").evaluate_all(
                    """nodes => nodes.filter(node => node.getClientRects().length && node.scrollWidth > node.clientWidth + 1).map(node => {
                      const box=node.getBoundingClientRect(); return {id:node.id,width:node.clientWidth,scroll:node.scrollWidth,
                        descendants:[...node.querySelectorAll('*')].filter(child=>child.getClientRects().length && child.getBoundingClientRect().right > box.right + 1).slice(0,12).map(child=>({tag:child.tagName,id:child.id,class:child.className,width:child.clientWidth,scroll:child.scrollWidth,right:child.getBoundingClientRect().right,parent:child.parentElement?.className}))};})""")})
                assert page.locator("#desktop-workbench").evaluate("node => node.scrollWidth <= node.clientWidth + 1"), name + " narrow overflow"
                page.set_viewport_size({"width": 1440, "height": 1000})

            def no_traffic(name, before):
                assert len(fixture.attempts) == before, (name, fixture.attempts[before:])
                checks.append({"journey": name, "target_requests": 0})

            def close_dialogs():
                # Close through the standard Escape interaction; never mutate app state.
                for _ in range(3):
                    if not page.locator("dialog[open]").count():
                        break
                    page.keyboard.press("Escape")

            def expert(name):
                close_dialogs()
                if page.locator("#desktop-expert").is_hidden():
                    page.locator("#desktop-advanced").click()
                page.locator("#desktop-expert-nav").get_by_role("button", name=name, exact=True).click()

            # Documentation resolution, masked identity, missing business data.
            before = len(fixture.attempts)
            expert("Guided setup")
            page.locator("#spec-url").fill(fixture.base + "/docs")
            page.locator("#import-submit").click()
            expect(page.locator("#setup-target")).to_be_visible()
            page.locator("#setup-server").select_option(fixture.base + "/success")
            page.locator("#setup-select-target").click()
            page.locator("#setup-tab-identity").click()
            page.locator("#auth-mode").select_option("bearer")
            page.locator("#bearer-token").fill("local-primary")
            assert page.locator("#bearer-token").get_attribute("type") == "password"
            page.locator("#setup-tab-data").click()
            page.locator("#setup-operation").select_option("POST /summaries")
            expect(page.locator("#setup-fields")).to_contain_text("documentUri")
            page.locator("#setup-tab-readiness").click()
            expect(page.locator("#setup-readiness-items")).to_contain_text(re.compile("baseline|resource|business", re.I))
            shot("01-guided-missing-business-data")
            narrow_shot("01-guided-missing-business-data")
            no_traffic("documentation URL and token do not establish business readiness", before)

            # Local, recorded successful control and an explicitly allowed second identity.
            page.locator("#setup-tab-data").click()
            page.locator("#setup-baseline-details").locator("summary").click()
            readiness = page.locator("#setup-baseline-mount")
            readiness.get_by_label("Known-good request (JSON, one HAR entry, or raw HTTP)").fill(json.dumps(known_good(fixture.base)))
            readiness.get_by_label("Local identity reference", exact=True).fill("primary")
            readiness.locator("summary", has_text="Advanced response assertions").click()
            readiness.get_by_label("Business assertions (JSON array)").fill(json.dumps(ASSERTIONS))
            readiness.locator("summary", has_text="Use an exchange captured elsewhere").click()
            readiness.get_by_label("Recorded successful exchange (optional JSON override)").fill(json.dumps(receipt(fixture.base)))
            readiness.get_by_role("button", name="Review baseline readiness", exact=True).click()
            expect(readiness.locator(".readiness-result")).to_contain_text("Business assertions passed for the recorded baseline")
            shot("02-recorded-successful-control")
            readiness.locator("summary", has_text="Prepare deeper tests or retry incomplete cases").click()
            readiness.get_by_label("Permission matrix (JSON array; explicit allow or deny)").fill(json.dumps(permission_matrix(fixture.base)))
            readiness.get_by_role("button", name="Build follow-up and incomplete-case plan", exact=True).click()
            expect(readiness.locator(".readiness-result")).to_contain_text("Requests sent: 0")
            expect(readiness.locator(".readiness-result")).to_contain_text("secondary")
            shot("03-two-identity-explicit-permission-plan")
            narrow_shot("03-two-identity-explicit-permission-plan")
            no_traffic("recorded baseline and explicit second-identity permission planning", before)

            # Retained reports can be inspected and reassessed without replay.
            close_dialogs()
            for name, report in (("successful", successful_report(fixture.base)),
                                 ("two-identity", successful_report(fixture.base, True)),
                                 ("historical-mixed", old_mixed_report())):
                expert("Audit / tools")
                page.locator("#import-audit-file").set_input_files({"name": name + ".json", "mimeType": "application/json", "buffer": json.dumps(report).encode()})
                expect(page.locator("#toast")).to_contain_text("Opened historical evidence from " + name + ".json")
                expect(page.locator("#view-audit-report")).to_be_visible()
                expect(page.locator("#audit-report-body")).to_contain_text(re.compile("historical|imported|recorded", re.I))
                page.locator("#view-audit-report .view-title").scroll_into_view_if_needed()
                shot("04-report-" + name)
                no_traffic("offline " + name + " report import", before)
                if name == "historical-mixed":
                    body = page.locator("#audit-report-body")
                    expect(body).to_contain_text(re.compile("denial|denied", re.I))
                    review = body.get_by_role("button", name=re.compile("Review retained responses|Refresh offline assessment"))
                    expect(review).to_be_visible()
                    expect(review).to_be_enabled()
                    with page.expect_response(lambda response: response.url.endswith("/api/audit/assess")) as assessed:
                        review.click()
                    assert assessed.value.status == 200
                    expect(review).to_be_enabled()
                    expect(body).to_contain_text("No captured record demonstrates exploitable security impact")
                    expect(body).to_contain_text("141")
                    accounting = body.locator(".evidence-assessment .audit-table").first.locator("tr").evaluate_all(
                        "rows => rows.slice(1).map(row => [...row.querySelectorAll('td')].map(cell => cell.textContent))")
                    assert accounting == [["Endpoint testing", "91", "85", "39", "28", "15", "6"],
                                          ["Inventory and calibration", "50", "50", "0", "0", "4", "0"],
                                          ["Total", "141", "135", "39", "28", "19", "6"]], accounting
                    page.locator("#view-audit-report .view-title").scroll_into_view_if_needed()
                    shot("05-offline-mixed-response-assessment")
                    narrow_shot("05-offline-mixed-response-assessment")
                    no_traffic("offline retained response assessment", before)
                close_dialogs()

            # Imported Bruno source remains data, and conversion remains offline.
            page.locator("#desktop-bruno").click()
            dialog = page.locator("#bruno-dialog")
            expect(dialog).to_be_visible()
            dialog.locator('input[type="file"]').nth(0).set_input_files(ROOT / "tests/fixtures/bruno/report.json")
            expect(page.locator("#bruno-summary")).to_contain_text("Imported Bruno run")
            with page.expect_download() as downloaded:
                dialog.get_by_role("button", name="Export redacted evidence + source", exact=True).click()
            downloaded.value.save_as(output / "bruno-redacted-evidence.json")
            report = json.loads((output / "bruno-redacted-evidence.json").read_text(encoding="utf-8"))
            assert report["provenance"]["requests_sent_during_current_action"] == 0
            dialog.locator('input[type="file"]').nth(1).set_input_files([
                {"name": "bruno.json", "mimeType": "application/json", "buffer": b'{"version":"1","name":"Local QA","type":"collection"}'},
                {"name": "local.bru", "mimeType": "text/plain", "buffer": ("meta {\n name: Local fixture\n type: http\n seq: 1\n}\nget {\n url: " + fixture.base + "/success/identity\n body: none\n auth: none\n}\n").encode()}])
            expect(page.locator("#bruno-summary")).to_contain_text("1 request definitions")
            page.locator("#bruno-results input[type=checkbox]").first.check()
            dialog.get_by_role("button", name="Preview conversion", exact=True).click()
            expect(page.locator("#bruno-export-preview")).to_be_visible()
            page.locator("#bruno-export-reviewed").check()
            with page.expect_download() as downloaded:
                dialog.get_by_role("button", name="Download Bruno collection (.zip)", exact=True).click()
            downloaded.value.save_as(output / "bruno-collection.zip")
            shot("06-bruno-offline-conversion")
            narrow_shot("06-bruno-offline-conversion")
            no_traffic("Bruno report import, definition import and exports", before)
            close_dialogs()

            # Explicit browser migration sanitises data before it can be applied.
            page.locator(".desktop-operation").first.click()
            expert("Connection / settings")
            legacy_key = "namazu-examples:Legacy local fixture:" + fixture.base
            preference_export = {"format": "namazu-browser-preferences", "version": 1, "preferences": {
                "namazu-theme": "dark", "namazu-layout": "rows", legacy_key: json.dumps({"POST /summaries": {
                    "example": {"url": fixture.base + "/success/summaries", "headers": {"Authorization": "Bearer legacy-import-secret"},
                                "body": {"documentUri": "doc-local", "password": "never-save-this"}}, "expectation": {"status": 200}}})}}
            migration = page.locator("#desktop-migration")
            migration.locator("input[type=file]").set_input_files({"name": "preferences.json", "mimeType": "application/json", "buffer": json.dumps(preference_export).encode()})
            expect(page.locator("#desktop-status")).to_contain_text("Nonsecret preferences imported")
            migration.get_by_role("button", name="Assign selected test data to this contract context", exact=True).click()
            expect(page.locator("#desktop-status")).to_contain_text("Selected draft templates assigned")
            assert not page.locator("#allow-writes").is_checked()
            with page.expect_download() as downloaded:
                migration.get_by_role("button", name="Export browser preferences / test data", exact=True).click()
            downloaded.value.save_as(output / "browser-preferences-redacted.json")
            preference_text = (output / "browser-preferences-redacted.json").read_text(encoding="utf-8")
            assert "legacy-import-secret" not in preference_text and "never-save-this" not in preference_text
            migration.scroll_into_view_if_needed()
            shot("07-explicit-browser-preferences-migration")
            no_traffic("explicit browser preference migration and selected-context assignment", before)

            # Discoverability and narrow layout for retained expert destinations.
            for label in ("OAuth / identity", "Baseline / readiness", "Schemas", "Runner", "Access / sequences", "History", "Traffic", "Connection / settings"):
                expert(label)
                expect(page.locator("#desktop-expert")).to_be_visible()
                checks.append({"journey": "expert navigation: " + label, "discoverable": True})
            expert("Access / sequences")
            expect(page.locator("#view-access")).to_be_visible()
            expect(page.get_by_role("button", name=re.compile("Run matrix", re.I))).to_be_visible()
            shot("07-expert-access-sequences")
            for width, label in ((390, "narrow"), (1440, "desktop")):
                page.set_viewport_size({"width": width, "height": 844 if width < 500 else 1000})
                expert("Connection / settings")
                shot("08-settings-" + label)
                assert page.locator("#desktop-workbench").evaluate("node => node.scrollWidth <= node.clientWidth + 1"), label + " desktop overflow"
            no_traffic("advanced discovery and layout inspection", before)
            assert not errors, errors
            assert not prohibited, prohibited
            if not cdp:
                browser.close()
            else:
                page.unroute("**/*", route_request)
        result = {"status": "passed", "mode": "native-cdp" if cdp else "packaged-backend-headless" if external_origin else "source-browser", "checks": checks,
                  "elapsed_seconds": round(time.monotonic() - started, 2), "api_target_requests": len(fixture.attempts),
                  "page_errors": errors, "external_browser_requests": prohibited,
                  "narrow_nested_overflows": narrow_overflows,
                  "boundary": "Local product behavior only; no API security coverage claimed."}
        (output / "report.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2))
    finally:
        fixture.shutdown()
        fixture.server_close()
        if process:
            process.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=5)
            if process.poll() is None:
                process.kill()
        if host_log:
            host_log.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8864)
    parser.add_argument("--output", type=Path, default=ROOT / ".local-reports/desktop-advanced")
    parser.add_argument("--cdp")
    arguments = parser.parse_args()
    run(arguments.port, arguments.output.resolve(), arguments.cdp)
