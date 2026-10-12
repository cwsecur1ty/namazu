"""Optional Playwright smoke/visual capture against a running LOCAL Namazu only.

python tests/bruno_ui.py --port 8807 --output .local-reports/bruno-ui
Requires playwright and its Chromium browser; never starts an audit.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

FIXTURES = Path(__file__).parent / "fixtures" / "bruno"


def run(port, output):
    output.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        for width, height, label in ((1440, 1000, "desktop"), (390, 844, "narrow")):
            page = browser.new_page(viewport={"width": width, "height": height})
            errors, prohibited, requests = [], [], []
            page.on("pageerror", lambda error, errors=errors: errors.append(str(error)))
            page.on("request", lambda request, requests=requests: requests.append(request.url))

            def route_request(route, prohibited=prohibited):
                parsed = urlsplit(route.request.url)
                if parsed.scheme == "blob" or (parsed.hostname == "127.0.0.1" and parsed.port == port):
                    route.continue_()
                else:
                    prohibited.append(route.request.url)
                    route.abort()

            page.route("**/*", route_request)
            page.goto(f"http://127.0.0.1:{port}")
            page.locator("#spec-file").set_input_files(FIXTURES / "openapi.json")
            page.locator("#import-submit").click()
            expect(page.locator("#fact-title")).to_contain_text("Bruno loopback fixture")
            page.locator("#bruno-open").click()
            dialog = page.locator("#bruno-dialog")
            report_file = dialog.locator('input[type="file"]').nth(0)
            report_file.set_input_files(FIXTURES / "report.json")
            expect(page.locator("#bruno-summary")).to_contain_text("14 recorded executions")
            expect(page.locator("#bruno-summary")).to_contain_text("12 HTTP responses")
            expect(dialog.locator(".bruno-row")).to_have_count(14)
            report_file.set_input_files(FIXTURES / "report.json")
            expect(dialog.locator(".bruno-row")).to_have_count(14)
            page.screenshot(path=str(output / f"{label}-import.png"))
            # Native log/report viewing is historical; it cannot replay a request.
            dialog.get_by_role("button", name="Open in Namazu evidence views").click()
            expect(page.locator("#audit-report-body")).to_contain_text("Imported Bruno run")
            expect(page.locator("#audit-report-body")).to_contain_text("Exact wire attempts")
            assert page.locator("#audit-report-body").evaluate("node => node.scrollWidth <= node.clientWidth + 1"), "Imported report overflows at narrow widths"
            with page.expect_download() as saved_report:
                page.locator("#export-audit-top").click()
            exported_path = output / f"{label}-evidence.json"
            saved_report.value.save_as(exported_path)
            exported = json.loads(exported_path.read_text(encoding="utf-8"))
            assert len(exported["requests"]) == 14
            assert exported["scope"]["requests_sent"] is None
            assert exported["provenance"]["requests_sent_during_current_action"] == 0
            assert exported["requests"][0]["exchange_id"] == exported["bruno"]["executions"][0]["id"]
            page.screenshot(path=str(output / f"{label}-results.png"))
            page.get_by_role("button", name="Inspect captured requests and responses").click()
            page.locator("#log-rows tr").first.click()
            expect(page.locator("#log-request-body")).to_contain_text("absent or omitted")
            expect(page.locator("#log-response-body")).to_contain_text("local-widget")
            expect(page.locator("#log-response-body")).to_contain_text("wire size unknown")
            page.locator("#bruno-open").click()
            dialog.locator("input[webkitdirectory]").set_input_files(FIXTURES / "collection")
            expect(page.locator("#bruno-environment")).to_be_visible()
            page.locator("#bruno-environment").select_option("Local")
            dialog.get_by_role("button", name="Resolve selected environment").click()
            expect(dialog.locator(".bruno-row")).to_have_count(7)
            dialog.locator('.bruno-row input[type="checkbox"]').first.check()
            dialog.locator(".bruno-mapping > summary").click()
            page.locator("#bruno-operation").select_option("GET /ok")
            page.locator("#bruno-identity").select_option("primary")
            for name, value in {"expected": "200", "resource-pointer": "/id", "resource-value": "local-widget", "content-pointer": "/owner", "content-value": "fixture-user"}.items():
                page.locator("#bruno-" + name).fill(value)
            page.locator("#bruno-identity-confirmed").check()
            page.locator("#bruno-expected").scroll_into_view_if_needed()
            page.screenshot(path=str(output / f"{label}-mapping.png"))
            dialog.get_by_role("button", name="Prepare and save baseline template").click()
            expect(page.locator("#bruno-prepared")).to_contain_text("Prepared offline")
            # Storage denial must not be reported as saved.
            page.evaluate("() => {window.originalStorageWrite = Storage.prototype.setItem; Storage.prototype.setItem = function(){throw Error('synthetic full storage')};}")
            page.locator("#bruno-resource-value").fill("another-local-widget")
            dialog.get_by_role("button", name="Prepare and save baseline template").click()
            expect(dialog.locator('[role="alert"]')).to_contain_text("was not saved")
            page.evaluate("() => {Storage.prototype.setItem = window.originalStorageWrite;}")
            dialog.get_by_role("button", name="Choose Namazu requests to export").click()
            baseline = dialog.locator(".bruno-row").filter(has_text="Prepared baseline: GET /ok")
            baseline.locator('input[type="checkbox"]').check()
            dialog.get_by_role("button", name="Preview conversion").click()
            expect(page.locator("#bruno-export-preview")).to_contain_text("bruno.json")
            expect(page.locator("#bruno-export-warnings")).to_contain_text("No roundtrip fidelity")
            download_button = dialog.get_by_role("button", name="Download Bruno collection (.zip)")
            expect(download_button).to_be_disabled()
            page.locator("#bruno-export-reviewed").check()
            download_button.scroll_into_view_if_needed()
            page.screenshot(path=str(output / f"{label}-export.png"))
            with page.expect_download() as download:
                download_button.click()
            download.value.save_as(output / f"{label}-collection.zip")
            assert dialog.evaluate("node => node.scrollWidth <= node.clientWidth + 1"), "Dialog has horizontal overflow"
            assert not errors, errors
            assert not prohibited, prohibited
            assert not any(urlsplit(url).path in {"/api/run", "/api/send", "/api/audit", "/api/audit/runs"} for url in requests), requests
            (output / f"{label}-network.json").write_text(json.dumps({"requests": requests, "page_errors": errors, "prohibited": prohibited}, indent=2), encoding="utf-8")
            print(f"{label}: import, duplicate import, native results, mapping, failed persistence and export passed; no target requests", flush=True)
            page.close()
        browser.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8807)
    parser.add_argument("--output", type=Path, default=Path(".local-reports/bruno-ui"))
    arguments = parser.parse_args()
    run(arguments.port, arguments.output)
