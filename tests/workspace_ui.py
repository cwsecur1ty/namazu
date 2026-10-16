"""Full workspace journeys on loopback only, with desktop/narrow screenshots.

Run Namazu on --port and tests.workspace_fixture_server on --fixture-port first.
python tests/workspace_ui.py --port 8810 --fixture-port 9138
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen

from playwright.sync_api import expect, sync_playwright


def run(port, fixture_port, output, cdp=None, session_secret=None):
    output.mkdir(parents=True, exist_ok=True)
    app = f"http://127.0.0.1:{port}"
    fixture = f"http://127.0.0.1:{fixture_port}"
    summary = []

    def attempts():
        with urlopen(fixture + "/stats", timeout=3) as response:
            return json.load(response)["attempts"]

    with sync_playwright() as playwright:
        browser = playwright.chromium.connect_over_cdp(cdp) if cdp else playwright.chromium.launch(headless=True)
        for width, height, label in ((1440, 1000, "desktop"), (390, 844, "narrow")):
            page = browser.contexts[0].pages[0] if cdp else browser.new_page(viewport={"width": width, "height": height},
                extra_http_headers={"X-Namazu-Session": session_secret} if session_secret else {})
            if cdp:
                app = page.url.rstrip("/")
                port = urlsplit(app).port
                page.set_viewport_size({"width": width, "height": height})
            errors, prohibited = [], []
            def page_error(error, errors=errors):
                errors.append(str(error))
            page.on("pageerror", page_error)

            def route_request(route, prohibited=prohibited, port=port):
                parts = urlsplit(route.request.url)
                if parts.scheme == "blob" or (parts.hostname == "127.0.0.1" and parts.port == port):
                    route.continue_()
                else:
                    prohibited.append(route.request.url)
                    route.abort()

            page.route("**/*", route_request)
            page.goto(app)
            expect(page.locator("#desktop-status")).to_contain_text("Opening saved drafts sends no requests", timeout=15000)
            page.locator("#desktop-import").click()
            page.locator('[data-import-kind="openapi"]').click()
            dialog = page.locator("#desktop-workspace-review")
            expect(dialog).to_be_visible()
            dialog.get_by_role("button", name="Switch / new workspace").click()
            page.locator("#workspace-new-name").fill("Local contracts · " + label)
            dialog.get_by_role("button", name="Create workspace", exact=True).click()
            expect(page.locator("#workspace-title")).to_have_text("Local contracts · " + label)
            files = [{"name": "broken.yaml", "mimeType": "application/yaml", "buffer": b"not-an-openapi-contract"}]
            if label == "narrow":
                for index, name in enumerate(("accounts", "orders", "accounts")):
                    with urlopen(fixture + f"/specs/{name}/openapi.json", timeout=3) as response:
                        files.append({"name": f"{index}-{name}.json", "mimeType": "application/json", "buffer": response.read()})
            page.locator("#workspace-contract-files").set_input_files(files)
            expect(page.locator("#workspace-status")).to_contain_text(f"{len(files)} contract files selected")
            if label == "desktop":
                page.locator("#workspace-spec-urls").fill("\n".join([
                    fixture + "/docs/accounts", fixture + "/docs/orders", fixture + "/docs/accounts"]))
            before = len(attempts())
            dialog.get_by_role("button", name="Import and review", exact=True).click()
            expect(dialog.locator(".workspace-contract-choice")).to_have_count(3)
            expect(dialog).to_contain_text("Imports needing attention")
            imported_attempts = attempts()[before:]
            assert not any(row["credential_present"] for row in imported_attempts)
            assert bool(imported_attempts) == (label == "desktop")
            assert not any("widgets" in row["path"] for row in imported_attempts)
            contract_ids = dialog.locator(".workspace-contract-choice").evaluate_all("nodes => nodes.map(node => node.dataset.contractId)")
            for contract_id in contract_ids:
                dialog.locator(f'.workspace-contract-choice[data-contract-id="{contract_id}"]').click()
                dialog.get_by_label("Contract request limit (optional)").fill("7")
                with page.expect_response(lambda response, cid=contract_id: response.request.method == "PATCH" and response.url.endswith("/contracts/" + cid)) as saved:
                    dialog.get_by_role("button", name="Save contract limits", exact=True).click()
                assert saved.value.status == 200, saved.value.text()
                expect(dialog.get_by_role("button", name="Save contract limits", exact=True)).to_be_enabled()
                expect(page.locator("#workspace-error")).to_be_empty()
            dialog.locator(".workspace-contract-choice").first.click()
            page.locator("#workspace-contract-detail").scroll_into_view_if_needed()
            page.screenshot(path=str(output / f"{label}-setup.png"))

            dialog.get_by_role("button", name=re.compile(r"^Identities")).click()
            page.locator("#workspace-profile-name").fill("Local shared reader")
            page.locator("#workspace-profile-token").fill("local-shared")
            assert page.locator("#workspace-profile-token").get_attribute("type") == "password"
            dialog.get_by_role("button", name="Create identity profile", exact=True).click()
            expect(page.locator("#workspace-shared-profile")).to_be_visible()
            for contract_id in contract_ids:
                dialog.locator(f'input[data-contract-id="{contract_id}"]').check()
            dialog.get_by_role("button", name="Assign profile to selected contracts", exact=True).click()
            expect(page.locator("#workspace-status")).to_contain_text("assignments saved")
            assert "local-shared" not in dialog.inner_text()
            page.screenshot(path=str(output / f"{label}-identities.png"))

            dialog.get_by_role("button", name=re.compile(r"^Overlap review")).click()
            duplicate = dialog.locator(".workspace-overlap").filter(has_text="Identical contract imported twice")
            expect(duplicate).to_have_count(1)
            duplicate.get_by_label("Decision", exact=True).select_option("separate")
            duplicate.get_by_role("button", name="Save decision", exact=True).click()
            expect(dialog).to_contain_text("Reviewed decision: separate")
            page.locator("#workspace-body").evaluate("node => node.scrollTop = 0")
            page.screenshot(path=str(output / f"{label}-overlap.png"))
            before_plan = len(attempts())

            dialog.get_by_role("button", name="Audit plan", exact=True).click()
            page.locator("#workspace-run-budget").fill("21")
            page.locator("#workspace-run-rate").fill("100")
            dialog.get_by_role("button", name="Build offline plan", exact=True).click()
            expect(page.locator("#workspace-execution-review")).to_be_visible()
            expect(page.locator("#workspace-start-audit")).to_be_enabled()
            assert len(attempts()) == before_plan
            page.locator("#workspace-execution-review").scroll_into_view_if_needed()
            page.screenshot(path=str(output / f"{label}-plan.png"))
            page.locator("#workspace-run-consent").check()
            with page.expect_response(lambda response: response.request.method == "POST" and response.url.endswith("/runs")) as started:
                page.locator("#workspace-start-audit").click()
            assert started.value.status == 200, started.value.text()
            run_id = started.value.json()["run_id"]
            expect(page.locator("#workspace-status")).to_contain_text(re.compile(r"Run (finished|incomplete)"), timeout=45000)
            expect(dialog.locator(".workspace-evidence-contract")).to_have_count(3)
            page.locator("#workspace-body").evaluate("node => node.scrollTop = 0")
            page.screenshot(path=str(output / f"{label}-results.png"))
            assert dialog.evaluate("node => node.scrollWidth <= node.clientWidth + 1"), "Dialog overflows viewport"
            assert page.locator("#workspace-body").evaluate("node => node.scrollWidth <= node.clientWidth + 1"), "Workspace body overflows"

            contract = dialog.locator(".workspace-evidence-contract").first
            contract.locator(":scope > summary").click()
            assessment = contract.locator(".workspace-assessment").first
            assessment.locator(":scope > summary").click()
            field = assessment.locator(".test-field").first
            expect(field).to_be_attached()
            field.locator(":scope > summary").click()
            group = field.locator(".test-response-group").first
            group.locator(":scope > summary").click()
            group.scroll_into_view_if_needed()
            expect(assessment.locator(".workspace-evidence-context")).to_be_visible()
            page.screenshot(path=str(output / f"{label}-cases.png"))

            with page.expect_download() as downloaded:
                dialog.get_by_role("button", name="Save workspace JSON", exact=True).click()
            exported_path = output / f"{label}-workspace.json"
            downloaded.value.save_as(exported_path)
            exported = json.loads(exported_path.read_text(encoding="utf-8"))
            assert "local-shared" not in json.dumps(exported)
            assert len(exported["workspace"]["contracts"]) == 3
            assert len(exported["saved_runs"]) == 1
            report = exported["saved_runs"][0]
            assert report["scope"]["reused_assessments"] == 1, report["scope"]
            assert report["scope"]["contract_assessments"] == 3
            assert len(report["requests"]) == report["scope"]["unique_network_attempts"]
            assert len(attempts()) - before_plan == report["scope"]["unique_network_attempts"]
            no_replay = len(attempts())
            page.locator("#workspace-saved-file").set_input_files(exported_path)
            expect(dialog.get_by_role("button", name="Saved report 1", exact=True)).to_be_visible()
            dialog.get_by_role("button", name="Saved report 1", exact=True).click()
            expect(dialog.locator(".workspace-evidence-contract")).to_have_count(3)
            page.locator("#workspace-body").evaluate("node => node.scrollTop = 0")
            page.screenshot(path=str(output / f"{label}-saved-report.png"))
            assert len(attempts()) == no_replay
            expect(page.locator("#workspace-error")).to_be_empty()
            assert not errors, errors
            assert not prohibited, prohibited
            summary.append({"viewport": label, "width": width, "height": height, "run_id": run_id,
                            "unique_network_attempts": report["scope"]["unique_network_attempts"],
                            "contract_assessments": 3, "reused_assessments": 1,
                            "page_errors": errors, "external_browser_requests": prohibited,
                            "saved_report_replayed_requests": 0})
            if cdp:
                page.unroute("**/*", route_request)
                page.remove_listener("pageerror", page_error)
            else:
                page.close()
        if not cdp:
            browser.close()
    (output / "journeys.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8810)
    parser.add_argument("--fixture-port", type=int, default=9138)
    parser.add_argument("--output", type=Path, default=Path(".local-reports/workspace-ui"))
    parser.add_argument("--cdp", help="Explicit loopback diagnostic WebView2 URL for the packaged application")
    args = parser.parse_args()
    run(args.port, args.fixture_port, args.output, args.cdp)
