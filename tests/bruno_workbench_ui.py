"""Real Bruno fixture journeys in headless Chromium; no native window control.

The optional packaged backend is launched through the private Host wrapper with
an isolated state directory and developer runtimes removed from the child PATH.
All ordinary requests go to this script's owned loopback fixture. File inputs
are populated directly; no operating-system file dialog is opened.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import site
import sys
import threading
import time
import zipfile
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
site.addsitedir(str(ROOT / ".venv/Lib/site-packages"))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from bruno_comprehensive_fixture import BASE, Fixture  # noqa: E402
from test_desktop_host import Host  # noqa: E402

FIXTURES = ROOT / "tests/fixtures/bruno/comprehensive"


def run(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    prior_backend, prior_python = os.environ.get("NAMAZU_PACKAGED_BACKEND"), os.environ.get("PYTHONPATH")
    if args.backend:
        os.environ["NAMAZU_PACKAGED_BACKEND"] = str(args.backend.resolve())
    else:
        os.environ.pop("NAMAZU_PACKAGED_BACKEND", None)
        os.environ["PYTHONPATH"] = str(ROOT / ".venv/Lib/site-packages") + os.pathsep + str(ROOT)
    fixture = Fixture()
    threading.Thread(target=fixture.serve_forever, daemon=True).start()
    host = None
    errors, prohibited, checks, widths = [], [], [], []
    start = time.monotonic()
    try:
        host = Host(output)
        assert host.reply["ready"], host.reply
        origin = host.reply["origin"].rstrip("/")
        upload_root = output / "upload collection with spaces"
        for source in (FIXTURES / "collection").rglob("*"):
            if source.is_file():
                target = upload_root / source.relative_to(FIXTURES / "collection")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(source.read_text(encoding="utf-8").replace(BASE, fixture.base), encoding="utf-8")
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1440, "height": 1000}, extra_http_headers={"X-Namazu-Session": host.secret})
            page.on("pageerror", lambda failure: errors.append(str(failure)))

            def local_only(route):
                if route.request.url.startswith(origin + "/") or route.request.url.startswith("blob:"):
                    route.continue_()
                else:
                    prohibited.append(route.request.url)
                    route.abort()

            page.route("**/*", local_only)
            page.goto(origin)
            expect(page.locator("#desktop-workbench")).to_have_attribute("data-ready", "true")
            expect(page.locator("#desktop-window-controls")).to_be_hidden()
            assert page.evaluate("typeof window.NamazuNative") == "undefined"

            def api(path, value=None, method="GET"):
                response = page.request.fetch(origin + path, method=method, data=value,
                    headers={"X-Namazu-Session": host.secret, "Content-Type": "application/json"})
                assert response.ok, response.text()
                return response.json()

            def offline(label, previous):
                assert len(fixture.attempts) == previous, label
                checks.append({"check": label, "target_requests": 0})
                print(label + ": passed, zero target requests", flush=True)

            def shot(label):
                page.screenshot(path=str(output / (label + "-desktop.png")))
                page.set_viewport_size({"width": 390, "height": 844})
                page.screenshot(path=str(output / (label + "-narrow.png")))
                measured = page.locator("#bruno-dialog:visible, #desktop-workbench").evaluate_all("nodes => nodes.map(node => ({id:node.id,width:node.clientWidth,scroll:node.scrollWidth}))")
                assert all(item["scroll"] <= item["width"] + 1 for item in measured), measured
                widths.append({"screen": label, "elements": measured})
                page.set_viewport_size({"width": 1440, "height": 1000})

            def chooser(kind):
                if page.locator("#bruno-dialog").is_visible():
                    page.locator("#bruno-dialog").get_by_role("button", name="Close", exact=True).click()
                page.locator("#desktop-import").click()
                expect(page.locator("#desktop-import-dialog")).to_be_visible()
                page.locator(f"[data-import-kind='{kind}']").click()
                expect(page.locator("#bruno-dialog")).to_be_visible()
                if kind == "bruno-definitions":
                    page.locator("#bruno-advanced-open").click()
                return page.locator("#bruno-dialog")

            def import_report_file(file):
                with page.expect_response(lambda response: urlsplit(response.url).path == "/api/bruno/report") as response:
                    page.locator("#bruno-report-file").set_input_files(file)
                expect(page.locator("#bruno-dialog")).to_have_attribute("aria-busy", "false")
                return response.value

            # Import into an already configured workspace, not only an empty one.
            original_workspace = api("/api/workspaces", {"title": "Existing API workspace"}, "POST")
            original_wid = original_workspace["id"]
            original_spec = {"openapi": "3.0.3", "info": {"title": "Existing authoritative contract", "version": "1"},
                "servers": [{"url": fixture.base + "/existing-api"}],
                "paths": {"/preserved": {"get": {"operationId": "preservedRequest", "responses": {"200": {"description": "Local mock only"}}}}}}
            original_workspace = api(f"/api/workspaces/{original_wid}/contracts/import", {"items": [{"raw_spec": original_spec}]}, "POST")
            original_contract_id = original_workspace["contracts"][0]["id"]
            original_workspace = api(f"/api/workspaces/{original_wid}/profiles",
                {"name": "Existing contract identity", "token": "local-original-contract", "persistence": "session"}, "POST")
            original_profile = next(profile["id"] for profile in original_workspace["profiles"] if profile["name"] == "Existing contract identity")
            original_workspace = api(f"/api/workspaces/{original_wid}/contracts/{original_contract_id}/identity",
                {"profile_id": original_profile, "allowed_scopes": [fixture.base + "/existing-api"]}, "PUT")
            original_contract = original_workspace["contracts"][0]
            page.reload()
            expect(page.locator("#desktop-workbench")).to_have_attribute("data-ready", "true")
            page.locator("#desktop-workspace").select_option(original_wid)
            page.locator(f'[data-operation-key="{original_contract["operations"][0]["id"]}"]').click()
            original_url = fixture.base + "/existing-api/preserved?draft=keep-original"
            page.locator("#desktop-request-url").fill(original_url)
            page.locator("#desktop-save-draft").click()
            page.evaluate("() => window.NamazuDesktop.flush()")
            original_state = api("/api/desktop/state")["state"]
            original_tab_id = original_state["selectedTab"]
            original_tab = next(tab for tab in original_state["tabs"] if tab["id"] == original_tab_id)

            def original_unchanged(*, restarted=False):
                current = api(f"/api/workspaces/{original_wid}")
                expected = json.loads(json.dumps(original_contract))
                if restarted:
                    expected["identity"]["credential_available"] = False
                assert current["contracts"] == [expected]
                state_tabs = api("/api/desktop/state")["state"]["tabs"]
                preserved = next(tab for tab in state_tabs if tab["id"] == original_tab_id)
                for key in ("id", "workspaceId", "contractId", "operationKey", "snapshotHash", "draft", "savedDraft"):
                    assert preserved.get(key) == original_tab.get(key), key

            original_unchanged()
            offline("existing OpenAPI contract, scoped identity and edited saved draft are established without dispatch", 0)

            # Historical reporter output is imported and reimported without dispatch.
            before = len(fixture.attempts)
            dialog = chooser("bruno-results")
            report_file = page.locator("#bruno-report-file")
            with page.expect_response(lambda response: urlsplit(response.url).path == "/api/bruno/report") as imported_report:
                report_file.set_input_files(FIXTURES / "report.json")
            assert imported_report.value.ok, imported_report.value.text()
            expect(page.locator("#bruno-summary")).to_contain_text("72 recorded executions")
            expect(page.locator("#bruno-summary")).to_contain_text("70 HTTP responses")
            expect(dialog.locator(".bruno-row")).to_have_count(72)
            with page.expect_response(lambda response: urlsplit(response.url).path == "/api/bruno/report") as reimported_report:
                report_file.set_input_files(FIXTURES / "report.json")
            assert reimported_report.value.ok, reimported_report.value.text()
            expect(dialog).to_have_attribute("aria-busy", "false")
            expect(dialog.locator(".bruno-row")).to_have_count(72)
            retained_summary = page.locator("#bruno-summary").inner_text()
            page.locator("#bruno-report-file").set_input_files(FIXTURES / "negative/malformed-report.json")
            expect(dialog.get_by_role("alert")).to_be_visible()
            expect(dialog).to_have_attribute("aria-busy", "false")
            expect(page.locator("#bruno-summary")).to_have_text(retained_summary)
            expect(dialog.locator(".bruno-row")).to_have_count(72)
            rejected = import_report_file(FIXTURES / "negative/unsupported-report.json")
            assert not rejected.ok
            expect(dialog.get_by_role("alert")).to_be_visible()
            expect(page.locator("#bruno-summary")).to_have_text(retained_summary)
            expect(dialog.locator(".bruno-row")).to_have_count(72)
            offline("malformed and unsupported reports preserve the previous imported evidence", before)

            omitted = import_report_file(FIXTURES / "omitted.json")
            assert omitted.ok, omitted.text()
            omitted_evidence = omitted.json()
            assert omitted_evidence["findings"] == []
            assert omitted_evidence["bruno"]["recorded_executions"] == 72
            assert all(row["missing_evidence"] for row in omitted_evidence["bruno"]["executions"])
            expect(dialog.locator(".bruno-row").first).to_contain_text("response body")
            expect(dialog.locator(".bruno-row").first).to_contain_text("response headers")
            shot("01a-omitted-evidence")
            offline("real CLI omitted bodies and headers remain explicitly missing", before)

            malicious_name = '<img src=x onerror="window.__brunoExecuted=1">'
            inert_report = json.loads((FIXTURES / "report.json").read_text(encoding="utf-8"))
            inert_report[0]["results"][0]["name"] = malicious_name
            imported = import_report_file({"name": "literal-name-test.json", "mimeType": "application/json", "buffer": json.dumps(inert_report).encode()})
            assert imported.ok, imported.text()
            expect(dialog.locator(".bruno-row").first).to_contain_text(malicious_name)
            assert dialog.locator('img[src="x"]').count() == 0
            assert page.evaluate("typeof window.__brunoExecuted") == "undefined"
            offline("malicious report names render as literal inert text", before)
            assert import_report_file(FIXTURES / "report.json").ok
            with page.expect_download() as saved:
                dialog.get_by_role("button", name="Export redacted evidence + source", exact=True).click()
            saved_path = output / "retained-bruno-evidence.json"
            saved.value.save_as(saved_path)
            evidence = json.loads(saved_path.read_text(encoding="utf-8"))
            assert evidence["bruno"]["recorded_executions"] == 72
            assert evidence["bruno"]["observed_responses"] == 70
            assert evidence["bruno"]["wire_attempts"] is None
            assert evidence["scope"]["requests_sent"] is None
            assert evidence["provenance"]["requests_sent_during_current_action"] == 0
            assert evidence["findings"] == []
            assert "fixture-shared-token" not in saved_path.read_text(encoding="utf-8")
            shot("01-real-report-and-reimport")
            dialog.get_by_role("button", name="Close", exact=True).click()
            page.locator("#desktop-import").click()
            page.locator("[data-import-kind='evidence']").click()
            page.locator("#import-audit-file").set_input_files(saved_path)
            expect(page.locator("#audit-report-body")).to_contain_text("Imported Bruno run")
            expect(page.locator("#audit-report-body")).to_contain_text("72 recorded executions")
            offline("real report import, duplicate import, export and retained evidence reimport", before)

            # Explicit folder/environment selection precedes workspace creation.
            dialog = chooser("bruno-definitions")
            page.locator("#bruno-collection-folder").set_input_files(upload_root)
            expect(page.locator("#bruno-environment")).to_be_visible()
            page.locator("#bruno-environment").select_option("Local")
            dialog.get_by_role("button", name="Resolve selected environment", exact=True).click()
            expect(dialog.locator(".bruno-row")).to_have_count(36)
            expect(page.locator("#bruno-summary")).to_contain_text("36 request definitions")
            retained_summary = page.locator("#bruno-summary").inner_text()
            with page.expect_response(lambda response: urlsplit(response.url).path == "/api/bruno/collection") as bad_definition:
                page.locator("#bruno-definition-files").set_input_files(FIXTURES / "negative/malformed.bru")
            assert not bad_definition.value.ok
            expect(dialog).to_have_attribute("aria-busy", "false")
            expect(dialog.get_by_role("alert")).to_be_visible()
            expect(page.locator("#bruno-summary")).to_have_text(retained_summary)
            expect(dialog.locator(".bruno-row")).to_have_count(36)
            blocked_rows = []
            for row in dialog.locator(".bruno-row").all():
                detail = json.loads(row.locator("pre").text_content())
                if detail.get("blockers"):
                    assert not detail["can_prepare"], detail
                    row.locator("summary").click()
                    expect(row.locator("pre")).to_be_visible()
                    blocked_rows.append(detail["id"])
            assert len(blocked_rows) >= 5, blocked_rows
            original_unchanged()
            offline("malformed definitions preserve prior state and unsupported rows stay inspectable and blocked", before)
            shot("02-real-definitions-reviewed")
            with page.expect_response(lambda response: urlsplit(response.url).path.endswith("/bruno") and response.request.method == "POST") as added:
                page.locator("#bruno-add-workspace").click()
            assert added.value.ok, added.value.text()
            created = added.value.json()
            wid, cid = created["workspace"]["id"], created["collection_id"]
            expect(page.locator("#desktop-collection-tree")).to_contain_text("Namazu comprehensive local Bruno fixture")
            workspace = api(f"/api/workspaces/{wid}")
            assert wid == original_wid
            assert workspace["contracts"] == [original_contract]
            assert len(workspace["request_collections"]) == 1
            collection = workspace["request_collections"][0]
            assert not collection["response_contract"] and len(collection["operations"]) == 36
            original_unchanged()
            tree_collection = page.locator(f'.desktop-contract[data-request-collection="{cid}"]')
            nested = tree_collection.locator(".desktop-folder").filter(has=page.locator(':scope > summary').filter(has_text=re.compile("^Nested folder$")))
            expect(nested).to_have_count(1)
            expect(nested.locator(':scope > .desktop-folder > summary')).to_have_text("Child with spaces")
            expect(tree_collection.locator(".desktop-operation-name").filter(has_text=re.compile("^Same request$"))).to_have_count(3)
            offline("folder import and workspace collection preserve definitions without inventing a response contract", before)

            def open_request(filename):
                if page.locator("#bruno-dialog").is_visible():
                    page.locator("#bruno-dialog").get_by_role("button", name="Close", exact=True).click()
                page.locator(f'[data-operation-key="{cid}::{filename}"]').click()
                expect(page.locator("#desktop-request")).to_be_visible()
                expect(page.locator("#desktop-request-context")).to_contain_text(re.compile("Bruno|definition|contract", re.I))

            def send(expected_method, expected_query, expected_body=None, expected_media=None):
                previous = len(fixture.attempts)
                if expected_method not in {"GET", "HEAD", "OPTIONS"}:
                    expect(page.locator("#desktop-write-consent")).not_to_be_checked()
                    page.locator("#desktop-write-consent").check()
                with page.expect_response(lambda response: urlsplit(response.url).path == "/api/desktop/requests" and response.request.method == "POST") as submitted:
                    page.locator("#desktop-send").click()
                assert submitted.value.ok, submitted.value.text()
                rid = submitted.value.json()["request_id"]
                deadline = time.monotonic() + 20
                record = api(f"/api/desktop/requests/{rid}")
                while record["status"] in {"pending", "running", "stopping"} and time.monotonic() < deadline:
                    page.wait_for_timeout(100)
                    record = api(f"/api/desktop/requests/{rid}")
                assert record["status"] == "completed", record
                assert len(fixture.attempts) == previous + 1
                receipt = fixture.attempts[-1]
                assert receipt["method"] == expected_method
                assert parse_qs(urlsplit(receipt["path"]).query, keep_blank_values=True) == expected_query
                if expected_body is not None:
                    if expected_media and "json" in expected_media:
                        assert json.loads(receipt["body"]) == expected_body
                    else:
                        assert receipt["body"] == expected_body
                if expected_media:
                    assert receipt["headers"]["content-type"] == expected_media
                assert record["context"]["contract_id"] == cid
                assert record["context"]["snapshot_hash"] == collection["hash"]
                checks.append({"check": "explicit definition send preserves method/query/body/media", "request_id": rid, "method": expected_method, "target_requests": 1})
                return receipt

            # A definition explicitly declaring no auth stays uncredentialed.
            open_request("02-no-auth.bru")
            receipt = send("GET", {"case": ["no-auth"]})
            assert "authorization" not in receipt["headers"]
            offline_before = len(fixture.attempts)
            # Fixture setup assigns a separate local bearer reference explicitly;
            # no imported Bruno credential is copied into the live profile.
            api(f"/api/workspaces/{wid}/profiles", {"name": "Explicit QA identity", "token": "local-bruno-qa", "persistence": "session"}, "POST")
            profile_id = next(profile["id"] for profile in api(f"/api/workspaces/{wid}")["profiles"] if profile["name"] == "Explicit QA identity")
            page.reload()
            expect(page.locator("#desktop-workbench")).to_have_attribute("data-ready", "true")
            offline("explicit local API identity fixture setup and app reload", offline_before)
            for filename, query, body, media in [
                ("05-json-false.bru", {"case": ["false"]}, False, "application/json"),
                ("06-json-zero.bru", {"case": ["zero"]}, 0, "application/json"),
                ("22-json-escapes.bru", {"case": ["escapes"]}, {"quote": 'a "quoted" value', "path": "C:\\fixture\\path", "line": "one\ntwo", "unicode": "caf\u00e9 \u96ea"}, "application/json"),
            ]:
                open_request(filename)
                page.locator("#desktop-editor-tabs").get_by_role("tab", name="Auth", exact=True).click()
                page.locator("#desktop-bruno-profile").select_option(profile_id)
                page.locator("#desktop-bruno-scopes").fill(fixture.base)
                with page.expect_response(lambda response: urlsplit(response.url).path.endswith("/identity") and response.request.method == "PUT") as assigned:
                    page.locator("#desktop-bruno-assign").click()
                assert assigned.value.ok, assigned.value.text()
                expect(page.locator("#desktop-bruno-assign")).to_be_enabled()
                receipt = send("POST", query, body, media)
                assert receipt["headers"]["authorization"] == "Bearer local-bruno-qa"
            shot("03-explicit-request-and-response")
            before = len(fixture.attempts)
            draft_url = page.locator("#desktop-request-url").input_value() + "&draft=preserved"
            page.locator("#desktop-request-url").fill(draft_url)
            page.evaluate("() => window.NamazuDesktop.flush()")
            saved_state = api("/api/desktop/state")["state"]
            active_tab_id = saved_state["selectedTab"]
            active_draft = next(tab for tab in saved_state["tabs"] if tab["id"] == active_tab_id)["draft"]
            assignments = api(f"/api/workspaces/{wid}")["request_collections"][0]["request_assignments"]
            assert len(assignments) == 3
            # Reimport the same exact environment/definitions; collection identity is stable.
            dialog = chooser("bruno-definitions")
            page.locator("#bruno-collection-folder").set_input_files(upload_root)
            expect(page.locator("#bruno-environment")).to_be_visible()
            page.locator("#bruno-environment").select_option("Local")
            dialog.get_by_role("button", name="Resolve selected environment", exact=True).click()
            expect(dialog.locator(".bruno-row")).to_have_count(36)
            with page.expect_response(lambda response: urlsplit(response.url).path.endswith("/bruno") and response.request.method == "POST") as duplicated:
                page.locator("#bruno-add-workspace").click()
            assert duplicated.value.json()["duplicate"] is True
            assert duplicated.value.json()["collection_id"] == cid
            assert len(api(f"/api/workspaces/{wid}")["request_collections"]) == 1
            assert api(f"/api/workspaces/{wid}")["request_collections"][0]["request_assignments"] == assignments
            original_unchanged()
            expect(dialog).to_be_hidden()
            open_request("22-json-escapes.bru")
            expect(page.locator("#desktop-request-url")).to_have_value(draft_url)
            offline("identical definition reimport preserves collection identity and causes no replay", before)

            # Export selected reviewed definitions as a Bruno ZIP, with warnings first.
            dialog = chooser("bruno-definitions")
            row = dialog.locator(".bruno-row").filter(has_text="JSON false")
            row.locator('input[type="checkbox"]').check()
            dialog.get_by_role("button", name="Preview conversion", exact=True).click()
            expect(page.locator("#bruno-export-preview")).to_contain_text("bruno.json")
            button = dialog.get_by_role("button", name="Download Bruno collection (.zip)", exact=True)
            expect(button).to_be_disabled()
            page.locator("#bruno-export-reviewed").check()
            with page.expect_download() as saved_zip:
                button.click()
            zip_path = output / "reviewed-definition.zip"
            saved_zip.value.save_as(zip_path)
            with zipfile.ZipFile(zip_path) as archive:
                texts = [archive.read(name).decode() for name in archive.namelist()]
                assert all("local-bruno-qa" not in value for value in texts)
                assert any("false" in value for value in texts)
            shot("04-reviewed-export")
            offline("selected definition export requires review and never sends", before)

            individual = (upload_root / "02-no-auth.bru").read_text(encoding="utf-8").replace("{{baseUrl}}", fixture.base).replace("Explicit no auth", malicious_name)
            with page.expect_response(lambda response: urlsplit(response.url).path == "/api/bruno/collection") as imported_individual:
                page.locator("#bruno-definition-files").set_input_files({"name": "Individual request with spaces.bru", "mimeType": "text/plain", "buffer": individual.encode()})
            assert imported_individual.value.ok, imported_individual.value.text()
            expect(dialog).to_have_attribute("aria-busy", "false")
            expect(dialog.locator(".bruno-row")).to_have_count(1)
            expect(dialog.locator(".bruno-row")).to_contain_text(malicious_name)
            assert dialog.locator('img[src="x"]').count() == 0
            assert page.evaluate("typeof window.__brunoExecuted") == "undefined"
            dialog.get_by_role("button", name="Close", exact=True).click()
            page.locator("#desktop-import").click()
            page.locator("#desktop-import-dialog").get_by_role("button", name="Close import chooser", exact=True).click()
            expect(page.locator("#desktop-request-url")).to_have_value(draft_url)
            assert api(f"/api/workspaces/{wid}")["request_collections"][0]["request_assignments"] == assignments
            original_unchanged()
            offline("individual file preview, literal HTML and closing import dialogs preserve drafts and identity references", before)

            page.locator("#desktop-menu-open").click()
            page.locator("#desktop-theme").click()
            expect(page.locator("html")).to_have_attribute("data-theme", "light")
            shot("05-light-request")
            dialog = chooser("bruno-definitions")
            shot("06-light-individual-preview")
            dialog.get_by_role("button", name="Close", exact=True).click()
            page.evaluate("() => window.NamazuDesktop.flush()")
            state_root = host.state
            page.goto("about:blank")
            host.close()
            restart_root = output / "restart"
            restart_root.mkdir(exist_ok=True)
            host = Host(restart_root, state=state_root)
            assert host.reply["ready"], host.reply
            origin = host.reply["origin"].rstrip("/")
            page.set_extra_http_headers({"X-Namazu-Session": host.secret})
            page.goto(origin)
            expect(page.locator("#desktop-workbench")).to_have_attribute("data-ready", "true")
            expect(page.locator("#desktop-request-url")).to_have_value(draft_url)
            expect(page.locator("html")).to_have_attribute("data-theme", "light")
            expect(page.locator("#desktop-write-consent")).not_to_be_checked()
            restored_state = api("/api/desktop/state")["state"]
            assert restored_state["selectedTab"] == active_tab_id
            restored_draft = next(tab for tab in restored_state["tabs"] if tab["id"] == active_tab_id)["draft"]
            assert restored_draft == active_draft
            restored_workspace = api(f"/api/workspaces/{wid}")
            assert restored_workspace["request_collections"][0]["request_assignments"] == assignments
            assert all(not profile["credential_available"] for profile in restored_workspace["profiles"])
            original_unchanged(restarted=True)
            assert len(api("/api/desktop/requests")["requests"]) == len(fixture.attempts)
            offline("owned backend restart restores drafts and identity references without credentials, write consent or replay", before)
            shot("07-restored-light-workspace")
            assert not errors and not prohibited, {"errors": errors, "prohibited": prohibited}
            page.evaluate("() => window.NamazuDesktop.flush()")
            browser.close()
        report = {"status": "passed", "surface": "headless Chromium using " + ("packaged backend/resources" if args.backend else "source backend/resources") + "; no native window or OS file dialog controlled",
                  "real_fixture_cli": "@usebruno/cli@4.2.1", "checks": checks, "target_requests": len(fixture.attempts), "external_browser_requests": prohibited,
                  "page_errors": errors, "narrow_widths": widths, "seconds": round(time.monotonic() - start, 2),
                  "identity_setup": "Synthetic profile created through the local API, explicitly assigned per request through Auth controls; imported credentials never activated.",
                  "coverage_boundary": "Interoperability and product behavior only; no API security coverage claimed."}
        (output / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report, indent=2), flush=True)
    finally:
        if host:
            host.close()
        fixture.shutdown()
        fixture.server_close()
        for name, value in [("NAMAZU_PACKAGED_BACKEND", prior_backend), ("PYTHONPATH", prior_python)]:
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", type=Path)
    parser.add_argument("--output", type=Path, default=Path(".local-reports/bruno-workbench-headless"))
    run(parser.parse_args())
