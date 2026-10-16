"""Complete local fixture journeys, without testing a real API's security."""
import copy
import json
import threading

import httpx
import pytest

from namazu.audit import readiness
from namazu.audit.model import Exchange
from namazu.audit.reporting import assess_saved_audit
from namazu.audit.response_compare import edge_block_markers
from namazu.discovery import fetch_document, setup_metadata
from namazu.spec import parse_spec
from tests.ux_fixture_server import (
    BODY,
    FixtureServer,
    known_good,
    old_mixed_report,
    successful_report,
)


@pytest.fixture
def local_fixture():
    with FixtureServer(timeout_delay=0.2) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield server
        server.shutdown()
        thread.join(timeout=2)


def test_docs_import_and_report_opening_do_not_send_endpoint_requests(local_fixture):
    base = local_fixture.base
    doc, url, _warnings = fetch_document(base + "/docs")
    setup = setup_metadata(parse_spec(doc, url), documentation_url=base + "/docs")
    assert len(setup["server_choices"]) == 2
    assert setup["target_selection_required"]
    with httpx.Client(trust_env=False) as client:
        page = client.get(base + "/reports")
        stats = client.get(base + "/stats").json()
    assert page.status_code == 200
    assert 'id="old-export"' in page.text
    assert 'id="two-identity-export"' in page.text
    assert stats["api_request_attempts"] == 0


def test_url_and_credentials_without_real_business_data_remain_denied(local_fixture):
    request = known_good(local_fixture.base)
    body = {**BODY, "documentUri": "string", "personaId": "string"}
    with httpx.Client(trust_env=False) as client:
        response = client.post(request["url"], headers=request["headers"], json=body)
    assert response.status_code == 403
    assert "role required" in response.text
    assert len(local_fixture.attempts) == 1


def test_successful_baseline_constraints_and_explicit_shared_permission(local_fixture):
    request = known_good(local_fixture.base)
    with httpx.Client(trust_env=False) as client:
        assert client.post(request["url"], headers=request["headers"], json=BODY).status_code == 200
        result = client.post(request["url"], headers=request["headers"], json={**BODY, "maxBulletsAmount": 9})
        assert result.status_code == 400
        assert "maxBulletsAmount" in result.json()["errors"]
        second = {"Authorization": "Bearer local-secondary"}
        assert client.post(request["url"], headers=second, json=BODY).status_code == 200
        assert client.post(request["url"], headers=second, json={**BODY, "documentUri": "doc-private"}).status_code == 403
    report = successful_report(local_fixture.base, True)
    configuration = report["readiness"]["configuration"]
    assert readiness.prepare(report["readiness"]["prepared"])["positive_control"]
    assert configuration["permission_matrix"][0]["expect"] == "allow"
    assert "local-primary" not in json.dumps(report)
    assert "local-secondary" not in json.dumps(report)


def test_expired_identity_and_failed_token_acquisition_do_not_claim_verification(local_fixture):
    with httpx.Client(trust_env=False) as client:
        response = client.get(local_fixture.base + "/success/identity", headers={"Authorization": "Bearer expired-token"})
        assert response.status_code == 401
        acquired = client.post(local_fixture.base + "/oauth/token", data={"grant_type": "client_credentials"})
        assert acquired.status_code == 400
        assert acquired.json()["error"] == "invalid_client"


def test_uniform_denials_edge_marker_and_timeout_are_distinct(local_fixture):
    base = local_fixture.base
    headers = known_good(base)["headers"]
    with httpx.Client(trust_env=False) as client:
        first = client.post(base + "/uniform/summaries", headers=headers, json=BODY)
        second = client.post(base + "/uniform/summaries", headers=headers, json={**BODY, "strictMode": None})
        assert first.status_code == second.status_code == 403
        assert first.text == second.text
        assert first.headers["fm-correlation-id"] != second.headers["fm-correlation-id"]
        edge = client.post(base + "/mixed/summaries", headers=headers, json={**BODY, "strictMode": None})
        assert edge_block_markers(Exchange(label="local", method="POST", url=base, status=edge.status_code, body=edge.text))
        with pytest.raises(httpx.ReadTimeout):
            client.post(base + "/timeout/summaries", headers=headers, json=BODY, timeout=0.05)


def test_old_mixed_report_and_offline_reassessment_preserve_classification(local_fixture):
    source = old_mixed_report()
    before = copy.deepcopy(source)
    result = assess_saved_audit(source)
    endpoints = result["request_accounting"]["endpoint"]
    assert endpoints["same-denial"] == 39
    assert endpoints["validation-observation"] == 28
    assert endpoints["edge-block"] == 15
    assert endpoints["incomplete-test"] == 6
    assert result["provenance"]["contract"]["availability"] == "unavailable"
    assert result["target_requests_sent"] == 0
    assert source == before
    assert not local_fixture.attempts
