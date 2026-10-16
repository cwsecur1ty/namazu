"""Comparison policy wiring is local and validated before any target/OAuth IO."""
import json
import shutil
import subprocess
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from namazu.app import app
from namazu.audit.engine import audit_operation, audit_plan
from namazu.audit.response_compare import metadata_header_catalog, normalize_policy
from tests.test_denied_campaign_integration import options, specification


@pytest.mark.parametrize("route", ["/api/audit", "/api/audit/plan"])
@pytest.mark.parametrize("name", ["set-cookie", "content-security-policy", "x-validation-field", "x-*", "server-timing"])
def test_policy_cannot_hide_security_or_arbitrary_headers_or_initiate_io(monkeypatch, route, name):
    def forbidden(*args, **kwargs):
        raise AssertionError("Policy must be rejected before credential resolution")

    monkeypatch.setattr("namazu.audit.engine.identity_resolver.resolve", forbidden)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        response = client.post(route, json={"spec": specification(), "operation_id": "POST /widgets",
                                            "response_comparison": {"metadata_headers": [name]}})
    assert response.status_code == 400
    assert "Unsupported response comparison metadata header" in response.text


@pytest.mark.parametrize("policy,expected", [(None, "same-denial-as-baseline"),
                                            ({"metadata_headers": []}, "request-sent")])
def test_effective_policy_survives_plan_execution_and_result(policy, expected):
    sent = 0

    def local(request):
        nonlocal sent
        sent += 1
        return httpx.Response(403, json={"detail": "Not entitled"},
                              headers={"fm-correlation-id": f"local-{sent}", "x-iinfo": f"diagnostic-{sent}"})

    kwargs = options(request_budget=4, response_comparison=policy)
    plan = audit_plan(specification(), "POST /widgets", **kwargs)
    with httpx.Client(transport=httpx.MockTransport(local)) as client:
        result = audit_operation(specification(), "POST /widgets", client=client, **kwargs)
    assert result["response_comparison"] == plan["response_comparison"] == normalize_policy(policy)
    probes = [probe for probe in result["probes"] if probe.get("id") and probe["request_sent"]]
    assert probes
    assert {probe["status"] for probe in probes} == {expected}
    assert sent == 4
    assert all("fm-correlation-id" in probe["exchange"]["response_headers"] for probe in probes)


def test_python_and_browser_exact_header_catalogs_and_defaults_match():
    if not shutil.which("node"):
        pytest.skip("node is not installed")
    model = Path("namazu/static/audit-results.js").resolve()
    script = f"const api=require({json.dumps(str(model))}); process.stdout.write(JSON.stringify([api.metadataHeaderCatalog,api.normalizePolicy()]));"
    result = subprocess.run(["node", "-e", script], text=True, capture_output=True, check=True, timeout=30)
    catalog, policy = json.loads(result.stdout)
    assert catalog == metadata_header_catalog()
    assert policy == normalize_policy()
