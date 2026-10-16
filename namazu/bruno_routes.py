"""Offline Bruno endpoints, covered by the application's host/origin middleware."""
from __future__ import annotations

import io
import json
import zipfile

from fastapi import APIRouter
from fastapi.responses import Response

from .bruno import CLI_VERSION, MARKER, bounded, import_report, sanitise, sensitive
from .bruno_collections import export_collection, import_collection, operation_matches

router = APIRouter(prefix="/api/bruno")


@router.post("/report")
def report(body: dict):
    bounded(body)
    return import_report(body.get("report"), version=body.get("version", CLI_VERSION), credential_names=body.get("credential_names", []), collection_name=body.get("collection_name"))


@router.post("/collection")
def collection(body: dict):
    return import_collection(body.get("files"), environment=body.get("environment"), spec=body.get("spec"), credential_names=body.get("credential_names", []))


@router.post("/prepare")
def prepare(body: dict):
    """Explicitly selected templates only; never mark imported 2xx as a control."""
    bounded(body)
    names = body.get("credential_names", [])
    if body.get("files"):
        imported = collection(body)
        selected = next((row for row in imported["requests"] if row["id"] == body.get("selection")), None)
        if selected is None:
            raise ValueError("Select an imported request after choosing its environment.")
        if not selected["can_prepare"]:
            raise ValueError("Resolve unsupported features and missing variables before preparing this request.")
        request = selected["request"]
    else:
        imported = report(body)
        selected = next((row for row in imported["requests"] if row["exchange_id"] == body.get("selection")), None)
        if selected is None:
            raise ValueError("Select a recorded execution with a resolved method and URL.")
        if selected["missing_evidence"] or selected["truncated"] or selected.get("error"):
            raise ValueError("Incomplete recorded evidence cannot define an exact baseline. Import its definition and review missing values explicitly.")
        request = {"method": selected["method"], "url": selected["url"], "headers": selected["request_headers"], "body": selected["request_body"]}
    spec = body.get("spec")
    operation_id = body.get("operation_id")
    if not spec or operation_id not in operation_matches(request, spec):
        raise ValueError("Import an OpenAPI contract and explicitly select an operation matching this method, target and path. A Bruno collection is not a response contract.")
    identity = body.get("identity_ref")
    if identity != "primary" or body.get("identity_confirmed") is not True:
        raise ValueError("Explicitly map and confirm the local primary identity used for Namazu baselines. Bruno authentication is never executed.")
    expectation = body.get("expectation") or {}
    assertions = body.get("assertions") or []
    if not isinstance(expectation, dict) or not isinstance(assertions, list):
        raise ValueError("Supply an expected status and explicit resource/content assertions.")
    if not isinstance(expectation.get("status"), str) or not expectation["status"].isdigit() or not 100 <= int(expectation["status"]) <= 599:
        raise ValueError("Supply one expected HTTP status between 100 and 599.")
    if not all(any(isinstance(a, dict) and a.get("purpose") == purpose and a.get("operator") in ("equals", "contains") and isinstance(a.get("pointer"), str) and a["pointer"].startswith("/") and a.get("expected") not in (None, "", [], {}) for a in assertions) for purpose in ("resource", "content")):
        raise ValueError("Both a resource assertion and a content assertion are required; a Bruno pass or HTTP 2xx is insufficient.")
    if len(assertions) > 30 or any(not isinstance(a, dict) or a.get("purpose") not in ("resource", "content") or a.get("operator") not in ("equals", "contains") or not isinstance(a.get("pointer"), str) or not a["pointer"].startswith("/") or any(sensitive(p.replace("~1", "/").replace("~0", "~"), names) for p in a["pointer"].split("/")[1:]) for a in assertions):
        raise ValueError("Use at most 30 resource/content assertions on non-secret response fields.")
    clean = sanitise({"request": request, "expectation": expectation, "assertions": assertions}, names)
    if MARKER in json.dumps(clean["assertions"]):
        raise ValueError("Redacted values cannot establish a resource/content assertion.")
    request = clean["request"]
    request["headers"] = {k: v for k, v in request.get("headers", {}).items() if not sensitive(k, names)}
    if MARKER in json.dumps(request) or "{{" in json.dumps(request):
        raise ValueError("The request contains unresolved or redacted values. Resolve them locally before preparation.")
    prepared = {"request": request, "identity_ref": identity, "expectation": clean["expectation"], "assertions": clean["assertions"], "positive_control": False, "requests_sent": 0, "missing_prerequisites": [{"code": "successful-response-missing", "detail": "Confirm this baseline in a separately authorised live run."}]}
    # Current Namazu has a richer readiness component. Reuse it without making
    # the adapter require unrelated, unpublished working-tree changes.
    try:
        from .audit.readiness import prepare as prepare_readiness
    except ImportError:
        pass
    else:
        prepared = prepare_readiness({**prepared, "operation": operation_id, "credential_names": names})
    expectation = {**clean["expectation"], "business_assertions": clean["assertions"]}
    return {"operation_id": operation_id, "identity_ref": identity, "example": {"url": request["url"], "body": request["body"], "headers": request["headers"], "content_type": next((v for k, v in request["headers"].items() if k.lower() == "content-type"), None), "label": "an explicitly reviewed Bruno definition"}, "expectation": expectation, "prepared": prepared, "requests_sent": 0, "note": "Prepared offline, not executed or established as a successful baseline. Configure the mapped identity and review a new Namazu run. Expected denials never unlock success-dependent checks."}


@router.post("/export")
def export(body: dict):
    return export_collection(body.get("requests"), credential_names=body.get("credential_names", []))


@router.post("/download")
def download(body: dict):
    if body.get("reviewed") is not True:
        raise ValueError("Preview and acknowledge conversion warnings before downloading.")
    converted = export(body)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for file in converted["files"]:
            archive.writestr(file["path"], file["content"])
    return Response(buffer.getvalue(), media_type="application/zip", headers={"Content-Disposition": 'attachment; filename="namazu-bruno.zip"'})
