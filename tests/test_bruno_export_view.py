"""The actual browser export adapter keeps semantic values distinct from text."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from namazu.bruno_collections import export_collection, import_collection

SOURCE = Path("namazu/static/app.js").read_text(encoding="utf-8")


def transform(rows):
    if not shutil.which("node"):
        pytest.skip("node is not installed")
    helper = re.search(r"  function brunoExportRequest\(row\) \{.*?^  \}", SOURCE, re.MULTILINE | re.DOTALL)
    assert helper
    script = helper[0] + "\nconst rows = " + json.dumps(rows) + ";\nconsole.log(JSON.stringify(rows.map(brunoExportRequest)));"
    result = subprocess.run(["node", "-"], input=script, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize("body", [None, False, 0, "", "ordinary string", '{"literal":"JSON-looking string"}'])
def test_actual_receipt_export_adapter_preserves_json_values_through_official_parser(body):
    request = {"method": "POST", "url": "http://fixture.localhost/exact", "headers": {},
               "has_body": True, "body": body, "content_type": "application/problem+json"}
    transformed = transform([{"method": "GET", "url": "http://fixture.localhost/stale", "result": {"request": request}}])[0]
    assert transformed["method"] == "POST" and transformed["url"] == request["url"]
    assert transformed["has_body"] and transformed["body_encoding"] == "json-value"
    converted = export_collection([transformed])
    restored = import_collection(converted["files"], environment="Local")["requests"][0]["request"]
    assert json.loads(restored["body"]) == body
    assert type(json.loads(restored["body"])) is type(body)


def test_capture_text_baselines_and_definition_text_are_not_retyped_as_json_values():
    base = {"method": "POST", "url": "http://fixture.localhost/exact", "headers": {"Content-Type": "application/json"}}
    rows = [
        {**base, "request_headers": base["headers"], "request_body": "false"},
        {"request": {**base, "body": "0", "body_mode": "json", "has_body": True}},
        {"request": {**base, "body": '"raw baseline string"', "has_body": True}},
        {"request": {**base, "body": False, "has_body": True, "request_validation": {"valid": None}}},
    ]
    transformed = transform(rows)
    assert all("body_encoding" not in item for item in transformed[:3])
    assert transformed[3]["body_encoding"] == "json-value"
    assert [item["body"] for item in transformed] == ["false", "0", '"raw baseline string"', False]


def test_no_body_empty_text_and_omitted_body_remain_distinct():
    base = {"method": "POST", "url": "http://fixture.localhost/exact", "headers": {}}
    transformed = transform([
        {"result": {"request": {**base, "body": None, "has_body": False}}},
        {"result": {"request": {**base, "body": "", "has_body": True, "content_type": "text/plain"}}},
        base,
        {**base, "request_body": None},
    ])
    assert transformed[0]["has_body"] is False and transformed[0]["body"] is None
    assert transformed[1]["has_body"] is True and transformed[1]["body"] == ""
    assert "body_encoding" not in transformed[1]
    assert "body" not in transformed[2] and "has_body" not in transformed[2]
    assert transformed[3]["body"] is None and "has_body" not in transformed[3]
