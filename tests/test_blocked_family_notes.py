"""Final coverage notes come from the same settled ledger as the audit export."""
import re

import httpx
import pytest

from namazu.audit import audit_operation
from namazu.spec import parse_spec


def spec():
    return parse_spec({
        "openapi": "3.0.3",
        "info": {"title": "Local blocked-family regression", "version": "1"},
        "servers": [{"url": "http://127.0.0.1/mock"}],
        "paths": {"/items": {"post": {
            "requestBody": {"required": True, "content": {"application/json": {
                "schema": {"type": "object", "required": ["enabled"],
                           "properties": {"enabled": {"type": "boolean", "example": True},
                                          "note": {"type": "string", "example": "local mock"}}},
            }}},
            "responses": {"200": {"description": "Created"}},
        }}},
    })


@pytest.mark.parametrize("status", [200, 403])
def test_one_final_blocked_note_matches_coverage_after_probe_receipts(status):
    def handler(request):
        assert request.url.host == "127.0.0.1"
        return httpx.Response(status, json={"detail": "Denied" if status == 403 else "Created"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = audit_operation(spec(), "POST /items", profile="writes",
                                 identities={"primary": {"Authorization": "Bearer local-test"}},
                                 allow_mutating=True, client=client)
    blocked = result["coverage"]["blocked"]
    notes = [note for note in result["notes"] if "check families did not run" in note]
    assert len(notes) == int(bool(blocked))
    if blocked:
        assert int(re.search(r"(\d+) check families did not run", notes[0]).group(1)) == len(blocked)
        for row in blocked:
            assert row["title"] in notes[0]
    if status == 403:
        assert len(blocked) == 9
        assert {row["check"] for row in blocked} >= {"access-bypass", "input-handling"}
        assert not any("7 check families did not run" in note for note in result["notes"])
