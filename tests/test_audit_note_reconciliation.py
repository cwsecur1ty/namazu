"""Opening old exports reconciles generated summaries without losing originals."""
import copy
import json
from pathlib import Path

from tests.test_frontend_campaign import function, node


def reconciled(audit):
    return node(function("auditNotes") + "\nconst audit = " + json.dumps(audit)
                + "; const before = JSON.stringify(audit); const result = auditNotes(audit);"
                "process.stdout.write(JSON.stringify({result, unchanged:before===JSON.stringify(audit)}));")


def test_export_excerpt_reconciles_seven_and_nine_from_final_ledger():
    fixture = json.loads(Path("tests/fixtures/response_classification_export.json").read_text(encoding="utf-8"))
    audit = fixture["notes_audit"]
    output = reconciled(audit)
    assert output["unchanged"]
    result = output["result"]
    assert result["reconciled"]
    assert result["originalNotes"] == audit["notes"]
    assert len(result["notes"]) == 2
    assert result["notes"][0] == "Local note retained."
    assert "9 blocked check families" in result["notes"][1]
    assert "Access-control bypass" in result["notes"][1]
    assert "Input handling" in result["notes"][1]
    assert "Security posture" not in result["notes"][1]
    assert "7 check families" not in " ".join(result["notes"])


def legacy(operation, count):
    return (f"{operation}: The baseline was permission-denied rather than a success, so {count} "
            "check families did not run and are reported as blocked, not as clean: Example. "
            "Nothing in this result says those areas are sound.")


def test_notes_are_operation_scoped_and_partial_receipts_do_not_inflate_families():
    audit = {"notes": [legacy("POST /one", 7), legacy("POST /two", 9)],
             "baselines": [{"endpoint": "POST /one", "operation_id": "one"},
                           {"endpoint": "POST /two", "operation_id": "two"}],
             "probes": [{"operation": "one", "family": "authorization", "status": "blocked-prerequisite"},
                        {"operation": "one", "family": "posture", "status": "blocked-prerequisite"},
                        {"operation": "one", "family": "posture", "status": "request-sent", "requests": 1},
                        {"operation": "two", "family": "authorization", "status": "request-sent", "requests": 1},
                        {"operation": "two", "family": "methods", "status": "blocked-prerequisite"},
                        {"operation": "two", "family": "cache", "status": "blocked-prerequisite"}],
             "coverage": {"authorization": {"check": "authorization", "title": "Authorization",
                                            "states": {"blocked": 1, "completed": 1},
                                            "blockedOn": ["POST /one"]}}}
    notes = reconciled(audit)["result"]["notes"]
    assert len(notes) == 2
    assert notes[0].startswith("POST /one: Recorded final coverage shows 1 blocked check families")
    assert notes[1].startswith("POST /two: Recorded final coverage shows 2 blocked check families")
    assert "posture" not in " ".join(notes)
    assert "Authorization" not in notes[1]


def test_unrelated_notes_and_missing_evidence_are_never_rewritten():
    audit = {"notes": [legacy("POST /unknown", 7), "Operator says 9 check families need attention."]}
    result = reconciled(audit)["result"]
    assert result["notes"] == audit["notes"]
    assert not result["reconciled"]
    assert result["originalNotes"] is None


def test_reopening_reconciled_notes_preserves_original_history():
    original = {"notes": [legacy("POST /mock", 7)],
                "baselines": [{"endpoint": "POST /mock"}],
                "coverage": {"a": {"check": "a", "state": "blocked"}}}
    first = reconciled(original)["result"]
    imported = copy.deepcopy(original)
    imported.update(notes=first["notes"], originalNotes=first["originalNotes"])
    second = reconciled(imported)["result"]
    assert second["notes"] == first["notes"]
    assert second["originalNotes"] == original["notes"]
    assert not second["reconciled"]
