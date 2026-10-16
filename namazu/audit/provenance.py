"""Offline saved-run identity and integrity metadata. No network operations."""
from __future__ import annotations

import copy
import hashlib
import json

from .. import __version__
from .model import redact_url


def snapshot_hash(snapshot: dict) -> str:
    """Hash the portable response contract, excluding its own integrity field."""
    material = {key: value for key, value in snapshot.items() if key != "integrity"}
    encoded = json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def attach_snapshot_integrity(snapshot: dict | None) -> dict | None:
    if not isinstance(snapshot, dict):
        return None
    saved = copy.deepcopy(snapshot)
    saved["integrity"] = {"algorithm": "sha256", "hash": snapshot_hash(saved),
                          "scope": "redacted-response-contract"}
    return saved


def contract_manifest(payload: dict) -> dict:
    snapshots = payload.get("contract_snapshots") or {}
    if isinstance(snapshots, list):
        snapshots = {item.get("endpoint", ""): item.get("contract_snapshot", item.get("snapshot"))
                     for item in snapshots if isinstance(item, dict)}
    if payload.get("contract_snapshot") and payload.get("endpoint"):
        snapshots = {**snapshots, payload["endpoint"]: payload["contract_snapshot"]}
    entries = []
    for endpoint, saved in sorted(snapshots.items()):
        if not isinstance(saved, dict):
            continue
        integrity = saved.get("integrity") or {}
        computed = snapshot_hash(saved)
        recorded = integrity.get("hash")
        status = ("missing" if not recorded else "verified" if recorded == computed
                  and integrity.get("algorithm") == "sha256" else "mismatch")
        entries.append({"operation": endpoint, "hash": computed, "recorded_hash": recorded,
                        "hash_status": status, "scope": "redacted-response-contract"})
    aggregate = hashlib.sha256(json.dumps([(item["operation"], item["hash"]) for item in entries],
                                         separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest() if entries else None
    return {"availability": "available" if entries else "unavailable", "operation_count": len(entries),
            "scope": "redacted-response-contract", "algorithm": "sha256", "hash": aggregate,
            "operations": entries,
            "limitation": ("Snapshots retain response contracts and reachable local references, not a complete original specification."
                           if entries else "This export contains no response contract snapshot. The original contract cannot be reconstructed from its responses.")}


def saved_run_provenance(payload: dict) -> dict:
    """Keep source run facts separate from a new offline assessment action."""
    previous = payload.get("provenance") or {}
    source = previous.get("source_run") or {}
    api = payload.get("api") or {}
    run = payload.get("run") or {}
    target = source.get("target") or api.get("base_url")
    return {"kind": "offline-reassessment", "requests_sent_during_current_action": 0,
            "source_kind": previous.get("kind") or "imported-historical-run",
            "source_run": {"target": redact_url(target) if target else None,
                           "environment": source.get("environment") or run.get("environment"),
                           "started_at": source.get("started_at") or payload.get("started_at"),
                           "tool_version": source.get("tool_version") or payload.get("tool_version"),
                           "status": source.get("status") or run.get("status") or "unknown"},
            "assessment_tool_version": __version__,
            "contract": contract_manifest(payload),
            "note": "This action reviewed retained evidence offline. It did not retest the target. Missing historical metadata remains unknown."}
