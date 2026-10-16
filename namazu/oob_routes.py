"""Offline callback evidence routes; no route executes or polls a target."""
from __future__ import annotations

import sqlite3
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .audit import oob

router = APIRouter(prefix="/api/oob")


def _call(method, *args):
    try:
        return getattr(oob.service(), method)(*args)
    except (OSError, sqlite3.Error) as error:
        raise HTTPException(status_code=507, detail="OOB evidence storage is unavailable. Existing saved evidence is preserved; retry after restoring storage access.") from error


class CaseField(BaseModel):
    model_config = ConfigDict(extra="forbid")
    location: Literal["body", "query", "header"]
    pointer: str | None = Field(default=None, max_length=1024)
    name: str | None = Field(default=None, max_length=1024)


class NewCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workspace_id: str = Field(min_length=1, max_length=128)
    contract_id: str = Field(min_length=1, max_length=128)
    snapshot_hash: str = Field(min_length=1, max_length=128)
    operation_key: str = Field(min_length=1, max_length=8192)
    callback_base: str = Field(min_length=1, max_length=2048)
    callback_scope_confirmed: bool = False
    kind: Literal["url-fetch", "blind-injection", "xxe", "other"] = "url-fetch"
    field: CaseField
    ttl_seconds: int = Field(default=86400, ge=60, le=604800)


@router.post("/cases")
def create_case(body: NewCase):
    return _call("create", body.model_dump(exclude_none=True))


@router.get("/cases")
def cases(workspace_id: str | None = None):
    return {"cases": _call("list", workspace_id)}


@router.get("/cases/{case_id}")
def get_case(case_id: str):
    return _call("get", case_id)


class Receipt(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: str = Field(min_length=1, max_length=128)


@router.post("/cases/{case_id}/receipts")
def attach_receipt(case_id: str, body: Receipt):
    return _call("attach_receipt", case_id, body.request_id)


class Interactions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    jsonl: str = Field(max_length=8 * 1024 * 1024)
    source_name: str = Field(default="Interactsh JSONL", max_length=200)


@router.post("/cases/{case_id}/interactions")
def import_interactions(case_id: str, body: Interactions):
    return _call("import_interactions", case_id, body.jsonl, body.source_name)


@router.post("/cases/{case_id}/retire")
def retire_case(case_id: str):
    return _call("retire", case_id)


@router.get("/cases/{case_id}/export")
def export_case(case_id: str):
    return _call("export", case_id)


@router.post("/import")
def restore_case(body: dict):
    return _call("restore", body)
