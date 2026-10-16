"""Narrow workbench APIs shared by the browser and authenticated desktop shell."""
from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from . import desktop_requests
from .audit import run_service

router = APIRouter(prefix="/api/desktop")


@router.get("/credentials")
def credential_storage():
    from .credential_store import store
    return store().capabilities()


@router.post("/preferences/sanitise")
def sanitise_preferences(body: dict):
    from .desktop_state import sanitise_browser_preferences
    from .workspaces import service
    return sanitise_browser_preferences(body, redact=service().sanitise_local_data)


class Draft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    method: str | None = Field(default=None, max_length=16)
    url: str | None = Field(default=None, max_length=16384)
    parameters: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    body: Any = None
    content_type: str | None = Field(default=None, max_length=256)
    assertions: dict = Field(default_factory=dict)


class RequestDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workspace_id: str = Field(min_length=1, max_length=128)
    contract_id: str = Field(min_length=1, max_length=128)
    snapshot_hash: str = Field(min_length=1, max_length=128)
    operation_key: str = Field(min_length=1, max_length=8192)
    environment_id: str | None = Field(default=None, max_length=128)
    identity_ref: str | None = Field(default=None, max_length=128)
    request: Draft = Field(default_factory=Draft)
    allow_mutating: bool = False
    timeout: float = Field(default=15, ge=1, le=120)
    connection: dict = Field(default_factory=dict)

    def payload(self):
        value = self.model_dump()
        # Omission and explicit null are different request bodies.
        value["request"] = self.request.model_dump(exclude_unset=True)
        return value


class SavedState(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int = 1
    revision: int = Field(ge=0)
    state: dict


@router.get("/state")
def state():
    from .desktop_state import store
    return store().get()


@router.put("/state")
def save_state(body: SavedState):
    from .desktop_state import StateConflict, StateStorageError, store
    try:
        return store().put(body.model_dump())
    except StateConflict:
        return JSONResponse({"detail": "This workspace changed in another window. Reload before saving to avoid losing edits.",
                             "current": store().get()}, status_code=409)
    except (OSError, StateStorageError):
        return JSONResponse({"detail": "The workspace could not be saved. Check available disk space and folder permissions. Your current edits remain in this window."}, status_code=507)


@router.post("/prepare")
def prepare_request(body: RequestDraft):
    return desktop_requests.prepare(body.payload())[2]


@router.post("/requests")
def send_request(body: RequestDraft):
    try:
        return desktop_requests.manager().start(body.payload())
    except (OSError, sqlite3.Error):
        return JSONResponse({"detail": "Request was not started because its evidence receipt could not be saved. Check disk space and folder permissions."}, status_code=507)


@router.get("/requests")
def request_history():
    return {"requests": desktop_requests.manager().list(summaries=True)}


@router.get("/requests/{request_id}")
def request_status(request_id: str):
    return desktop_requests.manager().get(request_id)


@router.post("/requests/{request_id}/cancel")
def cancel_request(request_id: str):
    return desktop_requests.manager().cancel(request_id)


@router.get("/status")
def status():
    from . import desktop_runtime
    from .bruno_sources import service as source_jobs
    from .identity_profiles import current_manager
    acquisitions = current_manager()
    runs = run_service.manager()
    retained_runs = runs.list_runs()
    retained_requests = desktop_requests.manager().list(summaries=True)
    active_runs = sum(runs.is_active(run["run_id"]) for run in retained_runs)
    return {"desktop": desktop_runtime.is_desktop(), "active_runs": active_runs,
            "active_requests": desktop_requests.manager().active_count(),
            "active_authentications": acquisitions.active_count() if acquisitions else 0,
            "active_source_jobs": source_jobs().active_count(),
            "stopping": sum(runs.is_stopping(run["run_id"]) for run in retained_runs)
                + sum(item.get("status") == "stopping" for item in retained_requests),
            "interrupted": sum(item.get("status") == "interrupted" for item in [*retained_runs, *retained_requests]),
            "close_behavior": "Closing stops new dispatch, waits briefly for in-flight evidence, and terminates this application's backend. Reopening never resumes requests."}


class Shutdown(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stop_runs: bool


@router.post("/stop")
def stop_work():
    """Stop new dispatch, without closing the app or discarding in-flight evidence."""
    runs = run_service.manager()
    for run in runs.list_runs():
        if runs.is_active(run["run_id"]):
            runs.stop(run["run_id"])
    desktop_requests.manager().stop_all()
    from .identity_profiles import current_manager
    if acquisitions := current_manager():
        acquisitions.stop_all()
    from .bruno_sources import service as source_jobs
    source_jobs().stop_all()
    return {"stopping": True}


@router.post("/shutdown")
def shutdown(body: Shutdown):
    from . import desktop_runtime
    if not desktop_runtime.is_desktop():
        return JSONResponse({"detail": "Desktop shutdown is only available to the owning desktop instance."}, status_code=403)
    if not body.stop_runs:
        raise ValueError("Closing the desktop requires stopping active dispatch.")
    runs = run_service.manager()
    for run in runs.list_runs():
        if runs.is_active(run["run_id"]):
            runs.stop(run["run_id"])
    desktop_requests.manager().stop_all()
    from .identity_profiles import current_manager
    if acquisitions := current_manager():
        acquisitions.stop_all()
    from .bruno_sources import service as source_jobs
    source_jobs().stop_all()
    desktop_runtime.request_shutdown()
    return {"stopping": True, "note": "New dispatch is stopped. Already in-flight requests may still reach the target; retained partial evidence remains available."}


@router.post("/sample")
def sample_workspace():
    from .desktop_sample import create_sample
    return create_sample()
