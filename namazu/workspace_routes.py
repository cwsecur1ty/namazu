"""Local workspace setup, offline review, and explicit execution boundaries."""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from . import workspaces
from .audit import run_service

router = APIRouter(prefix="/api/workspaces")


class CreateWorkspace(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(default="API workspace", max_length=256)


class ImportContracts(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[dict] = Field(min_length=1, max_length=100)


class ExecutePlan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    plan_id: str = Field(min_length=1, max_length=128)


@router.get("")
def list_workspaces():
    return {"workspaces": workspaces.service().list()}


@router.post("")
def create_workspace(body: CreateWorkspace):
    return workspaces.service().create(body.title)


@router.post("/import")
def restore_workspace(body: dict):
    # Offline restoration never obtains credentials or resumes a saved run.
    return workspaces.service().restore(body)


@router.get("/{workspace_id}")
def get_workspace(workspace_id: str):
    return workspaces.service().get(workspace_id)


@router.post("/{workspace_id}/contracts/import")
def import_contracts(workspace_id: str, body: ImportContracts):
    return workspaces.service().import_contracts(workspace_id, body.items)


@router.post("/{workspace_id}/bruno")
def import_bruno_collection(workspace_id: str, body: dict):
    return workspaces.service().import_bruno_collection(workspace_id, body)


@router.patch("/{workspace_id}/contracts/{contract_id}")
def update_contract(workspace_id: str, contract_id: str, body: dict):
    return workspaces.service().update_contract(workspace_id, contract_id, body)


@router.delete("/{workspace_id}/contracts/{contract_id}")
def remove_contract(workspace_id: str, contract_id: str):
    return workspaces.service().remove_contract(workspace_id, contract_id)


@router.post("/{workspace_id}/profiles")
def set_profile(workspace_id: str, body: dict):
    return workspaces.service().set_profile(workspace_id, body)


@router.put("/{workspace_id}/contracts/{contract_id}/identity")
def assign_identity(workspace_id: str, contract_id: str, body: dict):
    return workspaces.service().assign_identity(workspace_id, contract_id, body)


@router.post("/{workspace_id}/overlaps")
def decide_overlap(workspace_id: str, body: dict):
    return workspaces.service().decide_overlap(workspace_id, body)


@router.post("/{workspace_id}/plan")
def review_workspace(workspace_id: str, body: dict):
    return workspaces.service().plan(workspace_id, body)


@router.post("/{workspace_id}/runs")
def execute_workspace(workspace_id: str, body: ExecutePlan):
    service = workspaces.service()
    config = service.execution_config(workspace_id, body.plan_id)
    snapshot = run_service.manager().create(config)
    service.attach_run(workspace_id, snapshot["run_id"])
    return snapshot


@router.get("/{workspace_id}/export")
def export_workspace(workspace_id: str):
    exported = workspaces.service().export(workspace_id)
    workspace = exported.get("workspace", exported)
    # Include portable evidence, not just database-local run IDs. Existing run
    # exports retain the established redaction and evidence classifications.
    run_ids = workspace.get("run_ids", workspace.get("runs", []))
    current_runs = [
        result for run_id in run_ids if isinstance(run_id, str)
        if (result := run_service.manager().export(run_id)) is not None
    ]
    exported["saved_runs"] = list(exported.get("saved_runs") or [])
    for result in current_runs:
        if result not in exported["saved_runs"]:
            exported["saved_runs"].append(result)
    return exported
