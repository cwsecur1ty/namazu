"""Offline source jobs; native filesystem access requires a second capability."""
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import bruno_sources, desktop_runtime

router = APIRouter(prefix="/api/bruno/sources")


@router.post("")
def create(body: dict):
    return bruno_sources.service().create(body)


@router.post("/native")
def native(body: dict, request: Request):
    if not desktop_runtime.authorize_native(request.headers.get("X-Namazu-Native")):
        return JSONResponse({"detail": "Native folder selection capability required."}, status_code=403)
    if set(body) != {"root"}:
        raise ValueError("Select one source folder using the native picker.")
    return bruno_sources.service().native(body["root"])


@router.get("/{identifier}")
def get(identifier: str):
    return bruno_sources.service().get(identifier)


@router.post("/{identifier}/cancel")
def cancel(identifier: str):
    return bruno_sources.service().cancel(identifier)


@router.post("/{identifier}/review")
def review(identifier: str, body: dict):
    return bruno_sources.service().review(identifier, body)


@router.post("/{identifier}/import")
def import_reviewed(identifier: str, body: dict):
    return bruno_sources.service().import_reviewed(identifier, body)
