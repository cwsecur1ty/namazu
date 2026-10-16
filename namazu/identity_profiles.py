"""Explicit client-credentials acquisition using the existing OAuth transport.

Configuration is nonsecret; credentials use the existing session/DPAPI vault.
No startup, import, ordinary Send or audit path invokes acquisition implicitly.
"""
from __future__ import annotations

import copy
import math
import threading
import time
import uuid
from urllib.parse import parse_qsl, urlsplit

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from . import oauth, workspaces
from .audit.model import CREDENTIAL_QUERY
from .credential_store import CredentialStoreError
from .discovery import check_url

router = APIRouter(prefix="/api/workspaces")


class IdentityInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str | None = Field(default=None, max_length=128)
    name: str = Field(min_length=1, max_length=160)
    endpoint: str = Field(min_length=1, max_length=4096)
    client_id: str = Field(min_length=1, max_length=1024)
    client_secret: str | None = Field(default=None, max_length=16384)
    scope: str = Field(default="", max_length=4096)
    grant: str = "client_credentials"
    credential_placement: str = "post"
    persistence: str = "session"


def _profile(workspace, profile_id):
    result = next((p for p in workspace["profiles"] if p["id"] == profile_id), None)
    if not result:
        raise ValueError("Identity profile not found in this workspace")
    return result


def _config(body):
    if body["grant"] != "client_credentials":
        raise ValueError("This editor supports grant_type=client_credentials. Other existing OAuth grants remain in Advanced tools.")
    if body["credential_placement"] not in {"post", "basic"}:
        raise ValueError("Choose credentials in the POST body or HTTP Basic authentication")
    endpoint = check_url(body["endpoint"].strip())
    parts = urlsplit(endpoint)
    if parts.fragment or parts.username or parts.password or any(CREDENTIAL_QUERY.match(k) for k, _ in parse_qsl(parts.query)):
        raise ValueError("Use a token endpoint without embedded credentials or a fragment")
    if parts.scheme != "https" and parts.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Use HTTPS for identity platforms; HTTP is allowed only for local loopback fixtures")
    if any("\r" in body[key] or "\n" in body[key] or "\0" in body[key] for key in ("name", "client_id", "scope")):
        raise ValueError("Identity fields must not contain control line breaks")
    return {"endpoint": endpoint, "client_id": body["client_id"], "scope": body["scope"],
            "grant": "client_credentials", "credential_placement": body["credential_placement"]}


def save(service, workspace_id, body):
    config = _config(body)
    mode = body["persistence"]
    if mode not in {"session", "windows"}:
        raise ValueError("Choose session-only or Windows protected credential storage")
    with service._lock:
        workspace = service._load(workspace_id)
        profile_id = body.get("id") or uuid.uuid4().hex
        existing = _profile(workspace, profile_id) if body.get("id") else None
        if existing and existing.get("kind") != "oauth-client-credentials":
            raise ValueError("Create a separate OAuth identity; this profile is a bearer identity")
        profile = copy.deepcopy(existing or {"id": profile_id, "revision": 0})
        supplied = body.get("client_secret")
        previous_ref = profile.get("configuration_ref")
        secret = supplied if supplied is not None else service.credentials.get(previous_ref) if previous_ref else None
        if supplied is not None and (not supplied or "\0" in supplied):
            raise ValueError("Enter a non-empty client secret or leave it unchanged")
        if secret is None and mode != profile.get("configuration_persistence", "session"):
            raise ValueError("Re-enter the client secret before changing its storage mode")
        changed = config != profile.get("oauth_config") or supplied is not None or mode != profile.get("configuration_persistence", "session")
        profile.update(name=body["name"], kind="oauth-client-credentials", oauth_config=config,
                       configuration_persistence=mode)
        if changed or not existing:
            profile["revision"] += 1
            profile["configuration_revision"] = profile.get("configuration_revision", 0) + 1
            profile["acquisition"] = {"state": "configured", "policy": "explicit-only"}
            old_token = profile.pop("credential_ref", None)
            service._secrets.pop((workspace_id, profile_id), None)
        else:
            old_token = None
        reference = f"workspace:{workspace_id}:oauth:{profile_id}:config:{profile.get('configuration_revision', 1)}"
        if secret is not None:
            service.credentials.put(reference, secret, mode=mode)
            profile["configuration_ref"] = reference
            # Register echoes for all existing workspace/evidence sanitizers.
            service._secrets[(workspace_id, "oauth:" + profile_id)] = secret
        if existing:
            workspace["profiles"][workspace["profiles"].index(existing)] = profile
        else:
            workspace["profiles"].append(profile)
        affected = [c["id"] for c in workspace["contracts"] if service._identity(workspace, c)["profile_id"] == profile_id]
        service._invalidate(workspace, "OAuth configuration changed; acquire explicitly and review affected plans", affected)
        service._save(workspace)
        if previous_ref and previous_ref != profile.get("configuration_ref"):
            service.credentials.delete(previous_ref)
        if old_token:
            service.credentials.delete(old_token)
        return {"workspace": service.get(workspace_id), "profile_id": profile_id, "token_requests": 0}


def profile_status(service, workspace_id, profile):
    if profile.get("kind") != "oauth-client-credentials":
        return
    reference = profile.get("configuration_ref")
    try:
        secret = service.credentials.get(reference) if reference else None
    except CredentialStoreError:
        secret = None
    if secret:
        service._secrets[(workspace_id, "oauth:" + profile["id"])] = secret
    profile["configuration_available"] = secret is not None
    state = profile.setdefault("acquisition", {"state": "configured", "policy": "explicit-only"})
    expiry = state.get("expires_at")
    if isinstance(expiry, (int, float)) and expiry <= time.time():
        state["state"] = "expired"
    elif state.get("state") == "acquired" and not profile.get("credential_available"):
        state["state"] = "not-loaded"


class Acquisitions:
    def __init__(self, service):
        self.service = service
        self.lock = threading.RLock()
        self.jobs = {}

    def start(self, workspace_id, profile_id):
        with self.lock, self.service._lock:
            for job in self.jobs.values():
                if job["workspace_id"] == workspace_id and job["profile_id"] == profile_id and job["state"] in {"requesting", "stopping"}:
                    return self.public(job)
            workspace = self.service._load(workspace_id)
            profile = _profile(workspace, profile_id)
            if profile.get("kind") != "oauth-client-credentials":
                raise ValueError("Choose an OAuth 2.0 client credentials identity")
            config = copy.deepcopy(profile["oauth_config"])
            reference = profile.get("configuration_ref")
            secret = self.service.credentials.get(reference) if reference else None
            if secret is None:
                raise ValueError("Re-enter the client secret in this session before acquiring a token")
            # Retain only bounded, nonsecret diagnostics in memory.
            for key in list(self.jobs):
                if len(self.jobs) < 100:
                    break
                if self.jobs[key]["state"] not in {"requesting", "stopping"}:
                    del self.jobs[key]
            if len(self.jobs) >= 100:
                raise ValueError("Too many concurrent token requests; cancel or wait for current requests")
            job = {"id": uuid.uuid4().hex, "workspace_id": workspace_id, "profile_id": profile_id,
                   "state": "requesting", "attempts": 0, "responses": 0, "code": "", "detail": "Requesting a token…",
                   "cancel": threading.Event(), "revision": profile["revision"]}
            self.jobs[job["id"]] = job
            threading.Thread(target=self._run, args=(job, config, secret), daemon=True, name="namazu-explicit-token").start()
            return self.public(job)

    def _run(self, job, config, secret):
        try:
            if job["cancel"].is_set():
                return
            with self.lock:
                if job["cancel"].is_set():
                    return
                job["attempts"] = 1
            token = oauth.request_token(config["endpoint"], {"grant_type": "client_credentials", "scope": config["scope"]},
                client_id=config["client_id"], client_secret=secret, auth_style=config["credential_placement"], timeout=15)
            job["responses"] = 1
            if str(token["token_type"]).lower() != "bearer":
                raise oauth.TokenRequestError("unsupported-token-type", "This named identity supports Bearer tokens; the issuer returned another token_type.", response_received=True)
            lifetime = token.get("expires_in")
            if lifetime is not None:
                try:
                    lifetime = float(lifetime)
                    if not math.isfinite(lifetime) or lifetime < 0 or lifetime > 315360000 or isinstance(token.get("expires_in"), bool):
                        raise ValueError()
                except (TypeError, ValueError):
                    raise oauth.TokenRequestError("malformed-expiry", "The token response has an invalid expires_in lifetime.", response_received=True) from None
            returned_scope = token.get("scope")
            if returned_scope is not None and (not isinstance(returned_scope, str) or len(returned_scope) > 4096):
                raise oauth.TokenRequestError("malformed-scope", "The token response has an invalid scope value.", response_received=True)
            with self.lock, self.service._lock:
                workspace = self.service._load(job["workspace_id"])
                profile = _profile(workspace, job["profile_id"])
                if job["cancel"].is_set() or profile["revision"] != job["revision"]:
                    job.update(state="cancelled", detail="Token result discarded; acquisition was cancelled or configuration changed.")
                    return
                # Existing rotation invalidates reviewed plans and scoped controls.
                self.service.set_profile(job["workspace_id"], {"id": job["profile_id"], "token": token["access_token"],
                    "persistence": profile.get("configuration_persistence", "session")})
                workspace = self.service._load(job["workspace_id"])
                profile = _profile(workspace, job["profile_id"])
                now = time.time()
                profile["acquisition"] = {"state": "expired" if lifetime == 0 else "acquired", "policy": "explicit-only",
                    "acquired_at": now, "expires_at": now + lifetime if lifetime is not None else None,
                    "lifetime_seconds": lifetime, "token_type": "Bearer", "scope": returned_scope,
                    "attempts": 1, "responses": 1}
                self.service._secrets[(job["workspace_id"], job["profile_id"])] = token["access_token"]
                self.service._save(workspace)
                job.update(state="completed", detail="Token acquired. Assign it explicitly; API access and business baselines remain unverified.")
        except oauth.TokenRequestError as exc:
            job.update(state="failed", code=exc.code, detail=str(exc), responses=int(exc.response_received))
        except Exception:
            job.update(state="failed", code="acquisition-failed", detail="Token acquisition could not finish. Check configuration or secure storage, then retry explicitly.")
        finally:
            with self.lock:
                if job["cancel"].is_set():
                    if job["attempts"]:
                        detail = "Token acquisition cancelled. No token result was applied; an in-flight identity request may have completed."
                    else:
                        detail = "Token acquisition cancelled before any request was dispatched."
                    job.update(state="cancelled", detail=detail)

    @staticmethod
    def public(job):
        return {key: value for key, value in job.items() if key not in {"cancel", "revision"}}

    def get(self, workspace_id, job_id):
        with self.lock:
            job = self.jobs.get(job_id)
            if not job or job["workspace_id"] != workspace_id:
                raise ValueError("Token acquisition not found in this workspace")
            return self.public(job)

    def stop(self, workspace_id, job_id):
        with self.lock:
            self.get(workspace_id, job_id)
            job = self.jobs[job_id]
            if job["state"] in {"requesting", "stopping"}:
                job["cancel"].set()
                job["state"] = "stopping"
            return self.public(job)

    def active_count(self):
        with self.lock:
            return sum(job["state"] in {"requesting", "stopping"} for job in self.jobs.values())

    def stop_all(self):
        with self.lock:
            for job in self.jobs.values():
                self.stop(job["workspace_id"], job["id"])


def manager(service=None):
    service = service or workspaces.service()
    with service._lock:
        if not hasattr(service, "acquisitions"):
            service.acquisitions = Acquisitions(service)
        return service.acquisitions


def current_manager():
    service = workspaces._SERVICE
    return getattr(service, "acquisitions", None) if service is not None else None


class Assignment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    contract_id: str = Field(min_length=1, max_length=128)
    kind: str = "shared"
    environment: str | None = Field(default=None, max_length=256)
    operation_key: str | None = Field(default=None, max_length=8192)
    allowed_scopes: list[str] = Field(default_factory=list, max_length=100)
    remove: bool = False


class Assignments(BaseModel):
    model_config = ConfigDict(extra="forbid")
    profile_id: str = Field(min_length=1, max_length=128)
    assignments: list[Assignment] = Field(min_length=1, max_length=200)


def assign(service, workspace_id, profile_id, assignments):
    with service._lock:
        workspace = service._load(workspace_id)
        _profile(workspace, profile_id)
        affected = []
        for item in assignments:
            contract = service._contract(workspace, item["contract_id"])
            kind = item.get("kind", "shared")
            if kind not in {"shared", "override", "environment", "request", "anonymous"}:
                raise ValueError("Choose a shared, environment or explicit override assignment")
            if kind in {"environment", "request", "anonymous"} and not contract.get("request_collection"):
                raise ValueError("This assignment applies to an imported request collection")
            if kind == "environment" and (not item.get("environment") or item["environment"] != contract.get("environment")):
                raise ValueError("Choose the imported environment belonging to this collection")
            operation = None
            if kind in {"request", "anonymous"}:
                operation = next((row for row in contract["operations"] if row["id"] == item.get("operation_key")), None)
                if not operation:
                    raise ValueError("Choose a request in this collection")
            scopes = list(dict.fromkeys(workspaces.normalise_target(scope) for scope in item.get("allowed_scopes", [])))
            if not item.get("remove") and kind != "anonymous":
                if not scopes:
                    raise ValueError("Confirm explicitly allowed API origins/base paths")
                targets = [operation["request_definition"]["request"]["url"]] if operation else [row["request_definition"]["request"]["url"] for row in contract["operations"]] if contract.get("request_collection") else [contract.get("target", "") + "/"]
                if not any(workspaces.url_in_scopes(target, scopes) for target in targets if "{{" not in target):
                    raise ValueError("No resolved API target in this selection is inside the allowed scopes")
            binding = {"profile_id": profile_id, "allowed_scopes": scopes,
                "source": {"shared": "shared profile", "override": "contract-specific override", "environment": "environment assignment", "request": "request-specific override"}.get(kind, "request-specific no identity")}
            if kind == "anonymous":
                binding = {"anonymous": True, "source": "request-specific no identity"}
            if kind in {"request", "anonymous"}:
                container, key = contract.setdefault("request_assignments", {}), operation["id"]
            elif kind == "environment":
                container, key = contract.setdefault("environment_assignments", {}), item["environment"]
            else:
                container, key = contract, "identity_override" if kind == "override" else "identity_assignment"
            if item.get("remove"):
                container.pop(key, None)
            else:
                container[key] = binding
            if not contract.get("request_collection"):
                active = service._identity(workspace, contract)
                contract["scope_review_required"] = bool(active["profile_id"] and not workspaces.url_in_scopes(contract.get("target", "") + "/", active["allowed_scopes"]))
            affected.append(contract["id"])
        service._invalidate(workspace, "Identity assignments changed; no access, baseline or write permission is inherited", affected)
        service._save(workspace)
        return {"workspace": service.get(workspace_id), "requests_sent": 0}


@router.post("/{workspace_id}/identity-assignments")
def assign_profiles(workspace_id: str, body: Assignments):
    return assign(workspaces.service(), workspace_id, body.profile_id, [item.model_dump() for item in body.assignments])


@router.post("/{workspace_id}/oauth-identities")
def save_identity(workspace_id: str, body: IdentityInput):
    return save(workspaces.service(), workspace_id, body.model_dump())


@router.post("/{workspace_id}/oauth-identities/{profile_id}/acquire")
def acquire(workspace_id: str, profile_id: str):
    return manager().start(workspace_id, profile_id)


@router.get("/{workspace_id}/acquisitions/{job_id}")
def acquisition(workspace_id: str, job_id: str):
    return manager().get(workspace_id, job_id)


@router.post("/{workspace_id}/acquisitions/{job_id}/cancel")
def cancel(workspace_id: str, job_id: str):
    return manager().stop(workspace_id, job_id)
