"""Credential resolution for an audit run.

An identity can be a set of headers, or an OAuth configuration the engine mints
a token from. The second form is what makes a long audit survivable: a token
pasted into a header expires partway through a run across forty operations and
every request after that point returns 401, which reads like a finding rather
than a stale credential.

A minted token is cached for the configuration that produced it and reused
until shortly before it expires, so a run mints once rather than once per
operation. Tokens live in memory only and are never written to disk.
"""
from __future__ import annotations

import hashlib
import json
import time

from .. import oauth

# Mint a replacement this long before the server's own expiry, so a token does
# not lapse between being handed out and being used.
REFRESH_MARGIN = 30
# A token with no stated lifetime is still reused, but only briefly.
DEFAULT_TTL = 300

_tokens: dict[str, dict] = {}


class CredentialError(RuntimeError):
    """A configured identity could not be turned into a usable credential."""


def _fingerprint(config: dict) -> str:
    """A stable key for a configuration, without keeping the secret readable."""
    material = json.dumps({key: config.get(key) for key in sorted(config)}, sort_keys=True,
                          default=str)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def clear_cache() -> None:
    _tokens.clear()


def _mint(config: dict, *, verify_tls: bool, timeout: float) -> dict:
    """Obtain a token for an OAuth configuration, honouring the chosen grant."""
    grant = str(config.get("grant") or "client_credentials")
    token_endpoint = str(config.get("token_endpoint") or "").strip()
    if not token_endpoint:
        raise CredentialError("The OAuth identity has no token endpoint.")

    shared = {
        "token_url": token_endpoint,
        "client_id": str(config.get("client_id") or ""),
        "client_secret": str(config.get("client_secret") or ""),
        "auth_style": str(config.get("auth_style") or "post"),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }
    scope = str(config.get("scope") or "")
    try:
        if grant == "client_credentials":
            return oauth.client_credentials(scope=scope,
                                            audience=str(config.get("audience") or ""), **shared)
        if grant == "password":
            return oauth.password_grant(username=str(config.get("username") or ""),
                                        password=str(config.get("password") or ""),
                                        scope=scope, **shared)
        if grant in ("refresh_token", "authorization_code"):
            # An authorization code grant cannot be replayed without a browser,
            # but the refresh token it returned can be, which is what keeps a
            # long run authenticated.
            refresh_token = str(config.get("refresh_token") or "")
            if not refresh_token:
                raise CredentialError(
                    "This identity uses the authorization code grant, which needs a browser. "
                    "Supply the refresh token it returned so the audit can renew without one.")
            return oauth.refresh(refresh_token=refresh_token, scope=scope, **shared)
    except ValueError as exc:
        raise CredentialError(str(exc)) from exc
    raise CredentialError(f"Unsupported OAuth grant for an audit identity: {grant}")


def _token_headers(config: dict, *, verify_tls: bool, timeout: float) -> tuple[dict, dict]:
    """Headers for an OAuth identity, minting or reusing as needed."""
    key = _fingerprint(config)
    cached = _tokens.get(key)
    now = time.time()
    if cached and cached["expires_at"] > now:
        return dict(cached["headers"]), cached["summary"]

    token = _mint(config, verify_tls=verify_tls, timeout=timeout)
    lifetime = token.get("expires_in")
    try:
        ttl = max(int(lifetime) - REFRESH_MARGIN, 30) if lifetime else DEFAULT_TTL
    except (TypeError, ValueError):
        ttl = DEFAULT_TTL
    headers = {token["header_name"]: token["header_value"]}
    # The access token itself is not kept in the summary that reaches a report.
    summary = {key: value for key, value in token.items()
               if key not in ("access_token", "header_value", "refresh_token")}
    _tokens[key] = {"headers": headers, "summary": summary, "expires_at": now + ttl}
    return dict(headers), summary


def resolve(identities: dict, key: str, *, verify_tls: bool = True,
            timeout: float = 15.0) -> tuple[dict, dict | None, str]:
    """Turn one configured identity into request headers.

    Returns (headers, token summary, note). The note is empty on success and
    explains the failure otherwise, so a run reports a credential problem
    rather than producing a page of 401 findings.
    """
    value = (identities or {}).get(key) or {}
    if not isinstance(value, dict):
        return {}, None, ""

    config = value.get("oauth")
    if isinstance(config, dict) and config:
        base = value.get("headers") if isinstance(value.get("headers"), dict) else {}
        headers = {str(name): str(item) for name, item in base.items()}
        try:
            minted, summary = _token_headers(config, verify_tls=verify_tls, timeout=timeout)
        except CredentialError as exc:
            return headers, None, f"The {key} identity could not obtain an OAuth token. {exc}"
        # A minted token replaces any matching header rather than sitting beside it.
        for name in list(headers):
            if name.lower() in (item.lower() for item in minted):
                del headers[name]
        headers.update(minted)
        return headers, summary, ""

    if isinstance(value.get("headers"), dict):
        return {str(n): str(v) for n, v in value["headers"].items()}, None, ""
    # The historical shape: a flat mapping of header names to values.
    return {str(name): str(item) for name, item in value.items()
            if isinstance(item, (str, int, float))}, None, ""
