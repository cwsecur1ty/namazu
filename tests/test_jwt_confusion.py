"""Algorithm confusion: caught when it is real, silent when it is not.

The server bug is one line. A verifier handed the token's own ``alg`` instead
of the algorithm the route requires will check an HS256 token's HMAC against
whatever key material it holds for RS256, which is the public key. Anyone can
fetch that key, so the forgery costs nothing.

The RSA signing is stubbed, deliberately. What is under test is Namazu's
forging, its control and its decision to report, not RSA: the fixture accepts
the genuine RS256 token by identity and implements real HMAC verification for
the HS256 path, which is the path the probe exercises.
"""
import base64
import hashlib
import hmac
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest

from namazu.audit import audit_operation, jwtlab
from namazu.spec import parse_spec


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64u_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


# A fixed 2048-bit modulus with the high bit set, as a real RSA modulus has.
MODULUS = ((1 << 2047) | int("c0ffee" * 40 + "1b", 16) | 1).to_bytes(256, "big")
EXPONENT = (65537).to_bytes(3, "big")
KEY_ID = "signing-key-1"
JWK = {"kty": "RSA", "kid": KEY_ID, "use": "sig", "alg": "RS256",
       "n": b64u(MODULUS), "e": b64u(EXPONENT)}

SPKI_PEM = jwtlab.pem(jwtlab.rsa_spki_der(MODULUS, EXPONENT), "PUBLIC KEY")
PKCS1_PEM = jwtlab.pem(jwtlab.rsa_pkcs1_der(MODULUS, EXPONENT), "RSA PUBLIC KEY")

DATA = {"id": 7, "name": "widget", "owner": "alice"}


def genuine_token(issuer: str) -> str:
    """An RS256 token the fixture accepts. Its signature is never verified."""
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": KEY_ID}
    payload = {"sub": "alice", "iss": issuer, "aud": "orders",
               "iat": now, "exp": now + 3600, "role": "user"}
    signing_input = f"{b64u(json.dumps(header).encode())}.{b64u(json.dumps(payload).encode())}"
    return f"{signing_input}.{b64u(b'an-rsa-signature-this-fixture-does-not-check')}"


class _Api(BaseHTTPRequestHandler):
    """An API whose verifier is configurably wrong.

    ``mode`` selects the behaviour:

    ``confused_spki``  HMACs an HS256 token against the SubjectPublicKeyInfo PEM
    ``confused_pkcs1`` the same, against the PKCS#1 PEM
    ``correct``        accepts only the genuine RS256 token
    ``no_hmac_check``  accepts any HS256 token whatever its signature
    ``open``           returns the data with no credential at all
    """

    protocol_version = "HTTP/1.1"
    mode = "correct"
    token = ""
    issuer = ""
    seen: ClassVar[list] = []
    lock = threading.Lock()

    def log_message(self, *_args):
        pass

    def _reply(self, payload, status=200):
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _accepts(self) -> bool:
        if _Api.mode == "open":
            return True
        supplied = (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
        if not supplied or supplied.count(".") != 2:
            return False
        if supplied == _Api.token:
            return True
        try:
            header = json.loads(b64u_decode(supplied.split(".")[0]))
        except (ValueError, TypeError):
            return False
        algorithm = str(header.get("alg", "")).upper()
        if not algorithm.startswith("HS"):
            return False
        if _Api.mode == "no_hmac_check":
            return True
        secret = {"confused_spki": SPKI_PEM, "confused_pkcs1": PKCS1_PEM}.get(_Api.mode)
        if secret is None:
            return False
        signing_input, _, signature = supplied.rpartition(".")
        expected = hmac.new(secret.encode("ascii"), signing_input.encode("ascii"),
                            hashlib.sha256).digest()
        return hmac.compare_digest(b64u(expected), signature)

    def do_GET(self):
        with _Api.lock:
            _Api.seen.append((self.path, self.headers.get("Authorization")))
        if self.path == "/.well-known/openid-configuration":
            return self._reply({"issuer": _Api.issuer,
                                "jwks_uri": f"{_Api.issuer}/.well-known/jwks.json"})
        if self.path == "/.well-known/jwks.json":
            return self._reply({"keys": [JWK]})
        if not self._accepts():
            return self._reply({"detail": "unauthorized"}, 401)
        self._reply(DATA)

    def do_OPTIONS(self):
        self._reply({})

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self._reply({}, 405)

    def do_TRACE(self):
        self._reply({}, 405)


@pytest.fixture
def api():
    """Returns a function that runs an audit in a chosen verifier mode."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Api)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    _Api.issuer = base

    spec = parse_spec({
        "openapi": "3.0.3", "info": {"title": "Tokens", "version": "1"},
        "paths": {"/orders/{orderId}": {"get": {
            "security": [{"bearer": []}],
            "parameters": [{"name": "orderId", "in": "path", "required": True,
                            "schema": {"type": "integer", "example": 7}}],
            "responses": {"200": {"description": "ok", "content": {
                "application/json": {"schema": {"type": "object"}}}}}}}},
        "components": {"securitySchemes": {
            "bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}}},
    }, base)

    def run(mode, *, token=None, profile="readonly"):
        _Api.mode = mode
        _Api.token = genuine_token(base) if token is None else token
        with _Api.lock:
            _Api.seen.clear()
        return audit_operation(
            spec, "GET /orders/{orderId}", base_url=base, profile=profile,
            identities={"primary": {"Authorization": f"Bearer {_Api.token}"}})

    yield run
    server.shutdown()


def ids(result):
    return [item["id"] for item in result["findings"]]


def one(result, finding_id):
    matches = [item for item in result["findings"] if item["id"] == finding_id]
    assert len(matches) == 1, f"expected one {finding_id}, got {ids(result)}"
    return matches[0]


# ── it fires when the bug is real ───────────────────────────────────────────

def test_a_confused_verifier_is_caught(api):
    result = api("confused_spki")
    assert result["baseline_status"] == 200, "the genuine token has to work first"
    report = one(result, "jwt.alg-confusion")
    assert report["severity"] == "critical"
    assert report["confidence"] == "confirmed"
    assert report["evidence"]["key_encoding"] == "SubjectPublicKeyInfo PEM"
    assert report["evidence"]["token_algorithm"] == "RS256"
    assert report["evidence"]["forged_algorithm"] == "HS256"
    assert report["evidence"]["key_id"] == KEY_ID


def test_the_other_pem_encoding_is_caught_too(api):
    """Each encoding is a different secret, so each needs its own attempt."""
    report = one(api("confused_pkcs1"), "jwt.alg-confusion")
    assert report["evidence"]["key_encoding"] == "PKCS#1 PEM"


def test_the_report_names_the_key_source_and_the_control(api):
    report = one(api("confused_spki"), "jwt.alg-confusion")
    assert "/.well-known/jwks.json" in report["evidence"]["jwks_uri"]
    assert "control" in report["method"].lower()
    assert report["evidence"]["control_status"] == 401
    assert "algorithms=" in report["remediation"], "say what the fix looks like"


def test_the_evidence_carries_no_token(api):
    """A forged token is still a credential shape; it does not belong in a report."""
    report = one(api("confused_spki"), "jwt.alg-confusion")
    serialised = json.dumps(report)
    assert _Api.token not in serialised
    assert "an-rsa-signature" not in serialised


# ── and stays silent when it is not ─────────────────────────────────────────

def test_a_correct_verifier_produces_nothing(api):
    assert "jwt.alg-confusion" not in ids(api("correct"))
    assert "jwt.signature-not-verified" not in ids(api("correct"))


def test_a_server_that_checks_no_hmac_at_all_is_not_called_confusion(api):
    """The control's job. Accepting any HS256 token is a different bug.

    Reporting confusion here would tell the reader to go looking for a key
    being used as a secret, when the verifier is not checking signatures.
    """
    result = api("no_hmac_check")
    assert "jwt.alg-confusion" not in ids(result)
    # And prove it was the control that stopped it, not the probe never running.
    labels = [entry["label"] for entry in result["log"]]
    assert any("secret nobody holds" in label for label in labels), labels
    assert not any("signed with the SubjectPublicKeyInfo" in label for label in labels), (
        "the control should have ended the probe before any real key was tried")


def test_an_open_route_is_not_reported_as_a_signature_bypass(api):
    """A route needing no credential makes every forged token look accepted.

    This gate was missing: the JWT replays ran without the anonymous result
    that _cross_identity has always used, so an unauthenticated route produced
    a critical signature finding on top of the real one.
    """
    result = api("open")
    assert "authz.missing-authentication" in ids(result), "the real finding still fires"
    assert "jwt.signature-not-verified" not in ids(result)
    assert "jwt.alg-confusion" not in ids(result)


def test_a_token_with_no_issuer_is_not_probed(api):
    """With no iss there is no key source, so nothing is fetched."""
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": KEY_ID}
    payload = {"sub": "alice", "iat": now, "exp": now + 3600}
    signing = f"{b64u(json.dumps(header).encode())}.{b64u(json.dumps(payload).encode())}"
    result = api("confused_spki", token=f"{signing}.{b64u(b'sig')}")
    assert "jwt.alg-confusion" not in ids(result)
    with _Api.lock:
        assert not any("well-known" in path for path, _ in _Api.seen)


def test_an_hmac_signed_token_is_not_probed_for_confusion(api):
    """Confusion needs an asymmetric algorithm to confuse."""
    now = int(time.time())
    token = jwtlab.forge_hmac({"sub": "alice", "iss": _Api.issuer,
                               "iat": now, "exp": now + 3600}, "a-very-long-unguessable-secret-x")
    assert "jwt.alg-confusion" not in ids(api("correct", token=token))


# ── how it behaves while doing it ───────────────────────────────────────────

def test_the_key_fetch_carries_no_credentials(api):
    """The key set is public. Sending the target's token to fetch it is a leak."""
    api("confused_spki")
    with _Api.lock:
        fetches = [(path, auth) for path, auth in _Api.seen if "well-known" in path]
    assert fetches, "the keys were never fetched"
    for path, auth in fetches:
        assert auth is None, f"a credential was sent to {path}"


def test_the_probe_writes_nothing(api):
    result = api("confused_spki")
    assert all(entry["method"] in ("GET", "HEAD", "OPTIONS", "TRACE")
               for entry in result["log"]), "a confusion probe must not change state"


def test_the_key_fetch_shows_up_in_the_log(api):
    """An operator reading the log has to see where the key came from."""
    result = api("confused_spki")
    labels = [entry["label"] for entry in result["log"]]
    assert any("issuer's metadata" in label for label in labels)
    assert any("issuer's signing keys" in label for label in labels)


def test_an_encryption_only_key_is_never_used():
    """A key marked for encryption did not verify the signature."""
    assert jwtlab.jwks_signing_keys({"keys": [dict(JWK, use="enc")]}) == []
    assert jwtlab.jwks_signing_keys({"keys": [dict(JWK, kty="EC", crv="P-256")]}) == []
    assert jwtlab.jwks_signing_keys({"keys": [JWK]}) == [JWK]


# ── the key encoding, against known values ──────────────────────────────────

def test_the_encoder_matches_the_published_form_of_an_rsa_public_key():
    """Every 2048-bit RSA public key PEM begins with these bytes.

    Namazu has no cryptography dependency, so the encoder is checked against
    the prefix any real key file shows instead of against another library. An
    encoder that is subtly wrong would make the probe silently never fire,
    which is the one failure a security tool must not have.
    """
    spki = "".join(SPKI_PEM.splitlines()[1:-1])
    assert spki.startswith("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA")
    assert len(jwtlab.rsa_spki_der(MODULUS, EXPONENT)) == 294

    pkcs1 = "".join(PKCS1_PEM.splitlines()[1:-1])
    assert pkcs1.startswith("MIIBCgKCAQEA")
    assert len(jwtlab.rsa_pkcs1_der(MODULUS, EXPONENT)) == 270


def test_a_four_thousand_bit_key_encodes_too():
    """Exercises the multi-byte DER length form."""
    modulus = ((1 << 4095) | 1).to_bytes(512, "big")
    body = "".join(jwtlab.pem(jwtlab.rsa_spki_der(modulus, EXPONENT),
                              "PUBLIC KEY").splitlines()[1:-1])
    assert body.startswith("MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA")


def test_pem_formatting_is_what_a_library_would_have_written():
    assert SPKI_PEM.startswith("-----BEGIN PUBLIC KEY-----\n")
    assert SPKI_PEM.endswith("-----END PUBLIC KEY-----\n")
    assert max(len(line) for line in SPKI_PEM.splitlines()) <= 64


def test_a_leading_zero_in_the_modulus_does_not_change_the_key():
    """JWKS encoders differ on padding; the integer is the same either way."""
    padded = dict(JWK, n=b64u(b"\x00" + MODULUS))
    assert jwtlab.confusion_keys(padded) == jwtlab.confusion_keys(JWK)


def test_a_malformed_key_yields_no_probes():
    assert jwtlab.confusion_keys({"n": "!!!not base64!!!", "e": "AQAB"}) == []
    assert jwtlab.confusion_keys({}) == []


def test_the_three_encodings_are_three_different_secrets():
    """If two collapsed, one of the attempts would be wasted budget."""
    materials = [material for _, material in jwtlab.confusion_keys(JWK)]
    assert len(set(materials)) == 3
