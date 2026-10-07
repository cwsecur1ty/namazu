"""External entity probes, against a real parser configured four ways.

The fixture parses with expat rather than imitating one, because the whole
probe rests on how a parser actually behaves. Three of its modes are real
configurations: expat as it comes, which expands internal entities and
silently ignores external ones; expat with an ExternalEntityRefHandler that
opens what it is given, which is the vulnerable setting; and a parser that
rejects document type declarations, which is the fix.

The fourth mode exists for the false positive that would otherwise be
unavoidable. An endpoint that quotes the request body back in its error
response puts the nonce in the response without any entity ever being
expanded, and every signal here would read it as a finding.
"""
import json
import threading
import xml.parsers.expat as expat
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest

from namazu.audit import audit_operation, xmllab
from namazu.spec import parse_spec

SPEC = {
    "openapi": "3.0.3", "info": {"title": "Orders", "version": "1"},
    "paths": {"/orders": {"post": {
        "requestBody": {"required": True, "content": {"application/xml": {"schema": {
            "type": "object", "xml": {"name": "Order"},
            "properties": {"reference": {"type": "string"}, "quantity": {"type": "integer"}},
        }}}},
        "responses": {"201": {"description": "created", "content": {
            "application/xml": {"schema": {"type": "object"}}}}}}}},
}


class _Service(BaseHTTPRequestHandler):
    """An XML endpoint whose parser is configured by ``mode``."""

    protocol_version = "HTTP/1.1"
    mode = "expands"
    bodies: ClassVar[list] = []
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

    def _parse(self, body: str) -> str:
        text: list = []
        parser = expat.ParserCreate()
        parser.CharacterDataHandler = text.append
        if _Service.mode == "secure":
            def refuse(name, system_id, public_id, has_internal):
                raise ValueError("DOCTYPE is disallowed when the feature "
                                 "http://apache.org/xml/features/disallow-doctype-decl is true.")
            parser.StartDoctypeDeclHandler = refuse
        if _Service.mode == "resolves":
            def resolve(context, base, system_id, public_id):
                # What a careless application does: hand the system id straight
                # to the filesystem. The path is in the error it raises.
                # Not a context manager on purpose: the careless call is the bug
                # being modelled, and it raises before there is anything to close.
                open(system_id)  # noqa: SIM115
                return 1
            parser.ExternalEntityRefHandler = resolve
        parser.Parse(body, True)
        return "".join(text)

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        body = raw.decode("utf-8", errors="replace")
        with _Service.lock:
            _Service.bodies.append(body)
        if _Service.mode == "value_in_error":
            # Synthetic, to exercise the probable branch: the document is
            # parsed, so entities expand, but the value only surfaces when a
            # later check rejects the document and quotes what it parsed.
            # Real apps in this family reject on a secondary rule and put the
            # offending value in the message.
            try:
                parsed = self._parse(body)
            except Exception as exc:
                return self._reply({"detail": f"could not process document: {exc}"}, 400)
            if "<!DOCTYPE" in body:
                return self._reply({"detail": f"declarations are not supported; "
                                              f"parsed value was {parsed}"}, 400)
            return self._reply({"accepted": True}, 201)
        if _Service.mode == "echo":
            # The failure mode the control exists for: the body comes back.
            return self._reply({"detail": "could not process document", "received": body}, 400)
        try:
            parsed = self._parse(body)
        except Exception as exc:
            return self._reply({"detail": f"could not process document: {exc}"}, 400)
        return self._reply({"accepted": parsed}, 201)

    def do_GET(self):
        self._reply({"orders": []})

    def do_OPTIONS(self):
        self._reply({})

    def do_TRACE(self):
        self._reply({}, 405)

    do_PUT = do_PATCH = do_DELETE = do_POST


@pytest.fixture
def service():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Service)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    spec = parse_spec(SPEC, base)

    def run(mode):
        _Service.mode = mode
        with _Service.lock:
            _Service.bodies.clear()
        return audit_operation(spec, "POST /orders", base_url=base, profile="writes",
                               allow_mutating=True)

    yield run
    server.shutdown()


def ids(result):
    return [item["id"] for item in result["findings"]]


def one(result, finding_id):
    matches = [item for item in result["findings"] if item["id"] == finding_id]
    assert len(matches) == 1, f"expected one {finding_id}, got {ids(result)}"
    return matches[0]


# ── what it finds ───────────────────────────────────────────────────────────

def test_a_parser_that_expands_entities_is_reported(service):
    """expat as it comes expands internal entities, which is why defusedxml exists."""
    report = one(service("expands"), "xxe.entity-expansion")
    assert report["severity"] == "medium"
    assert report["confidence"] == "confirmed"
    assert report["evidence"]["media_type"] == "application/xml"
    assert report["evidence"]["root_element"] == "Order"
    assert report["evidence"]["reflects_field_values"] is True


def test_expansion_alone_is_not_called_external_resolution(service):
    """Default expat ignores external entities, so the high finding must not fire."""
    assert "xxe.external-entity" not in ids(service("expands"))


def test_a_parser_that_resolves_external_entities_is_reported(service):
    report = one(service("resolves"), "xxe.external-entity")
    assert report["severity"] == "high"
    assert report["confidence"] == "confirmed"
    assert "not-a-real-path" in report["evidence"]["entity_target"]
    assert report["evidence"]["entity_expansion_seen"] is True


def test_nothing_real_is_ever_read(service):
    """The point of the design: prove the capability without using it."""
    service("resolves")
    with _Service.lock:
        sent = list(_Service.bodies)
    entities = [body for body in sent if "SYSTEM" in body]
    assert entities, "no external entity was attempted"
    for body in entities:
        assert "not-a-real-path" in body
        for real in ("/etc/passwd", "/etc/shadow", "win.ini", "/etc/hostname",
                     "file:///c:", "http://", "https://"):
            assert real not in body, f"the probe reached for {real}"


def test_the_finding_says_what_was_not_tested(service):
    report = one(service("resolves"), "xxe.external-entity")
    assert "disclosure was not attempted" in report["limitations"]
    assert "out-of-band" in report["limitations"], "blind XXE needs the OOB work"


def test_the_remediation_names_the_setting(service):
    report = one(service("resolves"), "xxe.external-entity")
    for platform in ("disallow-doctype-decl", "defusedxml", "DtdProcessing"):
        assert platform in report["remediation"]


def test_expansion_without_reflection_is_only_probable(service):
    """The two-value evaluation. Without the control to say the endpoint
    reflects field values, the nonce could have arrived some other way, so the
    finding is reported without being asserted."""
    report = one(service("value_in_error"), "xxe.entity-expansion")
    assert report["confidence"] == "probable"
    assert report["evidence"]["reflects_field_values"] is False
    assert "it does not" in report["method"], "the method has to say which case this is"


# ── what it refuses to find ─────────────────────────────────────────────────

def test_a_parser_with_doctypes_disabled_is_clean(service):
    result = service("secure")
    assert not [item for item in ids(result) if item.startswith("xxe.")]


def test_an_endpoint_that_echoes_its_input_produces_nothing(service):
    """The nonce comes back without any entity having been expanded.

    Without the control this is the probe's false positive, and it would be a
    high-severity one on an endpoint whose only fault is a verbose error.
    """
    result = service("echo")
    assert not [item for item in ids(result) if item.startswith("xxe.")], ids(result)


def test_the_control_request_is_sent_first(service):
    result = service("expands")
    labels = [entry["label"] for entry in result["log"]]
    control = next(index for index, label in enumerate(labels) if "control" in label
                   and "document type" in label)
    internal = next(index for index, label in enumerate(labels) if "internal entity" in label)
    assert control < internal, "the echo control has to run before the signal it guards"


def test_a_json_only_operation_is_never_probed():
    """Sending XML to an operation that does not accept it proves nothing."""
    assert xmllab.request_media({"request_body": {"content": {"application/json": {}}}}) == ""
    assert xmllab.request_media({}) == ""
    assert xmllab.request_media({"request_body": {"content": {"text/plain": {}}}}) == ""


def test_a_read_only_profile_sends_no_xml_body(service):
    """An XML body on a POST changes state like any other, so it needs consent."""
    _Service.mode = "resolves"
    with _Service.lock:
        _Service.bodies.clear()
    server_spec = parse_spec(SPEC, "http://127.0.0.1:1")
    result = audit_operation(server_spec, "POST /orders", base_url="http://127.0.0.1:1",
                             profile="readonly")
    assert not [item for item in ids(result) if item.startswith("xxe.")]
    with _Service.lock:
        assert _Service.bodies == []


# ── the media types and documents ───────────────────────────────────────────

@pytest.mark.parametrize("media,expected", [
    ("application/xml", "application/xml"),
    ("text/xml", "text/xml"),
    ("application/soap+xml", "application/soap+xml"),
    ("application/atom+xml", "application/atom+xml"),
    ("text/xml; charset=utf-8", "text/xml; charset=utf-8"),
    ("application/json", ""),
    ("application/xml-dtd", ""),
    ("text/xmlish", ""),
])
def test_the_xml_media_types_are_recognised(media, expected):
    assert xmllab.request_media({"request_body": {"content": {media: {}}}}) == expected


def test_a_hostile_element_name_in_the_contract_cannot_break_the_document():
    """The contract is input too. A name from it goes into markup."""
    root, children = xmllab.shape({"request_body": {"content": {"text/xml": {"schema": {
        "xml": {"name": "</x><script>"},
        "properties": {"a<b>": {"type": "string"}, "ok": {"type": "string"}},
    }}}}}, "text/xml")
    assert root == "root"
    assert all("<" not in name and ">" not in name for name in children)


def test_the_document_is_well_formed_and_carries_the_value():
    body = xmllab.document("Order", ["reference", "quantity"], "&ns;",
                           doctype=xmllab.internal_doctype("Order", "nonce1"))
    assert body.startswith('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE Order [')
    assert "<reference>&ns;</reference>" in body
    assert body.endswith("</Order>")
    # It has to parse, or the entity never gets expanded.
    text: list = []
    parser = expat.ParserCreate()
    parser.CharacterDataHandler = text.append
    parser.Parse(body, True)
    assert "nonce1" in "".join(text)


def test_a_missing_schema_still_produces_a_document():
    root, children = xmllab.shape({"request_body": {"content": {"text/xml": {}}}}, "text/xml")
    assert (root, children) == ("root", ["field"])


def test_nested_properties_are_skipped():
    """A shallow document is enough: expansion happens before model validation."""
    _, children = xmllab.shape({"request_body": {"content": {"text/xml": {"schema": {
        "properties": {"items": {"type": "array"}, "meta": {"type": "object"},
                       "name": {"type": "string"}},
    }}}}}, "text/xml")
    assert children == ["name"]


def test_a_secure_parsers_own_wording_is_recognised():
    for message in ("DOCTYPE is disallowed",
                    "http://apache.org/xml/features/disallow-doctype-decl",
                    "DTDs are not allowed",
                    "External entities are not allowed",
                    "FEATURE_SECURE_PROCESSING"):
        assert xmllab.REFUSED.search(message), message
    assert not xmllab.REFUSED.search("could not process document: syntax error")
