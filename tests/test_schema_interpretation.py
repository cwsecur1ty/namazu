"""Whether a realistic schema is understood, and whether we say so when it is not.

Almost every property-driven check reads the request or response schema: the
mass-assignment surface, the body injection battery, the sensitive-field
review, the generated baseline request itself. A schema shape that silently
yields no properties therefore does not produce a wrong finding, it produces no
finding, and a report that is thin for an unstated reason is indistinguishable
from a clean one.

So this file has two halves. The first walks the schema shapes a real
specification actually uses and asserts each one still yields a request body
and the properties behind it. The second is about the case that cannot be
fixed, only disclosed: Namazu reads one document, so a specification split
across files arrives with its schemas missing, and that has to be said out
loud at import and again in the run notes.
"""
import httpx
import pytest

from namazu.audit import audit_operation, specscan
from namazu.spec import build_request, parse_spec

BASE = "https://api.example.test"


def _document(schemas):
    return {
        "openapi": "3.0.3", "info": {"title": "T", "version": "1"},
        "servers": [{"url": BASE}],
        "paths": {"/thing": {"post": {
            "operationId": "createThing",
            "requestBody": {"required": True, "content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/Thing"}}}},
            "responses": {"201": {"description": "ok", "content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/Thing"}}}}},
        }}},
        "components": {"schemas": schemas},
    }


def _body(schemas):
    parsed = parse_spec(_document(schemas), BASE)
    built = build_request(parsed, "POST /thing", base_url=BASE)
    return built.get("body"), built.get("warnings") or []


def _privileged(schemas):
    parsed = parse_spec(_document(schemas), BASE)
    operation = next(op for op in parsed["operations"] if op["id"] == "POST /thing")
    return sorted({item.parameter for item in specscan.review_operation(parsed, operation)
                   if item.id == "spec.mass-assignment-surface" and item.parameter})


# ── the shapes a real specification uses ────────────────────────────────────

INHERITANCE = {
    "Base": {"type": "object", "properties": {"id": {"type": "integer"}}},
    "Thing": {"allOf": [
        {"$ref": "#/components/schemas/Base"},
        {"type": "object", "required": ["name"], "properties": {
            "name": {"type": "string"}, "is_admin": {"type": "boolean"}}},
    ]},
}
CHAIN = {
    "L1": {"type": "object", "properties": {"a": {"type": "string"}}},
    "L2": {"allOf": [{"$ref": "#/components/schemas/L1"},
                     {"type": "object", "properties": {"b": {"type": "string"}}}]},
    "Thing": {"allOf": [{"$ref": "#/components/schemas/L2"},
                        {"type": "object", "properties": {"role": {"type": "string"}}}]},
}
SIBLING_PROPERTIES = {
    "Thing": {"type": "object", "allOf": [
        {"type": "object", "properties": {"x": {"type": "string"}}},
        {"type": "object", "properties": {"role": {"type": "string"}}},
    ], "properties": {"own": {"type": "string"}}},
}
DISCRIMINATED = {
    "Cat": {"type": "object", "properties": {"kind": {"type": "string"},
                                             "owner_id": {"type": "integer"}}},
    "Dog": {"type": "object", "properties": {"kind": {"type": "string"}}},
    "Thing": {"oneOf": [{"$ref": "#/components/schemas/Cat"},
                        {"$ref": "#/components/schemas/Dog"}],
              "discriminator": {"propertyName": "kind"}},
}
HOPS = {
    "Address": {"type": "object", "properties": {"line1": {"type": "string"}}},
    "Profile": {"type": "object", "properties": {
        "address": {"$ref": "#/components/schemas/Address"},
        "role": {"type": "string"}}},
    "Thing": {"type": "object", "properties": {
        "profile": {"$ref": "#/components/schemas/Profile"}}},
}
ARRAY_OF_REFS = {
    "Item": {"type": "object", "properties": {"sku": {"type": "string"}}},
    "Thing": {"type": "object", "properties": {
        "items": {"type": "array", "items": {"$ref": "#/components/schemas/Item"}}}},
}
SELF_REFERENTIAL = {
    "Thing": {"type": "object", "properties": {
        "name": {"type": "string"},
        "parent": {"$ref": "#/components/schemas/Thing"},
        "role": {"type": "string"}}},
}
NULLABLE_UNION = {
    "Thing": {"type": "object", "properties": {
        "name": {"type": ["string", "null"]},
        "is_staff": {"type": ["boolean", "null"]}}},
}


@pytest.mark.parametrize("name,schemas,expected", [
    ("allOf inheritance", INHERITANCE, {"id", "name", "is_admin"}),
    ("nested allOf chain", CHAIN, {"a", "b", "role"}),
    ("allOf beside its own properties", SIBLING_PROPERTIES, {"x", "role", "own"}),
    ("oneOf with a discriminator", DISCRIMINATED, {"kind", "owner_id"}),
    ("object behind two ref hops", HOPS, {"profile"}),
    ("array of refs", ARRAY_OF_REFS, {"items"}),
    ("self-referential schema", SELF_REFERENTIAL, {"name", "role"}),
    ("3.1 nullable type union", NULLABLE_UNION, {"name", "is_staff"}),
])
def test_the_generated_body_carries_the_documented_fields(name, schemas, expected):
    """No body, or a body missing its fields, silences the write battery."""
    body, warnings = _body(schemas)
    assert isinstance(body, dict), f"{name}: no object body was generated ({body!r})"
    assert set(body) >= expected, f"{name}: missing {expected - set(body)}"
    assert not any("Unresolved" in note for note in warnings), warnings


@pytest.mark.parametrize("name,schemas,expected", [
    ("allOf inheritance", INHERITANCE, "is_admin"),
    ("nested allOf chain", CHAIN, "role"),
    ("allOf beside its own properties", SIBLING_PROPERTIES, "role"),
    ("object behind two ref hops", HOPS, "profile.role"),
    ("self-referential schema", SELF_REFERENTIAL, "role"),
])
def test_privileged_properties_are_found_through_composition(name, schemas, expected):
    """The mass-assignment surface is what decides whether a write probe runs."""
    found = _privileged(schemas)
    assert any(expected in entry for entry in found), f"{name}: {expected} not in {found}"


def test_a_self_referential_schema_terminates():
    """It must not recurse forever, and must not drop its own fields either."""
    body, _warnings = _body(SELF_REFERENTIAL)
    assert set(body) >= {"name", "role"}
    assert "parent" not in body or body["parent"] is None or isinstance(body["parent"], dict)


def test_read_only_fields_are_left_out_of_a_generated_request():
    body, _warnings = _body({"Thing": {"type": "object", "properties": {
        "id": {"type": "integer", "readOnly": True},
        "name": {"type": "string"}}}})
    assert "name" in body
    assert "id" not in body, "a readOnly field was sent in a request body"


# ── the case that can only be disclosed ─────────────────────────────────────

SPLIT = {"Thing": {"type": "object", "properties": {
    "name": {"type": "string"},
    "other": {"$ref": "common.yaml#/components/schemas/Other"}}}}
DANGLING = {"Thing": {"type": "object", "properties": {
    "name": {"type": "string"},
    "other": {"$ref": "#/components/schemas/NotDefinedAnywhere"}}}}


def test_a_specification_split_across_files_says_so_at_import():
    """This is the likeliest reason a real contract yields a thin report."""
    warnings = parse_spec(_document(SPLIT), BASE)["warnings"]
    joined = " ".join(warnings)
    assert "common.yaml" in joined, warnings
    assert "bundle" in joined, "the warning does not say how to fix it"


def test_a_reference_to_a_schema_that_does_not_exist_says_so_at_import():
    warnings = parse_spec(_document(DANGLING), BASE)["warnings"]
    joined = " ".join(warnings)
    assert "NotDefinedAnywhere" in joined, warnings


def test_a_ref_inside_an_example_is_data_not_a_reference():
    """enum, const, example and default hold literal API payloads."""
    schemas = {"Thing": {"type": "object", "properties": {
        "name": {"type": "string", "example": {"$ref": "this is a literal value"}},
        "kind": {"type": "string", "enum": [{"$ref": "also literal"}]}}}}
    assert parse_spec(_document(schemas), BASE)["warnings"] == []


def test_a_resolvable_document_warns_about_nothing():
    """The control. A warning on every import would be worth nothing."""
    assert parse_spec(_document(INHERITANCE), BASE)["warnings"] == []
    assert parse_spec(_document(HOPS), BASE)["warnings"] == []


def test_the_audit_notes_say_the_request_could_not_be_built_properly():
    """The run has to repeat it: an import warning is long scrolled away.

    Before this, audit_operation discarded build_request's warnings, so an
    unresolved schema reference put null in the body, the target rejected or
    mis-answered it, most probes stopped at the baseline, and the report gave
    no reason at all.
    """
    parsed = parse_spec(_document(SPLIT), BASE)

    def handler(request):
        return httpx.Response(200, json={"name": "x"})

    with httpx.Client(transport=httpx.MockTransport(handler), base_url=BASE) as client:
        result = audit_operation(parsed, "POST /thing", base_url=BASE, profile="writes",
                                 allow_mutating=True, client=client)
    notes = " ".join(result["notes"])
    assert "Building the documented request" in notes, result["notes"]
    assert "common.yaml" in notes, result["notes"]
