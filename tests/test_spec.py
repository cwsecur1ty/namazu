import copy
import json
from urllib.parse import parse_qs, urlsplit

import pytest

from namazu.spec import build_request, parse_spec, validate_schema


@pytest.fixture
def document():
    return {
        "openapi": "3.0.3",
        "info": {"title": "Widget API", "version": "1"},
        "servers": [{"url": "https://api.example.test/v1"}],
        "paths": {
            "/widgets/{id}": {
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "integer", "minimum": 1}},
                    {"name": "search", "in": "query", "schema": {"type": "string", "default": "inherited"}},
                ],
                "post": {
                    "operationId": "createWidget",
                    "parameters": [{"name": "search", "in": "query", "schema": {"type": "string", "default": "operation"}}],
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Widget"}}}},
                    "responses": {"201": {"description": "Created", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Widget"}}}}},
                },
            },
        },
        "components": {
            "schemas": {
                "Widget": {
                    "type": "object",
                    "required": ["name", "id", "secret"],
                    "properties": {
                        "id": {"type": "integer", "readOnly": True},
                        "name": {"type": "string", "minLength": 3},
                        "secret": {"type": "string", "writeOnly": True},
                        "active": {"type": "boolean", "default": False},
                        "tags": {"type": "array", "items": {"type": "string", "enum": ["one", "two"]}},
                    },
                },
            },
            "securitySchemes": {"Token": {"type": "http", "scheme": "bearer"}},
        },
    }


def test_parse_and_build_local_refs_parameter_inheritance(document):
    spec = parse_spec(json.dumps(document), "https://docs.example.test/openapi.json")
    operation = spec["operations"][0]
    assert operation["id"] == "POST /widgets/{id}"
    assert operation["operation_id"] == "createWidget"
    assert operation["request_body"]["content"]["application/json"]["schema"]["$ref"] == "#/components/schemas/Widget"
    assert len(operation["parameters"]) == 2
    assert operation["parameters"][1]["schema"]["default"] == "operation"
    request = build_request(spec, operation["id"])
    assert request["url"] == "https://api.example.test/v1/widgets/1"
    assert request["body"]["active"] is False
    assert "id" not in request["body"]
    assert request["request_validation"]["valid"] is True


def test_request_validation_reports_user_payload_and_parameters(document):
    request = build_request(parse_spec(document), "POST /widgets/{id}", parameters={"path.id": "not an integer"}, body={"name": "x"})
    assert request["request_validation"]["valid"] is False
    paths = [item["path"] for item in request["request_validation"]["errors"]]
    assert "$.parameters.path.id" in paths
    assert "$.body.name" in paths
    assert any("secret" in item["message"] for item in request["request_validation"]["errors"])


def test_response_required_direction_and_nullable(document):
    schema = {"$ref": "#/components/schemas/Widget"}
    assert validate_schema({"name": "demo", "id": 1}, schema, document)["valid"] is True
    assert validate_schema({"name": "demo"}, schema, document)["valid"] is False
    assert validate_schema(None, {"type": "string", "nullable": True}, document)["valid"] is True
    assert validate_schema("no", {"type": "integer", "nullable": True}, document)["valid"] is False
    assert validate_schema({}, {"type": "object", "required": ["id"], "properties": {"id": {"type": "integer", "readOnly": True}}}, document, direction="request")["valid"] is True


def test_openapi31_union_and_constraints(document):
    document["openapi"] = "3.1.0"
    assert validate_schema(None, {"type": ["string", "null"]}, document)["valid"] is True
    assert validate_schema(1, {"type": "integer", "exclusiveMinimum": 1}, document)["valid"] is False
    assert validate_schema(["A", 2], {"type": "array", "prefixItems": [{"const": "A"}, {"type": "integer"}], "items": False}, document)["valid"] is True
    assert validate_schema("not-an-email", {"type": "string", "format": "email"}, document)["valid"] is False


@pytest.mark.parametrize("schema", [{"$ref": "https://example.test/schema.json"}, {"$ref": "#/components/schemas/Missing"}, {"$dynamicRef": "#node"}, {"$id": "https://example.test/local", "type": "string"}])
def test_unsupported_or_missing_refs_never_report_pass(schema, document):
    report = validate_schema("test", schema, document)
    assert report["valid"] is None
    assert report["warnings"]


def test_external_examples_are_not_schema_refs(document):
    schema = {"type": "object", "example": {"$ref": "https://example.test/value"}}
    assert validate_schema({}, schema, document)["valid"] is True


def test_swagger_body_and_formdata():
    raw = """swagger: '2.0'
info: {title: Legacy API, version: '1'}
host: api.example.test
basePath: /v2
schemes: [https]
consumes: [application/json]
definitions:
  Input:
    type: object
    required: [name]
    properties:
      name: {type: string, default: demo}
paths:
  /create:
    post:
      parameters:
        - {name: payload, in: body, required: true, schema: {$ref: '#/definitions/Input'}}
      responses:
        200: {description: OK, schema: {$ref: '#/definitions/Input'}}
  /form:
    post:
      consumes: [application/x-www-form-urlencoded]
      parameters:
        - {name: name, in: formData, type: string, required: true}
        - {name: count, in: formData, type: integer, minimum: 2}
      responses:
        '204': {description: OK}
"""
    spec = parse_spec(raw)
    body = build_request(spec, "POST /create")
    assert body["url"] == "https://api.example.test/v2/create"
    assert body["body"] == {"name": "demo"}
    assert body["request_validation"]["valid"] is True
    assert "200" in spec["operations"][0]["responses"]
    form = build_request(spec, "POST /form")
    assert form["body"]["count"] == 2
    assert form["content_type"] == "application/x-www-form-urlencoded"
    assert form["request_validation"]["valid"] is True


def test_server_variables_path_and_operation_servers(document):
    document["servers"] = [{"url": "https://{region}.example.test/{version}", "variables": {"region": {"default": "eu"}, "version": {"default": "v3"}}}]
    document["paths"]["/widgets/{id}"]["servers"] = [{"url": "/path-server"}]
    operation = document["paths"]["/widgets/{id}"]["post"]
    operation["servers"] = [{"url": "/operation-server"}]
    spec = parse_spec(document, "https://docs.example.test/spec/openapi.json")
    assert spec["base_url"] == "https://eu.example.test/v3"
    assert build_request(spec, "POST /widgets/{id}")["url"].startswith("https://docs.example.test/operation-server/")
    assert build_request(spec, "POST /widgets/{id}", base_url="https://override.example.test/root")["url"].startswith("https://override.example.test/root/")


def test_parameter_serialization_and_header_override(document):
    operation = document["paths"]["/widgets/{id}"]["post"]
    document["paths"]["/widgets/{id}"]["parameters"][0]["schema"] = {"type": "string"}
    operation["parameters"] += [
        {"name": "tags", "in": "query", "schema": {"type": "array", "items": {"type": "string"}}},
        {"name": "filter", "in": "query", "style": "deepObject", "schema": {"type": "object", "properties": {"name": {"type": "string"}}}},
        {"name": "X-Key", "in": "header", "schema": {"type": "string"}},
        {"name": "session", "in": "cookie", "schema": {"type": "string"}},
    ]
    request = build_request(parse_spec(document), "POST /widgets/{id}", parameters={"path.id": "a/b?c", "query.tags": ["one", "two"], "query.filter": {"name": "a b"}, "header.X-Key": "generated", "cookie.session": "a;b"}, headers={"x-key": "override"})
    assert urlsplit(request["url"]).path.endswith("/a%2Fb%3Fc")
    query = parse_qs(urlsplit(request["url"]).query)
    assert query["tags"] == ["one", "two"]
    assert query["filter[name]"] == ["a b"]
    assert request["headers"]["x-key"] == "override"
    assert "X-Key" not in request["headers"]
    assert request["headers"]["Cookie"] == "session=a%3Bb"


def test_path_matrix_array_encoding(document):
    parameter = document["paths"]["/widgets/{id}"]["parameters"][0]
    parameter.update({"style": "matrix", "explode": True, "schema": {"type": "array", "items": {"type": "string"}}})
    request = build_request(parse_spec(document), "POST /widgets/{id}", parameters={"path.id": ["a/b", "c"]})
    assert request["url"].endswith("/widgets/;id=a%2Fb;id=c")


def test_optional_parameters_are_only_sent_when_explicitly_supplied(document):
    spec = parse_spec(document)
    assert "?" not in build_request(spec, "POST /widgets/{id}")["url"]
    supplied = build_request(spec, "POST /widgets/{id}", parameters={"query.search": ""})
    assert supplied["url"].endswith("?search=")


def test_allof_anyof_nested_sample_and_honest_pattern_validation(document):
    schema = {"allOf": [{"type": "object", "required": ["name"], "properties": {"name": {"type": "string", "default": "example"}}}, {"type": "object", "properties": {"child": {"anyOf": [{"type": "object", "properties": {"number": {"type": "integer", "minimum": 5}}}, {"type": "null"}]}}}]}
    document["components"]["schemas"]["Widget"] = schema
    request = build_request(parse_spec(document), "POST /widgets/{id}")
    assert request["body"] == {"name": "example", "child": {"number": 5}}
    assert request["request_validation"]["valid"] is True
    assert any("anyOf" in warning for warning in request["warnings"])
    schema["allOf"][0]["properties"]["name"] = {"type": "string", "pattern": "^[0-9]{12}$"}
    request = build_request(parse_spec(document), "POST /widgets/{id}")
    assert request["request_validation"]["valid"] is False
    assert any("Pattern" in warning for warning in request["warnings"])


def test_recursive_schema_generation_and_validation_terminates(document):
    document["components"]["schemas"]["Widget"] = {"type": "object", "properties": {"name": {"type": "string"}, "child": {"$ref": "#/components/schemas/Widget"}}}
    request = build_request(parse_spec(document), "POST /widgets/{id}")
    assert request["body"] == {"name": "string"}
    assert request["request_validation"]["valid"] is True
    assert validate_schema({"name": "a", "child": {"name": "b"}}, {"$ref": "#/components/schemas/Widget"}, document)["valid"] is True


def test_reference_objects_and_escaped_json_pointer(document):
    document["components"]["schemas"]["a/b~c"] = {"type": "string"}
    assert validate_schema("value", {"$ref": "#/components/schemas/a~1b~0c"}, document)["valid"] is True
    original = document["paths"]["/widgets/{id}"]["post"]["requestBody"]
    document["components"]["requestBodies"] = {"Input": copy.deepcopy(original)}
    document["paths"]["/widgets/{id}"]["post"]["requestBody"] = {"$ref": "#/components/requestBodies/Input"}
    assert build_request(parse_spec(document), "POST /widgets/{id}")["request_validation"]["valid"] is True


@pytest.mark.parametrize("raw", ["[]", "null", "not: [valid", {"openapi": "4.0.0", "paths": {}}, {"openapi": "3.0.3", "paths": []}, {"swagger": "2.0", "paths": {"invalid": {}}}])
def test_invalid_spec_documents_rejected(raw):
    with pytest.raises(ValueError):
        parse_spec(raw)


def test_recursive_yaml_alias_rejected():
    with pytest.raises(ValueError, match="Recursive YAML"):
        parse_spec("openapi: 3.0.3\ninfo: {}\npaths: {}\nx-recursive: &loop {child: *loop}")


def test_bad_content_type_unknown_operation_and_base_query(document):
    spec = parse_spec(document)
    with pytest.raises(ValueError, match="Unknown operation"):
        build_request(spec, "POST /missing")
    with pytest.raises(ValueError, match="Content type"):
        build_request(spec, "POST /widgets/{id}", content_type="text/plain")
    with pytest.raises(ValueError, match="query string"):
        build_request(spec, "POST /widgets/{id}", base_url="https://api.example.test?x=1")


def test_invalid_referenced_schema_cannot_pass_on_an_absent_property(document):
    document["components"]["schemas"]["Widget"] = {"type": "object", "properties": {"unused": {"type": "strung"}}}
    report = validate_schema({}, {"$ref": "#/components/schemas/Widget"}, document)
    assert report["valid"] is None
    assert "could not be completed" in report["warnings"][0]


@pytest.mark.parametrize("version,keyword", [("3.0.3", "enum"), ("3.1.0", "enum"), ("3.1.0", "const")])
def test_literal_schema_like_payloads_are_never_normalized(document, version, keyword):
    document["openapi"] = version
    payload = {"type": "string", "nullable": True, "required": ["id"], "properties": {"id": {"type": "integer", "readOnly": True}}}
    schema = {"type": "object", keyword: [payload] if keyword == "enum" else payload}
    document["components"]["schemas"]["Literal"] = schema
    assert validate_schema(payload, {"$ref": "#/components/schemas/Literal"}, document, direction="request")["valid"] is True
    mutated = {**payload, "type": ["string", "null"]}
    assert validate_schema(mutated, schema, document, direction="request")["valid"] is False


def test_nullable_does_not_bypass_enum_constraint(document):
    assert validate_schema(None, {"type": "string", "nullable": True, "enum": ["a"]}, document)["valid"] is False
    assert validate_schema(None, {"type": "string", "nullable": True, "enum": ["a", None]}, document)["valid"] is True


def test_unsupported_legacy_keywords_are_not_silently_ignored(document):
    report = validate_schema("wrong", {"const": "right"}, document)
    assert report["valid"] is None
    assert "require OpenAPI 3.1" in report["warnings"][0]


@pytest.mark.parametrize("schema", [
    {"type": "string", "minLength": None},
    {"type": "string", "format": {}},
    {"type": "array", "minItems": {}},
    {"type": "array", "prefixItems": None},
    {"type": "number", "minimum": []},
    {"type": "number", "maximum": {}},
    {"type": "integer", "minimum": 10 ** 400},
])
def test_problematic_sample_constraints_produce_warnings_instead_of_crashing(document, schema):
    document["components"]["schemas"]["Widget"] = schema
    request = build_request(parse_spec(document), "POST /widgets/{id}")
    assert request["body"] is None
    assert request["request_validation"]["valid"] is not True
    assert any("Example generation could not interpret" in item for item in request["warnings"])


def test_parameter_content_uses_media_example_and_text_is_not_json_quoted(document):
    operation = document["paths"]["/widgets/{id}"]["post"]
    operation["parameters"] = [
        {"name": "filter", "in": "query", "required": True, "content": {"application/json": {"schema": {"type": "object", "properties": {"active": {"type": "boolean"}}}, "example": {"active": False}}}},
        {"name": "X-Name", "in": "header", "required": True, "content": {"text/plain": {"schema": {"type": "string"}, "example": "hello"}}},
    ]
    request = build_request(parse_spec(document), "POST /widgets/{id}")
    assert parse_qs(urlsplit(request["url"]).query)["filter"] == ['{"active":false}']
    assert request["headers"]["X-Name"] == "hello"
    assert request["request_validation"]["valid"] is True


@pytest.mark.parametrize("change", [
    {"style": {}}, {"explode": "yes"}, {"required": []},
    {"content": {"application/json": {}}},
    {"content": {"application/json": None}},
])
def test_malformed_parameter_metadata_is_rejected_at_import(document, change):
    parameter = document["paths"]["/widgets/{id}"]["parameters"][0]
    parameter.update(change)
    with pytest.raises(ValueError):
        parse_spec(document)


def test_custom_form_encoding_is_reported_as_incomplete(document):
    document["paths"]["/widgets/{id}"]["post"]["requestBody"] = {"content": {"application/x-www-form-urlencoded": {"schema": {"type": "object", "properties": {"tags": {"type": "array", "items": {"type": "string"}}}}, "encoding": {"tags": {"style": "form", "explode": False}}}}}
    request = build_request(parse_spec(document), "POST /widgets/{id}")
    assert request["request_validation"]["valid"] is None
    assert any("Custom form" in item for item in request["warnings"])


def test_absent_parameter_schema_is_not_reported_as_valid(document):
    operation = document["paths"]["/widgets/{id}"]["post"]
    operation["parameters"] = [{"name": "filter", "in": "query", "required": True, "content": {"application/json": {"example": {"name": "x"}}}}]
    request = build_request(parse_spec(document), "POST /widgets/{id}")
    assert request["request_validation"]["valid"] is None
    assert "No schema" in request["request_validation"]["warnings"][0]


def test_malformed_nullable_flag_cannot_make_a_value_valid(document):
    report = validate_schema(None, {"type": "string", "nullable": "false"}, document)
    assert report["valid"] is None
    assert "must be a boolean" in report["warnings"][0]


def test_unresolved_request_body_reference_does_not_use_malformed_siblings(document):
    document["paths"]["/widgets/{id}"]["post"]["requestBody"] = {"$ref": "https://example.test/body.json", "content": "invalid sibling"}
    request = build_request(parse_spec(document), "POST /widgets/{id}")
    assert request["request_validation"]["valid"] is None


@pytest.mark.parametrize("location", ["global", "operation"])
@pytest.mark.parametrize("produces", [17, "application/json", None, [17]])
def test_swagger_produces_metadata_must_be_an_array_of_media_types(location, produces):
    document = {"swagger": "2.0", "info": {}, "paths": {"/widgets": {"post": {"responses": {"200": {"description": "OK"}}}}}}
    owner = document if location == "global" else document["paths"]["/widgets"]["post"]
    owner["produces"] = produces
    with pytest.raises(ValueError, match="produces must be an array"):
        parse_spec(document)


def test_swagger_produces_is_normalized_for_referenced_operations():
    document = {"swagger": "2.0", "info": {}, "produces": ["application/json"], "paths": {"/inherited": {"get": {"responses": {}}}, "/referenced": {"$ref": "#/x-paths/overridden"}}, "x-paths": {"overridden": {"get": {"produces": ["text/plain"], "responses": {}}}}}
    operations = {operation["path"]: operation for operation in parse_spec(document)["operations"]}
    assert operations["/inherited"]["produces"] == ["application/json"]
    assert operations["/referenced"]["produces"] == ["text/plain"]
