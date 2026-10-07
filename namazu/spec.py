"""Bounded OpenAPI parsing, request examples, and offline schema validation.

This module has no dependency on Kanine, an application server, or a database.
References are resolved only inside the supplied document; importing or validating
a specification never fetches a URL.
"""

from __future__ import annotations

import contextlib
import copy
import json
import math
import re
from typing import Any
from urllib.parse import quote, urlencode, urljoin, urlsplit, urlunsplit

import yaml
from jsonschema import Draft4Validator, Draft202012Validator, FormatChecker
from jsonschema.validators import validator_for
from referencing import Registry
from referencing.exceptions import NoSuchResource

METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_NODES = 100_000
MAX_DEPTH = 64
_MISSING = object()
_SCHEMA_MAPS = ("properties", "patternProperties", "$defs", "definitions", "dependentSchemas")
_SCHEMA_CHILDREN = ("items", "prefixItems", "additionalItems", "additionalProperties", "unevaluatedProperties", "unevaluatedItems", "contains", "propertyNames", "allOf", "oneOf", "anyOf", "not", "if", "then", "else")


def _bounded_json(value: Any, *, max_nodes: int = MAX_NODES) -> Any:
    """Copy JSON/YAML into JSON values, detecting aliases, cycles and excess depth."""
    count = 0
    text_size = 0

    def visit(item: Any, depth: int, parents: frozenset[int]) -> Any:
        nonlocal count, text_size
        count += 1
        if count > max_nodes or depth > MAX_DEPTH:
            raise ValueError("Document or value exceeds Namazu's size/depth limit")
        if isinstance(item, (dict, list)):
            if id(item) in parents:
                raise ValueError("Recursive YAML aliases are not supported")
            parents = parents | {id(item)}
        if isinstance(item, dict):
            result = {}
            for key, child in item.items():
                if not isinstance(key, (str, int, float, bool)):
                    raise ValueError("Document object keys must be strings")
                key = str(key)
                if key in result:
                    raise ValueError(f"Duplicate document key: {key}")
                result[key] = visit(child, depth + 1, parents)
            return result
        if isinstance(item, list):
            return [visit(child, depth + 1, parents) for child in item]
        if item is None or isinstance(item, (str, bool, int)):
            if isinstance(item, str):
                text_size += len(item.encode("utf-8"))
                if text_size > MAX_DOCUMENT_BYTES:
                    raise ValueError("Document or value exceeds Namazu's 8 MiB text limit")
            return item
        if isinstance(item, float) and math.isfinite(item):
            return item
        raise ValueError("Document contains a value that cannot be represented as JSON")

    return visit(value, 0, frozenset())


def _pointer(document: dict, ref: str) -> Any:
    if ref == "#":
        return document
    if not isinstance(ref, str) or not ref.startswith("#/"):
        raise ValueError(f"Only local JSON Pointer references are supported: {ref}")
    current: Any = document
    from urllib.parse import unquote

    for token in unquote(ref[2:]).split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        try:
            current = current[int(token)] if isinstance(current, list) else current[token]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise ValueError(f"Unresolved local reference: {ref}") from exc
    return current


def _object_ref(value: Any, document: dict, warnings: list[str], seen: tuple = ()) -> dict:
    if not isinstance(value, dict):
        raise ValueError("OpenAPI parameters, bodies and responses must be objects")
    if "$ref" not in value:
        return copy.deepcopy(value)
    ref = value["$ref"]
    if ref in seen or len(seen) >= 32:
        warnings.append(f"Recursive object reference was left unresolved: {ref}")
        return copy.deepcopy(value)
    try:
        target = _pointer(document, ref)
    except ValueError as exc:
        warnings.append(str(exc))
        return copy.deepcopy(value)
    resolved = _object_ref(target, document, warnings, seen + (ref,))
    # Reference Object summary/description overrides are defined in OpenAPI 3.1.
    if str(document.get("openapi", "")).startswith("3.1"):
        resolved.update({key: value[key] for key in ("summary", "description") if key in value})
    return resolved


def _servers(values: Any, source_url: str, warnings: list[str]) -> list[str]:
    if not isinstance(values, list):
        raise ValueError("OpenAPI servers must be an array")
    result = []
    for server in values:
        if not isinstance(server, dict) or not isinstance(server.get("url"), str):
            raise ValueError("Each OpenAPI server must have a URL")
        url = server["url"]
        variables = server.get("variables", {})
        if not isinstance(variables, dict):
            raise ValueError("Server variables must be an object")
        for name in re.findall(r"\{([^{}]+)\}", url):
            variable = variables.get(name, {})
            if not isinstance(variable, dict) or "default" not in variable:
                warnings.append(f"Server variable {name} has no default; set a base URL before execution")
                continue
            url = url.replace("{" + name + "}", str(variable["default"]))
        result.append(urljoin(source_url, url) if source_url else url)
    return list(dict.fromkeys(result))


def parse_spec(raw: str | dict, source_url: str = "") -> dict:
    """Read Swagger 2.0 or OpenAPI 3.0/3.1, retaining the original schema refs."""
    if isinstance(raw, str):
        if len(raw.encode("utf-8")) > MAX_DOCUMENT_BYTES:
            raise ValueError("Specification exceeds the 8 MiB limit")
        try:
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError:
                raw = yaml.safe_load(raw)
        except (yaml.YAMLError, RecursionError) as exc:
            raise ValueError(f"Invalid JSON or YAML specification: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("The specification must be a JSON or YAML object")
    document = _bounded_json(raw)
    swagger = document.get("swagger") == "2.0"
    version = str(document.get("openapi", document.get("swagger", "")))
    if not swagger and not re.fullmatch(r"3\.[01]\.\d+(?:[-+].*)?", version):
        raise ValueError("Namazu supports Swagger 2.0 and OpenAPI 3.0/3.1 specifications")
    info = document.get("info", {})
    paths = document.get("paths")
    if not isinstance(info, dict) or not isinstance(paths, dict):
        raise ValueError("The specification needs an info object and a paths object")
    warnings: list[str] = []
    source = urlsplit(source_url)
    if swagger:
        produces = document.get("produces", [])
        if not isinstance(produces, list) or any(not isinstance(item, str) for item in produces):
            raise ValueError("Swagger produces must be an array of media types")
        schemes = document.get("schemes") or [source.scheme or "https"]
        if not isinstance(schemes, list) or any(item not in ("http", "https") for item in schemes):
            raise ValueError("Swagger schemes must be HTTP or HTTPS")
        host = document.get("host", source.netloc)
        base_path = document.get("basePath", "/")
        if not isinstance(host, str) or not isinstance(base_path, str):
            raise ValueError("Swagger host and basePath must be strings")
        servers = [f"{scheme}://{host}/{base_path.lstrip('/')}" for scheme in schemes] if host else [base_path]
        schemas = document.get("definitions", {})
        security_schemes = document.get("securityDefinitions", {})
    else:
        servers = _servers(document.get("servers") or [{"url": "/"}], source_url, warnings)
        components = document.get("components", {})
        if not isinstance(components, dict):
            raise ValueError("OpenAPI components must be an object")
        schemas = components.get("schemas", {})
        security_schemes = components.get("securitySchemes", {})
    if not isinstance(schemas, dict) or not isinstance(security_schemes, dict):
        raise ValueError("Schemas and security schemes must be objects")
    operations = []
    for path, raw_path in paths.items():
        if path.startswith("x-"):
            continue
        if not path.startswith("/"):
            raise ValueError(f"Operation paths must begin with '/': {path}")
        path_item = _object_ref(raw_path, document, warnings)
        for method, operation in path_item.items():
            if method not in METHODS:
                continue
            if not isinstance(operation, dict):
                raise ValueError(f"Operation {method.upper()} {path} must be an object")
            combined: dict[tuple, dict] = {}
            unresolved_parameters = []
            for owner in (path_item, operation):
                parameters = owner.get("parameters", [])
                if not isinstance(parameters, list):
                    raise ValueError(f"Parameters for {method.upper()} {path} must be an array")
                for raw_parameter in parameters:
                    parameter = _object_ref(raw_parameter, document, warnings)
                    if "$ref" in parameter:
                        warnings.append(f"Unresolved parameter on {method.upper()} {path}")
                        unresolved_parameters.append(parameter["$ref"])
                        continue
                    locations = ("path", "query", "header", "body", "formData") if swagger else ("path", "query", "header", "cookie")
                    if not isinstance(parameter.get("name"), str) or not parameter["name"] or parameter.get("in") not in locations:
                        raise ValueError(f"Invalid parameter on {method.upper()} {path}")
                    if any(key in parameter and not isinstance(parameter[key], bool) for key in ("required", "explode", "allowReserved")):
                        raise ValueError("Parameter required, explode and allowReserved flags must be booleans")
                    if any(key in parameter and not isinstance(parameter[key], str) for key in ("style", "collectionFormat")):
                        raise ValueError("Parameter style and collectionFormat must be strings")
                    if "content" in parameter:
                        content = parameter["content"]
                        if "schema" in parameter or not isinstance(content, dict) or len(content) != 1 or not isinstance(next(iter(content.values()), None), dict):
                            raise ValueError("Parameter content must contain exactly one media object and cannot coexist with schema")
                    combined[(parameter["name"], parameter["in"])] = parameter
            parameters = list(combined.values())
            request_body = None
            if swagger:
                produces = operation.get("produces", document.get("produces", []))
                if not isinstance(produces, list) or any(not isinstance(item, str) for item in produces):
                    raise ValueError("Swagger operation produces must be an array of media types")
                consumes = operation.get("consumes", document.get("consumes", ["application/json"]))
                if not isinstance(consumes, list) or any(not isinstance(item, str) for item in consumes):
                    raise ValueError("Swagger consumes must be an array of media types")
                bodies = [param for param in parameters if param["in"] == "body"]
                forms = [param for param in parameters if param["in"] == "formData"]
                if len(bodies) > 1 or (bodies and forms):
                    raise ValueError("Swagger operations may have one body or formData parameters")
                if bodies:
                    parameter = bodies[0]
                    request_body = {"required": parameter.get("required", False), "description": parameter.get("description", ""), "content": {media: {"schema": parameter.get("schema")} for media in consumes or ["application/json"]}}
                elif forms:
                    properties = {param["name"]: {key: value for key, value in param.items() if key not in ("name", "in", "required", "collectionFormat")} for param in forms}
                    schema = {"type": "object", "properties": properties, "required": [param["name"] for param in forms if param.get("required")]}
                    media_types = [media for media in consumes if media in ("multipart/form-data", "application/x-www-form-urlencoded")] or ["application/x-www-form-urlencoded"]
                    encoding_warnings = [f"Swagger form array {param['name']} requires {param.get('collectionFormat', 'csv')} encoding; Namazu currently repeats form array fields" for param in forms if param.get("type") == "array" and param.get("collectionFormat", "csv") != "multi"]
                    request_body = {"required": bool(schema["required"]), "content": {media: {"schema": schema, "x-namazu-encoding-warnings": encoding_warnings} for media in media_types}}
                parameters = [param for param in parameters if param["in"] not in ("body", "formData")]
                for parameter in parameters:
                    if parameter.get("type") == "array":
                        parameter.setdefault("collectionFormat", "csv")
            elif "requestBody" in operation:
                request_body = _object_ref(operation["requestBody"], document, warnings)
                if "$ref" not in request_body:
                    if not isinstance(request_body.get("content"), dict):
                        raise ValueError(f"Request body for {method.upper()} {path} needs a content object")
                    if any(not isinstance(media, dict) for media in request_body["content"].values()):
                        raise ValueError("Request body media definitions must be objects")
            raw_responses = operation.get("responses", {})
            if not isinstance(raw_responses, dict):
                raise ValueError(f"Responses for {method.upper()} {path} must be an object")
            responses = {status: _object_ref(response, document, warnings) for status, response in raw_responses.items() if not status.startswith("x-")}
            op_servers = servers
            if not swagger:
                op_servers = _servers(operation.get("servers", path_item.get("servers", document.get("servers"))) or [{"url": "/"}], source_url, warnings)
            elif operation.get("schemes") and servers:
                if not isinstance(operation["schemes"], list) or any(item not in ("http", "https") for item in operation["schemes"]):
                    raise ValueError("Swagger operation schemes must be an array containing HTTP or HTTPS")
                op_servers = [urlunsplit((scheme, urlsplit(servers[0]).netloc, urlsplit(servers[0]).path, "", "")) for scheme in operation["schemes"]]
            operations.append({"id": f"{method.upper()} {path}", "operation_id": operation.get("operationId", ""), "method": method.upper(), "path": path, "summary": operation.get("summary", ""), "description": operation.get("description", ""), "deprecated": bool(operation.get("deprecated", False)), "tags": operation.get("tags", []), "parameters": parameters, "request_body": request_body, "responses": responses, "security": operation.get("security", document.get("security", [])), "servers": op_servers, "unresolved_parameters": unresolved_parameters})
            if swagger:
                operations[-1]["produces"] = list(produces)
    return {"title": str(info.get("title", "Untitled API")), "version": version, "api_version": str(info.get("version", "")), "source_url": source_url, "base_url": servers[0] if servers else "", "servers": servers, "operations": operations, "schemas": schemas, "security_schemes": security_schemes, "warnings": list(dict.fromkeys(warnings)), "document": document}


def _normalise_schema(value: Any, *, legacy: bool, direction: str, document: dict | None = None) -> Any:
    if isinstance(value, list):
        return [_normalise_schema(item, legacy=legacy, direction=direction, document=document) for item in value]
    if not isinstance(value, dict):
        return value
    # Only schema-valued keywords may be transformed. enum/const/default/examples
    # are literal API payloads, including when their keys happen to say "type".
    result = copy.deepcopy(value)
    for key in _SCHEMA_MAPS:
        if isinstance(value.get(key), dict):
            result[key] = {name: _normalise_schema(item, legacy=legacy, direction=direction, document=document) for name, item in value[key].items()}
    for key in _SCHEMA_CHILDREN:
        if key in value:
            result[key] = _normalise_schema(value[key], legacy=legacy, direction=direction, document=document)
    if isinstance(value.get("dependencies"), dict):
        result["dependencies"] = {name: _normalise_schema(item, legacy=legacy, direction=direction, document=document) if isinstance(item, (dict, bool)) else copy.deepcopy(item) for name, item in value["dependencies"].items()}
    if legacy:
        if result.get("type") == "file":
            result["type"] = "string"
        if result.get("nullable") or result.get("x-nullable"):
            if isinstance(result.get("type"), str):
                result["type"] = [result["type"], "null"]
    properties = result.get("properties", {})
    if isinstance(result.get("required"), list) and isinstance(properties, dict):
        ignored = "readOnly" if direction == "request" else "writeOnly"
        def excluded(key: str) -> bool:
            prop = properties.get(key)
            visited = set()
            while isinstance(prop, dict):
                if prop.get(ignored):
                    return True
                ref = prop.get("$ref")
                if not isinstance(ref, str) or ref in visited or not document:
                    break
                visited.add(ref)
                try:
                    prop = _pointer(document, ref)
                except ValueError:
                    break
            return False

        result["required"] = [key for key in result["required"] if not excluded(key)]
        if legacy and not result["required"]:
            del result["required"]
    return result


def _schema_dependencies(schema: Any, document: dict, references: dict[str, Any] | None = None) -> list[str]:
    """Reject any reference mode we cannot validate entirely offline."""
    warnings = []
    visited: set[str] = set()
    nodes = 0

    def visit(value: Any, depth: int = 0) -> None:
        nonlocal nodes
        nodes += 1
        if depth > MAX_DEPTH or nodes > MAX_NODES:
            raise ValueError("Schema exceeds validation depth/size limit")
        if isinstance(value, list):
            for item in value:
                visit(item, depth + 1)
        elif isinstance(value, dict):
            for flag in ("readOnly", "writeOnly", "nullable", "x-nullable"):
                if flag in value and not isinstance(value[flag], bool):
                    warnings.append(f"Schema {flag} must be a boolean")
            if not str(document.get("openapi", "")).startswith("3.1"):
                modern = set(value) & {"const", "if", "then", "else", "contains", "minContains", "maxContains", "propertyNames", "dependentRequired", "dependentSchemas", "unevaluatedProperties", "unevaluatedItems", "prefixItems"}
                if modern:
                    warnings.append(f"Schema keywords require OpenAPI 3.1: {', '.join(sorted(modern))}")
            if "$dynamicRef" in value or "$recursiveRef" in value:
                warnings.append("Dynamic or recursive-reference keywords are not supported")
            if "$schema" in value and value["$schema"] not in ("https://json-schema.org/draft/2020-12/schema", "https://json-schema.org/draft/2020-12/schema#", "http://json-schema.org/draft-04/schema#", "https://spec.openapis.org/oas/3.1/dialect/base"):
                warnings.append(f"Unsupported schema dialect: {value['$schema']}")
            if "$id" in value or ("id" in value and isinstance(value["id"], str)):
                warnings.append("Schemas with scoped identifiers cannot currently be validated")
            if "$ref" in value:
                ref = value["$ref"]
                if not isinstance(ref, str):
                    warnings.append("Schema references must be strings")
                elif ref == "#":
                    warnings.append("A schema reference to the whole OpenAPI document is not supported")
                elif ref not in visited:
                    visited.add(ref)
                    if len(visited) > 512:
                        raise ValueError("Schema exceeds the limit of 512 reachable references")
                    try:
                        target = _pointer(document, ref)
                        if references is not None:
                            references[ref] = target
                        visit(target, depth + 1)
                    except ValueError as exc:
                        warnings.append(str(exc))
            # Examples/defaults are payloads, not subschemas, and may contain $ref.
            for key in _SCHEMA_MAPS:
                if isinstance(value.get(key), dict):
                    for item in value[key].values():
                        visit(item, depth + 1)
            for key in _SCHEMA_CHILDREN:
                if key in value:
                    visit(value[key], depth + 1)
            if isinstance(value.get("dependencies"), dict):
                for item in value["dependencies"].values():
                    if isinstance(item, dict):
                        visit(item, depth + 1)

    visit(schema)
    return list(dict.fromkeys(warnings))


def _replace_pointer(document: dict, ref: str, value: Any) -> None:
    from urllib.parse import unquote

    tokens = [token.replace("~1", "/").replace("~0", "~") for token in unquote(ref[2:]).split("/")]
    parent: Any = document
    for token in tokens[:-1]:
        parent = parent[int(token)] if isinstance(parent, list) else parent[token]
    parent[int(tokens[-1]) if isinstance(parent, list) else tokens[-1]] = value


def validate_schema(value: Any, schema: Any, document: dict, *, direction: str = "response") -> dict:
    """Validate without network access; valid=None means validation was incomplete."""
    if direction not in ("request", "response"):
        raise ValueError("direction must be request or response")
    if schema is None:
        return {"valid": None, "errors": [], "warnings": ["No schema is documented for this value"]}
    if not isinstance(schema, (dict, bool)):
        return {"valid": None, "errors": [], "warnings": ["The documented schema is not an object or boolean"]}
    try:
        value = _bounded_json(value)
        references: dict[str, Any] = {}
        warnings = _schema_dependencies(schema, document, references)
        if document.get("jsonSchemaDialect") not in (None, "https://spec.openapis.org/oas/3.1/dialect/base", "https://json-schema.org/draft/2020-12/schema"):
            warnings.append(f"Unsupported document schema dialect: {document['jsonSchemaDialect']}")
        if warnings:
            return {"valid": None, "errors": [], "warnings": warnings}
        legacy = not str(document.get("openapi", "")).startswith("3.1")
        normal_document = copy.deepcopy(document)
        normal_schema = _normalise_schema(schema, legacy=legacy, direction=direction, document=document)
        validator_type = Draft4Validator if legacy else Draft202012Validator
        validator_for(normal_schema, default=validator_type).check_schema(normal_schema)
        for ref, target in references.items():
            normal_target = _normalise_schema(target, legacy=legacy, direction=direction, document=document)
            # check_schema does not follow $ref. Check every reachable definition
            # even if this particular payload does not exercise its bad field.
            validator_for(normal_target, default=validator_type).check_schema(normal_target)
            _replace_pointer(normal_document, ref, normal_target)
        key = "__namazu_validation_schema__"
        while key in normal_document:
            key += "_"
        normal_document[key] = normal_schema
        normal_document["$ref"] = "#/" + key
        # Explicitly reject retrieval even if a future schema keyword slips past preflight.
        def no_retrieval(uri: str) -> Any:
            raise NoSuchResource(ref=uri)

        validator = validator_type(normal_document, format_checker=FormatChecker(), registry=Registry(retrieve=no_retrieval))
        errors = []
        for error in validator.iter_errors(value):
            path = "$" + "".join(f"[{item}]" if isinstance(item, int) else f".{item}" for item in error.absolute_path)
            errors.append({"path": path, "message": error.message})
            if len(errors) >= 100:
                warnings.append("Validation errors were truncated at 100 entries")
                break
        return {"valid": not errors, "errors": errors, "warnings": warnings}
    except Exception as exc:
        # Invalid schemas, unresolved references, recursion, unsupported regexes etc.
        return {"valid": None, "errors": [], "warnings": [f"Schema validation could not be completed: {str(exc)[:400]}"]}


def _sample(schema: Any, document: dict, warnings: list[str], *, depth: int = 0, seen: tuple = (), budget: list[int] | None = None) -> Any:
    try:
        return _sample_unchecked(schema, document, warnings, depth=depth, seen=seen, budget=budget)
    except (TypeError, ValueError, OverflowError, KeyError, IndexError, RecursionError) as exc:
        warnings.append(f"Example generation could not interpret this schema; supply a value: {str(exc)[:160]}")
        return None


def _sample_unchecked(schema: Any, document: dict, warnings: list[str], *, depth: int = 0, seen: tuple = (), budget: list[int] | None = None) -> Any:
    budget = budget if budget is not None else [1000]
    budget[0] -= 1
    if depth > 12 or budget[0] < 0:
        warnings.append("Example generation stopped at its depth/size limit")
        return None
    if not isinstance(schema, dict):
        if schema is False:
            warnings.append("The schema forbids every value")
        return None
    for key in ("example", "default"):
        if key in schema:
            return copy.deepcopy(schema[key])
    if isinstance(schema.get("examples"), list) and schema["examples"]:
        return copy.deepcopy(schema["examples"][0])
    if "const" in schema:
        return copy.deepcopy(schema["const"])
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return copy.deepcopy(schema["enum"][0])
    if "$ref" in schema:
        ref = schema["$ref"]
        if ref in seen:
            warnings.append(f"Recursive example reference requires a supplied value: {ref}")
            return None
        try:
            target = _pointer(document, ref)
        except ValueError as exc:
            warnings.append(str(exc))
            return None
        return _sample(target, document, warnings, depth=depth + 1, seen=seen + (ref,), budget=budget)
    def child(item: Any) -> Any:
        return _sample(item, document, warnings, depth=depth + 1, seen=seen, budget=budget)

    if isinstance(schema.get("allOf"), list):
        result: Any = _MISSING
        for branch in schema["allOf"]:
            example = child(branch)
            if isinstance(result, dict) and isinstance(example, dict):
                result.update(example)
            elif result is _MISSING or result is None:
                result = example
        own = {key: value for key, value in schema.items() if key != "allOf"}
        if "properties" in own:
            example = child(own)
            if isinstance(result, dict) and isinstance(example, dict):
                result.update(example)
        return None if result is _MISSING else result
    for keyword in ("oneOf", "anyOf"):
        if isinstance(schema.get(keyword), list) and schema[keyword]:
            warnings.append(f"Example generation selected the first {keyword} branch; review before execution")
            return child(schema[keyword][0])
    kind = schema.get("type")
    if isinstance(kind, list):
        kind = next((item for item in kind if item != "null"), "null")
    if kind is None:
        kind = "object" if "properties" in schema or "additionalProperties" in schema else "array" if "items" in schema else "string"
    if kind == "object":
        result = {}
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            return result
        required = schema.get("required", [])
        for name, prop in list(properties.items())[:40]:
            resolved = prop
            if isinstance(prop, dict) and "$ref" in prop:
                with contextlib.suppress(ValueError):
                    resolved = _pointer(document, prop["$ref"])
            if isinstance(resolved, dict) and resolved.get("readOnly"):
                continue
            if isinstance(prop, dict) and prop.get("$ref") in seen and name not in required:
                continue
            result[name] = child(prop)
        if len(properties) > 40:
            warnings.append("Example object properties were limited to 40")
        return result
    if kind == "array":
        minimum = schema.get("minItems", 1)
        count = min(max(int(minimum), 0), 20)
        if schema.get("maxItems") is not None:
            count = min(count, max(0, int(schema["maxItems"])))
        if minimum > 20:
            warnings.append("Example array length was limited to 20")
        items = schema.get("items", {})
        prefixes = schema.get("prefixItems", [])
        result = [child(prefixes[index] if index < len(prefixes) else items) for index in range(count)]
        if schema.get("uniqueItems"):
            for index in range(1, len(result)):
                if result[index] in result[:index]:
                    if isinstance(result[index], str):
                        result[index] += str(index)
                    elif isinstance(result[index], (int, float)) and not isinstance(result[index], bool):
                        result[index] += index
        return result
    if kind in ("integer", "number"):
        minimum = schema.get("minimum", 0)
        maximum = schema.get("maximum")
        lower_exclusive = schema.get("exclusiveMinimum", False)
        upper_exclusive = schema.get("exclusiveMaximum", False)
        value = float(minimum)
        if isinstance(lower_exclusive, (float, int)) and not isinstance(lower_exclusive, bool):
            value = max(value, lower_exclusive + (1 if kind == "integer" else 0.1))
        elif lower_exclusive:
            value += 1 if kind == "integer" else 0.1
        if maximum is not None:
            value = min(value, float(maximum) - (1 if upper_exclusive is True else 0))
        if isinstance(upper_exclusive, (float, int)) and not isinstance(upper_exclusive, bool):
            value = min(value, upper_exclusive - (1 if kind == "integer" else 0.1))
        multiple = schema.get("multipleOf")
        if isinstance(multiple, (int, float)) and multiple > 0:
            value = math.ceil(value / multiple) * multiple
        return math.ceil(value) if kind == "integer" else value
    if kind == "boolean":
        return True
    if kind == "null":
        return None
    if kind == "file" or schema.get("format") in ("binary", "byte"):
        warnings.append("File/binary schema examples are placeholders; supply the required content")
    formats = {"date": "2026-01-01", "date-time": "2026-01-01T00:00:00Z", "email": "user@example.com", "hostname": "example.com", "ipv4": "192.0.2.1", "ipv6": "2001:db8::1", "uri": "https://example.com", "url": "https://example.com", "uuid": "123e4567-e89b-12d3-a456-426614174000", "byte": "ZXhhbXBsZQ=="}
    result = formats.get(schema.get("format"), "string")
    minimum = max(0, int(schema.get("minLength", 0)))
    maximum = max(0, int(schema.get("maxLength", max(256, minimum))))
    if minimum > 256:
        warnings.append("Example string length was limited to 256")
    result = (result + "x" * min(minimum, 256))[:max(len(result), min(minimum, 256))]
    result = result[:min(maximum, 256)]
    if "pattern" in schema:
        warnings.append(f"Pattern-constrained example must be reviewed: {schema['pattern']}")
    return result


def _parameter_schema(parameter: dict) -> Any:
    if "schema" in parameter:
        return parameter["schema"]
    content = parameter.get("content", {})
    if isinstance(content, dict) and content:
        media = content.get("application/json", next(iter(content.values())))
        return media.get("schema") if isinstance(media, dict) else None
    if "type" not in parameter:
        return None
    return {key: value for key, value in parameter.items() if key not in ("name", "in", "required", "description", "collectionFormat", "allowEmptyValue")}


def _scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value)


def _serialise_parameter(parameter: dict, value: Any, warnings: list[str]) -> list[tuple[str, str]]:
    name, location = parameter["name"], parameter["in"]
    encode = (lambda item: quote(_scalar(item), safe="")) if location == "path" else _scalar
    if parameter.get("content"):
        media_type = next(iter(parameter["content"]))
        media_name = media_type.split(";", 1)[0].strip().lower()
        if media_name == "application/json" or media_name.endswith("+json"):
            serialised = json.dumps(value, separators=(",", ":"))
        elif isinstance(value, (str, int, float, bool)) or value is None:
            serialised = _scalar(value)
        else:
            warnings.append(f"Structured parameter content for {media_type} cannot be encoded; review {location}.{name}")
            serialised = json.dumps(value, separators=(",", ":"))
        return [(name, encode(serialised))]
    if parameter.get("allowReserved"):
        warnings.append(f"Reserved characters are percent-encoded for query safety: {name}")
    style = parameter.get("style", "form" if location in ("query", "cookie") else "simple")
    explode = parameter.get("explode", style == "form")
    if "collectionFormat" in parameter:
        collection = parameter["collectionFormat"]
        if isinstance(value, list) and collection == "multi":
            return [(name, encode(item)) for item in value]
        separator = {"csv": ",", "ssv": " ", "tsv": "\t", "pipes": "|"}.get(collection, ",")
        return [(name, separator.join(encode(item) for item in value))] if isinstance(value, list) else [(name, encode(value))]
    if style == "deepObject" and location == "query" and isinstance(value, dict):
        if any(isinstance(item, (dict, list)) for item in value.values()):
            warnings.append(f"Nested deepObject values are not defined by OpenAPI: {name}")
        return [(f"{name}[{key}]", _scalar(item)) for key, item in value.items()]
    if style == "form" and explode and location in ("query", "cookie"):
        if isinstance(value, list):
            return [(name, _scalar(item)) for item in value]
        if isinstance(value, dict):
            return [(str(key), _scalar(item)) for key, item in value.items()]
    separator = {"spaceDelimited": " ", "pipeDelimited": "|"}.get(style, ",")
    if isinstance(value, list):
        serialised = separator.join(encode(item) for item in value)
    elif isinstance(value, dict):
        serialised = separator.join(f"{encode(key)}={encode(item)}" if explode else f"{encode(key)},{encode(item)}" for key, item in value.items())
    else:
        serialised = encode(value)
    if location == "path":
        if style == "label":
            serialised = "." + (serialised.replace(",", ".") if explode else serialised)
        elif style == "matrix":
            if isinstance(value, list) and explode:
                serialised = "".join(f";{name}={encode(item)}" for item in value)
            elif isinstance(value, dict) and explode:
                serialised = "".join(f";{encode(key)}={encode(item)}" for key, item in value.items())
            else:
                serialised = f";{name}={serialised}"
    if style not in ("simple", "form", "label", "matrix", "spaceDelimited", "pipeDelimited", "deepObject"):
        warnings.append(f"Unsupported parameter style {style}; review {location}.{name}")
    return [(name, serialised)]


def build_request(spec: dict, operation_id: str, *, base_url: str | None = None, parameters: dict | None = None, body: Any = ..., content_type: str | None = None, headers: dict | None = None) -> dict:
    """Build an editable request preview. This function performs no HTTP requests."""
    operation = next((op for op in spec["operations"] if op["id"] == operation_id), None)
    if operation is None:
        raise ValueError(f"Unknown operation: {operation_id}")
    overrides = parameters or {}
    if not isinstance(overrides, dict) or not isinstance(headers or {}, dict):
        raise ValueError("Parameters and headers must be objects")
    document = spec["document"]
    warnings: list[str] = []
    request_headers = {}
    query: list[tuple[str, str]] = []
    cookies: list[tuple[str, str]] = []
    path = operation["path"]
    validation_errors = []
    validation_warnings = []
    validation_states = []
    if operation.get("unresolved_parameters"):
        validation_states.append(None)
        validation_warnings.append("Some parameter references could not be resolved; request validation is incomplete")
    expected_keys = set()
    for parameter in operation["parameters"]:
        key = f"{parameter['in']}.{parameter['name']}"
        expected_keys.add(key)
        # Absence is the omission signal. Explicit null remains a real value for
        # nullable schemas, and documented defaults apply on the server itself.
        if key not in overrides and not parameter.get("required") and parameter["in"] != "path":
            continue
        schema = _parameter_schema(parameter)
        if key in overrides:
            value = overrides[key]
        elif "example" in parameter:
            value = copy.deepcopy(parameter["example"])
        elif isinstance(parameter.get("examples"), dict) and parameter["examples"]:
            example = _object_ref(next(iter(parameter["examples"].values())), document, warnings)
            value = copy.deepcopy(example.get("value")) if "value" in example else _sample(schema, document, warnings)
        elif parameter.get("content"):
            media = next(iter(parameter["content"].values()))
            if "example" in media:
                value = copy.deepcopy(media["example"])
            elif isinstance(media.get("examples"), dict) and media["examples"]:
                example = _object_ref(next(iter(media["examples"].values())), document, warnings)
                value = copy.deepcopy(example["value"]) if "value" in example else _sample(schema, document, warnings)
            else:
                value = _sample(schema, document, warnings)
        else:
            value = _sample(schema, document, warnings)
        report = validate_schema(value, schema, document, direction="request")
        validation_states.append(report["valid"])
        validation_errors.extend({"path": f"$.parameters.{key}" + item["path"][1:], "message": item["message"]} for item in report["errors"])
        validation_warnings.extend(report["warnings"])
        pairs = _serialise_parameter(parameter, value, warnings)
        location = parameter["in"]
        if location == "path":
            path = path.replace("{" + parameter["name"] + "}", pairs[0][1])
        elif location == "query":
            query.extend(pairs)
        elif location == "header":
            request_headers.update(pairs)
        elif location == "cookie":
            cookies.extend(pairs)
    for key in overrides.keys() - expected_keys:
        warnings.append(f"Parameter override does not match the operation: {key}")
    unresolved = re.findall(r"\{[^{}]+\}", path)
    if unresolved:
        validation_states.append(False)
        validation_errors.append({"path": "$.url", "message": f"Missing path parameter definitions: {', '.join(unresolved)}"})
    if cookies:
        request_headers["Cookie"] = "; ".join(f"{quote(name, safe='')}={quote(value, safe='')}" for name, value in cookies)
    request_body = operation.get("request_body")
    has_body = body is not ...
    body_value = body if has_body else None
    if request_body:
        media = {} if "$ref" in request_body else request_body.get("content", {})
        if not media:
            validation_states.append(None)
            validation_warnings.append("The request body definition could not be resolved")
        else:
            content_type = content_type or next((name for name in media if name == "application/json"), next((name for name in media if name.endswith("+json")), next(iter(media))))
            media_object = media.get(content_type)
            if not isinstance(media_object, dict):
                raise ValueError(f"Content type is not documented for this operation: {content_type}")
            schema = media_object.get("schema")
            encoding_warnings = media_object.get("x-namazu-encoding-warnings", [])
            encoding_warnings = list(encoding_warnings) if isinstance(encoding_warnings, list) and all(isinstance(item, str) for item in encoding_warnings) else []
            if media_object.get("encoding"):
                encoding_warnings.append("Custom form field encoding rules are not applied; review the serialized request before execution")
            if encoding_warnings:
                warnings.extend(encoding_warnings)
                validation_states.append(None)
                validation_warnings.extend(encoding_warnings)
            if body is ...:
                if "example" in media_object:
                    body_value = copy.deepcopy(media_object["example"])
                elif isinstance(media_object.get("examples"), dict) and media_object["examples"]:
                    example = _object_ref(next(iter(media_object["examples"].values())), document, warnings)
                    body_value = copy.deepcopy(example["value"]) if "value" in example else _sample(schema, document, warnings)
                else:
                    body_value = _sample(schema, document, warnings)
            has_body = True
            report = validate_schema(body_value, schema, document, direction="request")
            validation_states.append(report["valid"])
            validation_errors.extend({"path": "$.body" + item["path"][1:], "message": item["message"]} for item in report["errors"])
            validation_warnings.extend(report["warnings"])
    elif has_body:
        content_type = content_type or "application/json"
        validation_states.append(None)
        validation_warnings.append("This operation does not document a request body schema")
    if has_body and content_type:
        request_headers["Content-Type"] = content_type
    for key, value in (headers or {}).items():
        for previous in list(request_headers):
            if previous.lower() == str(key).lower():
                del request_headers[previous]
        request_headers[str(key)] = str(value)
    selected_base = base_url if base_url is not None else next(iter(operation.get("servers") or []), spec.get("base_url", ""))
    parsed = urlsplit(selected_base)
    if parsed.query or parsed.fragment:
        raise ValueError("Base URL must not contain a query string or fragment")
    url = selected_base.rstrip("/") + "/" + path.lstrip("/")
    if query:
        url += "?" + urlencode(query)
    valid = False if False in validation_states else None if None in validation_states else True
    return {"method": operation["method"], "url": url, "headers": request_headers, "body": _bounded_json(body_value), "content_type": content_type, "has_body": has_body, "warnings": list(dict.fromkeys(warnings)), "request_validation": {"valid": valid, "errors": validation_errors, "warnings": list(dict.fromkeys(validation_warnings))}}
