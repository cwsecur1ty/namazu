"""Shared local-only API contract for standalone Namazu integration tests."""

import pytest


@pytest.fixture
def api_document():
    return {
        "openapi": "3.0.3",
        "info": {"title": "Widget test API", "version": "1.0"},
        "servers": [{"url": "https://api.example.test"}],
        "paths": {
            "/widgets": {
                "post": {
                    "operationId": "createWidget",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/CreateWidget"}
                            }
                        },
                    },
                    "responses": {
                        "201": {
                            "description": "Created",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Widget"}
                                }
                            },
                        },
                        "400": {
                            "description": "Bad input",
                            "content": {
                                "application/problem+json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["detail"],
                                        "properties": {"detail": {"type": "string"}},
                                    }
                                }
                            },
                        },
                    },
                }
            },
            "/widgets/{id}": {
                "get": {
                    "operationId": "getWidget",
                    "parameters": [
                        {"name": "id", "in": "path", "required": True,
                         "schema": {"type": "integer", "minimum": 1}}
                    ],
                    "responses": {
                        "200": {
                            "description": "Found",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Widget"}
                                }
                            },
                        }
                    },
                }
            },
        },
        "components": {
            "schemas": {
                "CreateWidget": {
                    "type": "object",
                    "required": ["name", "items"],
                    "properties": {
                        "name": {"type": "string", "minLength": 1},
                        "items": {
                            "type": "array", "minItems": 1,
                            "items": {
                                "type": "object", "required": ["sku", "quantity"],
                                "properties": {
                                    "sku": {"type": "string"},
                                    "quantity": {"type": "integer", "minimum": 1},
                                },
                            },
                        },
                    },
                },
                "Widget": {
                    "type": "object", "required": ["id", "audit"],
                    "properties": {
                        "id": {"type": "integer"},
                        "audit": {
                            "type": "object", "required": ["created_by"],
                            "properties": {"created_by": {"type": "string"}},
                        },
                    },
                },
            }
        },
    }


@pytest.fixture
def widget_body():
    return {"name": "Contract sample", "items": [{"sku": "SKU-1", "quantity": 2}]}


@pytest.fixture
def widget_response():
    return {"id": 42, "audit": {"created_by": "tester"}}
