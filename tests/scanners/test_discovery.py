"""Conservative surface discovery tests."""

from safescope_scanners.discovery import (
    discover_graphql_schema,
    discover_javascript,
    discover_openapi,
)


def test_openapi_extracts_and_deduplicates_only_allowed_origin() -> None:
    document = {
        "paths": {
            "/api/users/{id}": {
                "parameters": [{"name": "id", "in": "path"}],
                "get": {"parameters": [{"name": "expand", "in": "query"}]},
            },
            "https://outside.test/api": {"get": {}},
        }
    }
    candidates = discover_openapi(document, "https://target.test", ("https://target.test",))
    assert [(item.method, item.url, item.parameters) for item in candidates] == [
        ("GET", "https://target.test/api/users/{id}", ("expand", "id")),
    ]


def test_javascript_extracts_quoted_api_paths_without_executing_them() -> None:
    source = "fetch('/api/users/1'); const x='/v1/orders'; const ignored='/assets/app.js'"
    candidates = discover_javascript(source, "https://target.test", ("https://target.test",))
    assert [item.url for item in candidates] == [
        "https://target.test/api/users/1",
        "https://target.test/v1/orders",
    ]


def test_graphql_uses_supplied_schema_and_rejects_out_of_scope_endpoint() -> None:
    document = {
        "data": {
            "__schema": {
                "types": [
                    {"name": "Query", "fields": [{"name": "viewer"}]},
                    {"name": "Mutation", "fields": [{"name": "updateProfile"}]},
                ]
            }
        }
    }
    allowed = discover_graphql_schema(document, "https://target.test/graphql", ("https://target.test",))
    blocked = discover_graphql_schema(document, "https://outside.test/graphql", ("https://target.test",))
    assert allowed[0].parameters == ("updateProfile", "viewer")
    assert blocked == []
