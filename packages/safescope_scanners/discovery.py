"""Conservative attack-surface discovery from analyst-provided artifacts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

_HTTP_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"})
_JS_PATH = re.compile(r"(?P<quote>['\"])(?P<path>/(?:api|graphql|v\d+)/[^'\"\s?#]*)(?P=quote)")


@dataclass(frozen=True, order=True)
class EndpointCandidate:
    method: str
    url: str
    parameters: tuple[str, ...] = ()
    source: str = "manual"


def discover_openapi(
    document: dict[str, Any],
    base_url: str,
    allowed_origins: tuple[str, ...],
) -> list[EndpointCandidate]:
    """Extract declared operations and parameter names from an OpenAPI document."""
    candidates: list[EndpointCandidate] = []
    paths = document.get("paths", {})
    if not isinstance(paths, dict):
        return []
    for path, path_item in paths.items():
        if not isinstance(path, str) or not isinstance(path_item, dict):
            continue
        url = urljoin(f"{base_url.rstrip('/')}/", path.lstrip("/"))
        if not _allowed(url, allowed_origins):
            continue
        shared = _parameter_names(path_item.get("parameters"))
        for method, operation in path_item.items():
            normalized_method = str(method).upper()
            if normalized_method not in _HTTP_METHODS or not isinstance(operation, dict):
                continue
            parameters = tuple(sorted(set(shared) | set(_parameter_names(operation.get("parameters")))))
            candidates.append(EndpointCandidate(normalized_method, url, parameters, "openapi"))
    return deduplicate_candidates(candidates)


def discover_graphql_schema(
    document: dict[str, Any],
    endpoint_url: str,
    allowed_origins: tuple[str, ...],
) -> list[EndpointCandidate]:
    """Extract operation names from an already supplied introspection result."""
    if not _allowed(endpoint_url, allowed_origins):
        return []
    schema = document.get("data", {}).get("__schema", {}) if isinstance(document.get("data"), dict) else {}
    types = schema.get("types", []) if isinstance(schema, dict) else []
    operation_names: set[str] = set()
    for item in types if isinstance(types, list) else []:
        if not isinstance(item, dict) or item.get("name") not in {"Query", "Mutation"}:
            continue
        for field in item.get("fields", []):
            if isinstance(field, dict) and isinstance(field.get("name"), str):
                operation_names.add(field["name"])
    if not operation_names:
        return []
    return [EndpointCandidate("POST", endpoint_url, tuple(sorted(operation_names)), "graphql-schema")]


def discover_javascript(
    source: str,
    base_url: str,
    allowed_origins: tuple[str, ...],
) -> list[EndpointCandidate]:
    """Extract only quoted API-like paths; results remain unexecuted candidates."""
    candidates = []
    for match in _JS_PATH.finditer(source):
        url = urljoin(f"{base_url.rstrip('/')}/", match.group("path").lstrip("/"))
        if _allowed(url, allowed_origins):
            candidates.append(EndpointCandidate("GET", url, source="javascript"))
    return deduplicate_candidates(candidates)


def deduplicate_candidates(candidates: list[EndpointCandidate]) -> list[EndpointCandidate]:
    """Merge duplicates by method/URL and preserve all discovered parameters."""
    merged: dict[tuple[str, str], EndpointCandidate] = {}
    for candidate in candidates:
        key = (candidate.method.upper(), candidate.url)
        current = merged.get(key)
        parameters = set(candidate.parameters)
        sources = {candidate.source}
        if current is not None:
            parameters.update(current.parameters)
            sources.update(current.source.split(","))
        merged[key] = EndpointCandidate(
            key[0],
            key[1],
            tuple(sorted(parameters)),
            ",".join(sorted(sources)),
        )
    return sorted(merged.values())


def _parameter_names(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item["name"] for item in value if isinstance(item, dict) and isinstance(item.get("name"), str))


def _allowed(url: str, origins: tuple[str, ...]) -> bool:
    parsed = urlsplit(url)
    origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
    return origin in origins and parsed.scheme.lower() in {"http", "https"}
