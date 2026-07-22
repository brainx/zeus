from __future__ import annotations

import json
from typing import Any, cast
from urllib.parse import parse_qs, urlparse

MAX_JSON_DEPTH = 64
MAX_QUERY_FIELDS = 16


def normalize_api_path(target: str) -> str:
    parsed = urlparse(target)
    if parsed.fragment:
        raise ValueError("request target must not include a fragment")
    path = parsed.path
    if path == "/v1":
        return "/"
    if path.startswith("/v1/"):
        return path[3:]
    return path


def parse_query(target: str, allowed: frozenset[str]) -> dict[str, list[str]]:
    try:
        values = parse_qs(
            urlparse(target).query,
            keep_blank_values=True,
            max_num_fields=MAX_QUERY_FIELDS,
        )
    except ValueError as exc:
        raise ValueError("too many query parameters") from exc
    unknown = sorted(set(values) - allowed)
    if unknown:
        raise ValueError(f"unknown query parameter: {unknown[0]}")
    duplicates = sorted(name for name, entries in values.items() if len(entries) > 1)
    if duplicates:
        raise ValueError(f"query parameter {duplicates[0]} must be specified once")
    return values


def decode_json_object(data: bytes, *, max_depth: int = MAX_JSON_DEPTH) -> dict[str, Any]:
    try:
        parsed: object = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_json_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except RecursionError as exc:
        raise ValueError(f"request JSON nesting exceeds {max_depth}") from exc
    _validate_json_depth(parsed, max_depth=max_depth)
    if not isinstance(parsed, dict):
        raise ValueError("request body must be a JSON object")
    return cast(dict[str, Any], parsed)


def _json_object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"invalid JSON constant: {value}")


def _validate_json_depth(value: object, *, max_depth: int) -> None:
    stack = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            raise ValueError(f"request JSON nesting exceeds {max_depth}")
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
