from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", re.ASCII)


@dataclass(frozen=True)
class IdempotencyClaim:
    kind: Literal["claimed", "replay", "conflict", "in_progress", "indeterminate", "unavailable"]
    response_status: int | None = None
    response_json: str | None = None


def validate_idempotency_key(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("idempotency key must be a string")
    if IDEMPOTENCY_KEY_RE.fullmatch(value) is None:
        raise ValueError("idempotency key has an invalid format")
    return value


def hash_key(value: str) -> str:
    safe_value = validate_idempotency_key(value)
    return hashlib.sha256(safe_value.encode("ascii")).hexdigest()


def _validate_json_value(value: object) -> None:
    value_type = type(value)
    if value is None or value_type is bool or value_type is int or value_type is str:
        return
    if value_type is float:
        if math.isfinite(cast(float, value)):
            return
        raise ValueError("request must contain canonical JSON values")
    if value_type is list:
        for item in cast(list[object], value):
            _validate_json_value(item)
        return
    if value_type is dict:
        for key, item in cast(dict[object, object], value).items():
            if type(key) is not str:
                raise ValueError("request must contain canonical JSON values")
            _validate_json_value(item)
        return
    raise ValueError("request must contain canonical JSON values")


def _validated_query(query: object) -> dict[str, list[str]]:
    if type(query) is not dict:
        raise ValueError("request must contain canonical JSON values")

    validated: dict[str, list[str]] = {}
    for key, values in cast(dict[object, object], query).items():
        if type(key) is not str or type(values) is not list:
            raise ValueError("request must contain canonical JSON values")
        string_key = key
        string_values = cast(list[object], values)
        if any(type(value) is not str for value in string_values):
            raise ValueError("request must contain canonical JSON values")
        validated[string_key] = cast(list[str], string_values)
    return validated


def canonical_request_hash(
    method: str,
    path: str,
    query: Mapping[str, list[str]],
    body: object,
) -> str:
    if not isinstance(method, str):
        raise TypeError("request method must be a string")
    if not isinstance(path, str):
        raise TypeError("request path must be a string")
    normalized_path = path[3:] if path.startswith("/v1/") else path
    try:
        validated_query = _validated_query(query)
        _validate_json_value(body)
        payload = {
            "method": method.upper(),
            "path": normalized_path,
            "query": {key: validated_query[key] for key in sorted(validated_query)},
            "body": body,
        }
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError):
        raise ValueError("request must contain canonical JSON values") from None
    return hashlib.sha256(encoded).hexdigest()
