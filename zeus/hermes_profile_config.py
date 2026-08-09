from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, NoReturn

from zeus.private_io import UnsafeFileError, nofollow_absolute_path, read_private_bytes

HERMES_PROFILE_CONFIG_MAX_BYTES = 64 * 1024
_INVALID_CONFIG_MESSAGE = "Hermes profile configuration could not be validated safely"
_MAX_NESTING_DEPTH = 64
_YAML_IMPLICIT_KEYS = {
    "false",
    "n",
    "no",
    "null",
    "off",
    "on",
    "true",
    "y",
    "yes",
}


class HermesProfileConfigError(ValueError):
    """Raised when a stored Hermes profile configuration cannot be trusted."""


class _UnsupportedYamlError(ValueError):
    pass


@dataclass(frozen=True)
class _YamlLine:
    indent: int
    kind: Literal["mapping", "sequence"]
    key: str | None
    value: str | None


def load_hermes_profile_config(path: Path) -> dict[str, Any]:
    """Read a profile config through a bounded, unambiguous YAML subset."""
    try:
        data = read_private_bytes(
            nofollow_absolute_path(path),
            HERMES_PROFILE_CONFIG_MAX_BYTES,
        )
        text = data.decode("utf-8", errors="strict")
        return _parse_document(text)
    except HermesProfileConfigError:
        raise
    except (UnsafeFileError, UnicodeDecodeError, _UnsupportedYamlError) as exc:
        raise HermesProfileConfigError(_INVALID_CONFIG_MESSAGE) from exc
    except (RecursionError, TypeError, ValueError) as exc:
        raise HermesProfileConfigError(_INVALID_CONFIG_MESSAGE) from exc


def _parse_document(text: str) -> dict[str, Any]:
    if text.startswith("\ufeff"):
        text = text[1:]
    if "\ufeff" in text:
        raise _UnsupportedYamlError
    text = text.replace("\r\n", "\n")
    if "\r" in text or any(
        ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F or character in {"\u2028", "\u2029"}
        for character in text
        if character != "\n"
    ):
        raise _UnsupportedYamlError

    stripped = text.strip()
    if not stripped:
        raise _UnsupportedYamlError
    if stripped.startswith("{"):
        value = _parse_json_value(stripped)
        if not isinstance(value, dict):
            raise _UnsupportedYamlError
        return value

    lines = _tokenize(text)
    if not lines or lines[0].indent != 0 or lines[0].kind != "mapping":
        raise _UnsupportedYamlError
    value, next_index = _parse_block(lines, 0, 0, 0)
    if next_index != len(lines) or not isinstance(value, dict):
        raise _UnsupportedYamlError
    return value


def load_hermes_legacy_gateway_config(path: Path) -> dict[str, Any]:
    """Read the optional legacy gateway JSON as its effective config overlay."""
    try:
        data = read_private_bytes(
            nofollow_absolute_path(path),
            HERMES_PROFILE_CONFIG_MAX_BYTES,
            missing_ok=True,
        )
        if data is None:
            return {}
        text = data.decode("utf-8", errors="strict")
        value = _parse_json_value(text)
        if not isinstance(value, dict):
            raise _UnsupportedYamlError
        return {"gateway": value}
    except HermesProfileConfigError:
        raise
    except (UnsafeFileError, UnicodeDecodeError, _UnsupportedYamlError) as exc:
        raise HermesProfileConfigError(_INVALID_CONFIG_MESSAGE) from exc
    except (RecursionError, TypeError, ValueError) as exc:
        raise HermesProfileConfigError(_INVALID_CONFIG_MESSAGE) from exc


def _tokenize(text: str) -> list[_YamlLine]:
    result: list[_YamlLine] = []
    for raw_line in text.split("\n"):
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        content = _strip_comment(raw_line[indent:]).rstrip()
        if not content:
            continue
        if content == "%" or content.startswith("%"):
            raise _UnsupportedYamlError
        if content in {"---", "..."} or content.startswith(("--- ", "... ")):
            raise _UnsupportedYamlError
        if content == "?" or content.startswith("? "):
            raise _UnsupportedYamlError
        if content == "-":
            result.append(_YamlLine(indent, "sequence", None, None))
            continue
        if content.startswith("- "):
            result.append(_YamlLine(indent, "sequence", None, content[2:].strip()))
            continue

        separator = _mapping_separator(content)
        if separator is None:
            raise _UnsupportedYamlError
        key = _parse_key(content[:separator].strip())
        if key == "<<":
            raise _UnsupportedYamlError
        raw_value = content[separator + 1 :].strip()
        result.append(_YamlLine(indent, "mapping", key, raw_value or None))
    return result


def _parse_block(
    lines: list[_YamlLine],
    index: int,
    indent: int,
    depth: int,
) -> tuple[dict[str, Any] | list[Any], int]:
    if depth > _MAX_NESTING_DEPTH or index >= len(lines):
        raise _UnsupportedYamlError
    kind = lines[index].kind
    if kind == "mapping":
        result: dict[str, Any] | list[Any] = {}
    else:
        result = []

    while index < len(lines):
        line = lines[index]
        if line.indent < indent:
            break
        if line.indent != indent or line.kind != kind:
            raise _UnsupportedYamlError

        if kind == "mapping":
            if line.key is None or not isinstance(result, dict) or line.key in result:
                raise _UnsupportedYamlError
            key = line.key
            index += 1
            child, index = _line_value(lines, index, indent, depth, line.value)
            result[key] = child
        else:
            if not isinstance(result, list):
                raise _UnsupportedYamlError
            index += 1
            child, index = _line_value(lines, index, indent, depth, line.value)
            result.append(child)
    return result, index


def _line_value(
    lines: list[_YamlLine],
    next_index: int,
    parent_indent: int,
    depth: int,
    raw_value: str | None,
) -> tuple[Any, int]:
    has_nested_value = next_index < len(lines) and lines[next_index].indent > parent_indent
    if raw_value is not None:
        if has_nested_value:
            raise _UnsupportedYamlError
        return _parse_scalar(raw_value), next_index
    if not has_nested_value:
        return None, next_index
    return _parse_block(
        lines,
        next_index,
        lines[next_index].indent,
        depth + 1,
    )


def _parse_key(value: str) -> str:
    if not value or value[0] in "&*!|>@`[]{},":
        raise _UnsupportedYamlError
    quoted = value[0] in {'"', "'"}
    parsed = _parse_quoted_string(value) if quoted else value
    if not isinstance(parsed, str) or not parsed:
        raise _UnsupportedYamlError
    if quoted:
        return parsed
    if any(character in parsed for character in "[]{}"):
        raise _UnsupportedYamlError
    if not quoted and (
        parsed.casefold() in _YAML_IMPLICIT_KEYS or parsed[0].isdigit() or parsed[0] in "+-.~"
    ):
        raise _UnsupportedYamlError
    return parsed


def _parse_scalar(value: str) -> Any:
    if value[0] in {'"', "'"}:
        return _parse_quoted_string(value)
    if value[0] in "[{":
        return _parse_json_value(value)
    if value[0] in "&*!|>@`" or value in {"---", "..."}:
        raise _UnsupportedYamlError
    if ": " in value or any(token.startswith(("&", "*", "!")) for token in value.split()):
        raise _UnsupportedYamlError
    return value


def _parse_quoted_string(value: str) -> str:
    if value.startswith('"'):
        parsed = _parse_json_value(value)
        if not isinstance(parsed, str):
            raise _UnsupportedYamlError
        return parsed
    if len(value) < 2 or not value.endswith("'"):
        raise _UnsupportedYamlError
    inner = value[1:-1]
    result: list[str] = []
    index = 0
    while index < len(inner):
        character = inner[index]
        if character != "'":
            result.append(character)
            index += 1
            continue
        if index + 1 >= len(inner) or inner[index + 1] != "'":
            raise _UnsupportedYamlError
        result.append("'")
        index += 2
    return "".join(result)


def _parse_json_value(value: str) -> Any:
    try:
        return json.loads(
            value,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except _UnsupportedYamlError:
        raise
    except json.JSONDecodeError as exc:
        raise _UnsupportedYamlError from exc


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result or key == "<<":
            raise _UnsupportedYamlError
        result[key] = value
    return result


def _reject_json_constant(value: str) -> NoReturn:
    del value
    raise _UnsupportedYamlError


def _strip_comment(value: str) -> str:
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(value):
        character = value[index]
        if quote == '"':
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        elif quote == "'":
            if character == "'" and index + 1 < len(value) and value[index + 1] == "'":
                index += 1
            elif character == quote:
                quote = None
        elif character in {'"', "'"}:
            quote = character
        elif character == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index]
        index += 1
    return value


def _mapping_separator(value: str) -> int | None:
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(value):
        character = value[index]
        if quote == '"':
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        elif quote == "'":
            if character == "'" and index + 1 < len(value) and value[index + 1] == "'":
                index += 1
            elif character == quote:
                quote = None
        elif character in {'"', "'"}:
            quote = character
        elif character == ":" and (index + 1 == len(value) or value[index + 1].isspace()):
            return index
        index += 1
    return None
