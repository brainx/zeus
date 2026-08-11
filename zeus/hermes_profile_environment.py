from __future__ import annotations

import json
import re
from pathlib import Path

from zeus.envfile import parse_env_text
from zeus.private_io import UnsafeFileError, nofollow_absolute_path, read_private_bytes

HERMES_PROFILE_ENV_MAX_BYTES = 64 * 1024
_FEISHU_MODE = "FEISHU_CONNECTION_MODE"
_INVALID_ENV_MESSAGE = "Hermes profile environment could not be validated safely"
_UNQUOTED_MODE_RE = re.compile(r"^[A-Za-z0-9_./:@%+=,-]+$")
_RESERVED_PROFILE_KEYS = frozenset({"HERMES_HOME"})
# Profile dotenv files carry bot secrets (API keys). They must never steer
# executable/library resolution or interpreter startup of Zeus or its child
# processes, otherwise a writable profile .env could substitute binaries or
# inject code into Zeus-spawned processes.
_BLOCKED_PROFILE_KEYS = frozenset(
    {
        "PATH",
        "HOME",
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONEXECUTABLE",
        "PYTHONBREAKPOINT",
        "PYTHONINSPECT",
        "BASH_ENV",
        "ENV",
        "SHELLOPTS",
        "BASHOPTS",
        "PROMPT_COMMAND",
        "IFS",
        "CDPATH",
        "GLOBIGNORE",
        "TERMINFO",
        "TERMINFO_DIRS",
        "NODE_OPTIONS",
        "PERL5OPT",
        "PERL5LIB",
        "RUBYOPT",
        "RUBYLIB",
    }
)
_BLOCKED_PROFILE_KEY_PREFIXES = ("LD_", "DYLD_", "GIT_")


def _is_blocked_profile_key(key: str) -> bool:
    normalized = key.upper()
    return normalized in _BLOCKED_PROFILE_KEYS or normalized.startswith(
        _BLOCKED_PROFILE_KEY_PREFIXES
    )


class HermesProfileEnvironmentError(ValueError):
    """Raised when a stored Hermes profile environment cannot be trusted."""


class _UnsupportedDotenvError(ValueError):
    pass


def load_hermes_profile_environment(path: Path) -> dict[str, str]:
    """Read profile dotenv values while constraining the security-relevant mode."""
    try:
        data = read_private_bytes(
            nofollow_absolute_path(path),
            HERMES_PROFILE_ENV_MAX_BYTES,
        )
        text = data.decode("utf-8", errors="strict")
        text = _validated_text(text)
        _reject_reserved_assignments(text)
        found_mode, mode = _strict_feishu_mode(text)
        values = parse_env_text(text)
        if found_mode:
            values[_FEISHU_MODE] = mode
        elif _FEISHU_MODE in values:
            raise _UnsupportedDotenvError
        return values
    except HermesProfileEnvironmentError:
        raise
    except (UnsafeFileError, UnicodeDecodeError, _UnsupportedDotenvError) as exc:
        raise HermesProfileEnvironmentError(_INVALID_ENV_MESSAGE) from exc
    except (TypeError, ValueError) as exc:
        raise HermesProfileEnvironmentError(_INVALID_ENV_MESSAGE) from exc


def _validated_text(text: str) -> str:
    if "\ufeff" in text:
        raise _UnsupportedDotenvError
    text = text.replace("\r\n", "\n")
    if "\r" in text or any(
        ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F
        for character in text
        if character != "\n"
    ):
        raise _UnsupportedDotenvError
    return text


def _strict_feishu_mode(text: str) -> tuple[bool, str]:
    found = False
    mode = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export") and len(line) > len("export"):
            suffix = line[len("export")]
            if suffix.isspace():
                line = line[len("export") :].lstrip()

        if line.startswith(f"'{_FEISHU_MODE}'"):
            raise _UnsupportedDotenvError
        key_match = re.match(r"([^=\s#]+)", line)
        if key_match is None or key_match.group(1) != _FEISHU_MODE:
            continue
        if found:
            raise _UnsupportedDotenvError
        remainder = line[key_match.end() :]
        assignment = re.match(r"\s*=\s*(.*)\Z", remainder)
        if assignment is None:
            raise _UnsupportedDotenvError
        mode = _parse_mode_value(assignment.group(1).strip())
        found = True
    return found, mode


def _reject_reserved_assignments(text: str) -> None:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export") and len(line) > len("export"):
            suffix = line[len("export")]
            if suffix.isspace():
                line = line[len("export") :].lstrip()

        if line.startswith(("'", '"')):
            quote = line[0]
            closing = line.find(quote, 1)
            if closing < 0:
                continue
            key = line[1:closing]
            remainder = line[closing + 1 :]
        else:
            key_match = re.match(r"([^=\s#]+)", line)
            if key_match is None:
                continue
            key = key_match.group(1)
            remainder = line[key_match.end() :]
        if (key in _RESERVED_PROFILE_KEYS or _is_blocked_profile_key(key)) and re.match(
            r"\s*=", remainder
        ):
            raise _UnsupportedDotenvError


def _parse_mode_value(raw_value: str) -> str:
    if "${" in raw_value:
        raise _UnsupportedDotenvError
    if not raw_value:
        return ""
    if raw_value.startswith('"'):
        try:
            value = json.loads(raw_value)
        except json.JSONDecodeError as exc:
            raise _UnsupportedDotenvError from exc
        if not isinstance(value, str) or "${" in value:
            raise _UnsupportedDotenvError
        return value
    if raw_value.startswith("'"):
        if len(raw_value) < 2 or not raw_value.endswith("'"):
            raise _UnsupportedDotenvError
        value = raw_value[1:-1]
        if "'" in value or "\\" in value or "${" in value:
            raise _UnsupportedDotenvError
        return value
    if not _UNQUOTED_MODE_RE.fullmatch(raw_value):
        raise _UnsupportedDotenvError
    return raw_value
