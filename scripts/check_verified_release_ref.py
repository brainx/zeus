#!/usr/bin/env python3
"""Fail closed unless a release tag and its commit are GitHub-verified."""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Callable, Mapping
from typing import Any, TextIO
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

API_ROOT = "https://api.github.com"
API_VERSION = "2026-03-10"
MAX_RESPONSE_BYTES = 128 * 1024
REQUEST_TIMEOUT_SECONDS = 15
REPOSITORY_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z")
TAG_RE = re.compile(r"\Av[0-9][A-Za-z0-9._+-]{0,127}\Z")
SHA_RE = re.compile(r"\A[0-9a-f]{40}\Z")
VERIFIED_AT_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\Z")

JsonObject = dict[str, Any]
FetchJson = Callable[[str, str], JsonObject]


class ReleaseVerificationError(RuntimeError):
    """A release reference did not satisfy the verification policy."""


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _reject_constant(_value: str) -> None:
    raise ValueError("non-standard JSON constant")


def _strict_object(pairs: list[tuple[str, Any]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _decode_json(body: bytes) -> JsonObject:
    try:
        value = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError):
        raise ReleaseVerificationError("GitHub API returned malformed JSON") from None
    if not isinstance(value, dict):
        raise ReleaseVerificationError("GitHub API returned an invalid response shape")
    return value


def _fetch_github_json(path: str, token: str, *, opener: Any = None) -> JsonObject:
    request = Request(
        f"{API_ROOT}{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "zeus-release-ref-verifier",
            "X-GitHub-Api-Version": API_VERSION,
        },
        method="GET",
    )
    active_opener = opener if opener is not None else build_opener(_NoRedirects())
    try:
        with active_opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            if getattr(response, "status", None) != 200:
                raise ReleaseVerificationError("GitHub API returned an unexpected status")
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except ReleaseVerificationError:
        raise
    except (HTTPError, URLError, TimeoutError, OSError):
        raise ReleaseVerificationError("GitHub API request failed") from None

    if len(body) > MAX_RESPONSE_BYTES:
        raise ReleaseVerificationError("GitHub API response exceeded the size limit")
    return _decode_json(body)


def _required_environment(environ: Mapping[str, str], name: str) -> str:
    value = environ.get(name)
    if not value:
        raise ReleaseVerificationError(f"required workflow environment is missing: {name}")
    return value


def _object(value: Any, label: str) -> JsonObject:
    if not isinstance(value, dict):
        raise ReleaseVerificationError(f"GitHub API returned malformed {label} metadata")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        raise ReleaseVerificationError(f"GitHub API returned malformed {label} SHA")
    return value


def _require_verified(value: Any, label: str) -> None:
    verification = _object(value, f"{label} verification")
    verified_at = verification.get("verified_at")
    if (
        verification.get("verified") is not True
        or verification.get("reason") != "valid"
        or not isinstance(verified_at, str)
        or VERIFIED_AT_RE.fullmatch(verified_at) is None
    ):
        raise ReleaseVerificationError(f"{label} is not GitHub-verified")


def verify_release_ref(
    environ: Mapping[str, str],
    *,
    fetch_json: FetchJson | None = None,
) -> tuple[str, str]:
    token = _required_environment(environ, "GITHUB_TOKEN")
    if token.strip() != token or any(
        ord(character) < 33 or ord(character) > 126 for character in token
    ):
        raise ReleaseVerificationError("GITHUB_TOKEN is malformed")

    repository = _required_environment(environ, "GITHUB_REPOSITORY")
    if REPOSITORY_RE.fullmatch(repository) is None:
        raise ReleaseVerificationError("GITHUB_REPOSITORY is malformed")

    if _required_environment(environ, "GITHUB_EVENT_NAME") != "push":
        raise ReleaseVerificationError("release verification requires a push event")
    if _required_environment(environ, "GITHUB_REF_TYPE") != "tag":
        raise ReleaseVerificationError("release verification requires a tag ref")

    tag_name = _required_environment(environ, "GITHUB_REF_NAME")
    if TAG_RE.fullmatch(tag_name) is None:
        raise ReleaseVerificationError("GITHUB_REF_NAME is not a safe release tag")
    full_ref = _required_environment(environ, "GITHUB_REF")
    if full_ref != f"refs/tags/{tag_name}":
        raise ReleaseVerificationError("GITHUB_REF does not match GITHUB_REF_NAME")

    event_sha = _required_environment(environ, "GITHUB_SHA")
    if SHA_RE.fullmatch(event_sha) is None:
        raise ReleaseVerificationError("GITHUB_SHA is malformed")

    fetch = fetch_json if fetch_json is not None else _fetch_github_json
    encoded_tag = quote(tag_name, safe="")
    ref_path = f"/repos/{repository}/git/ref/tags/{encoded_tag}"
    ref_data = _object(fetch(ref_path, token), "tag ref")
    if ref_data.get("ref") != full_ref:
        raise ReleaseVerificationError("GitHub tag ref does not match the workflow ref")
    ref_object = _object(ref_data.get("object"), "tag ref")
    if ref_object.get("type") != "tag":
        raise ReleaseVerificationError("release tag is not annotated")
    tag_object_sha = _sha(ref_object.get("sha"), "tag object")

    tag_path = f"/repos/{repository}/git/tags/{tag_object_sha}"
    tag_data = _object(fetch(tag_path, token), "tag object")
    if tag_data.get("tag") != tag_name or tag_data.get("sha") != tag_object_sha:
        raise ReleaseVerificationError("GitHub tag object does not match the workflow ref")
    _require_verified(tag_data.get("verification"), "release tag")
    tag_target = _object(tag_data.get("object"), "tag target")
    if tag_target.get("type") != "commit":
        raise ReleaseVerificationError("release tag does not reference a commit")
    commit_sha = _sha(tag_target.get("sha"), "tag target")
    if commit_sha != event_sha:
        raise ReleaseVerificationError("release tag commit does not match GITHUB_SHA")

    commit_path = f"/repos/{repository}/git/commits/{commit_sha}"
    commit_data = _object(fetch(commit_path, token), "commit")
    if commit_data.get("sha") != commit_sha:
        raise ReleaseVerificationError("GitHub commit does not match the release tag")
    _require_verified(commit_data.get("verification"), "release commit")
    return tag_name, commit_sha


def main(
    *,
    environ: Mapping[str, str] | None = None,
    fetch_json: FetchJson | None = None,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    active_environment = os.environ if environ is None else environ
    try:
        tag_name, _commit_sha = verify_release_ref(
            active_environment,
            fetch_json=fetch_json,
        )
    except ReleaseVerificationError as error:
        print(f"release ref verification failed: {error}", file=stderr)
        return 1

    print(
        f"Verified GitHub release ref {tag_name}: annotated tag and commit signatures are valid.",
        file=stdout,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
