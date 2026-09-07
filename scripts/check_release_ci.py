#!/usr/bin/env python3
"""Require the latest canonical CI push run for the exact release commit."""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Callable, Mapping
from http.client import HTTPException
from typing import Any, TextIO
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

API_ROOT = "https://api.github.com"
API_VERSION = "2026-03-10"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 15
PAGE_SIZE = 100
MAX_PAGES = 3
REPOSITORY_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z")
SHA_RE = re.compile(r"\A[0-9a-f]{40}\Z")
TAG_RE = re.compile(r"\Av[0-9][A-Za-z0-9._+-]{0,127}\Z")
REQUIRED_JOBS = frozenset(
    {
        "test (3.11)",
        "test (3.12)",
        "test (3.13)",
        "python-3-14",
        "lifecycle-subprocess",
        "audit-docker-isolation",
        "real-hermes",
        "macos-process-lifecycle",
        "package",
    }
)
ERROR_CODES = frozenset(
    {
        "invalid_environment",
        "api_request_failed",
        "api_response_invalid",
        "api_response_too_large",
        "pagination_limit",
        "ci_identity_mismatch",
        "ci_missing",
        "ci_not_successful",
        "ci_jobs_missing",
        "ci_jobs_not_successful",
        "ci_changed",
    }
)
JsonObject = dict[str, Any]
FetchJson = Callable[[str, str], JsonObject]
RunSnapshot = tuple[int, int, int, str, str | None]


class ReleaseCIError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code if code in ERROR_CODES else "api_response_invalid"
        super().__init__(self.code)


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(
        self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
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
    except (UnicodeError, ValueError, RecursionError):
        raise ReleaseCIError("api_response_invalid") from None
    return _object(value)


def _fetch_github_json(path: str, token: str, *, opener: Any = None) -> JsonObject:
    request = Request(
        f"{API_ROOT}{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "zeus-release-ci-verifier",
            "X-GitHub-Api-Version": API_VERSION,
        },
        method="GET",
    )
    active_opener = opener if opener is not None else build_opener(_NoRedirects())
    try:
        with active_opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            if getattr(response, "status", None) != 200:
                raise ReleaseCIError("api_request_failed")
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except ReleaseCIError:
        raise
    except (HTTPError, URLError, HTTPException, TimeoutError, OSError):
        raise ReleaseCIError("api_request_failed") from None
    if len(body) > MAX_RESPONSE_BYTES:
        raise ReleaseCIError("api_response_too_large")
    return _decode_json(body)


def _object(value: Any) -> JsonObject:
    if not isinstance(value, dict):
        raise ReleaseCIError("api_response_invalid")
    return value


def _positive_integer(value: Any) -> int:
    if type(value) is not int or not 0 < value < 2**63:
        raise ReleaseCIError("api_response_invalid")
    return value


def _environment(environ: Mapping[str, str]) -> tuple[str, str, str]:
    token = environ.get("GITHUB_TOKEN", "")
    repository = environ.get("GITHUB_REPOSITORY", "")
    sha = environ.get("GITHUB_SHA", "")
    tag = environ.get("GITHUB_REF_NAME", "")
    if (
        not 1 <= len(token) <= 4096
        or any(ord(character) < 33 or ord(character) > 126 for character in token)
        or REPOSITORY_RE.fullmatch(repository) is None
        or SHA_RE.fullmatch(sha) is None
        or TAG_RE.fullmatch(tag) is None
        or environ.get("GITHUB_EVENT_NAME") != "push"
        or environ.get("GITHUB_REF_TYPE") != "tag"
        or environ.get("GITHUB_REF") != f"refs/tags/{tag}"
    ):
        raise ReleaseCIError("invalid_environment")
    return token, repository, sha


def _pages(fetch: FetchJson, path: str, token: str, key: str) -> list[JsonObject]:
    items: list[JsonObject] = []
    total: int | None = None
    separator = "&" if "?" in path else "?"
    for page in range(1, MAX_PAGES + 1):
        data = _object(fetch(f"{path}{separator}per_page={PAGE_SIZE}&page={page}", token))
        count = data.get("total_count")
        if type(count) is not int or count < 0:
            raise ReleaseCIError("api_response_invalid")
        if count > PAGE_SIZE * MAX_PAGES:
            raise ReleaseCIError("pagination_limit")
        if total is not None and count != total:
            raise ReleaseCIError("ci_changed")
        total = count
        batch = data.get(key)
        if not isinstance(batch, list) or len(batch) != min(PAGE_SIZE, total - len(items)):
            raise ReleaseCIError("api_response_invalid")
        items.extend(_object(item) for item in batch)
        if len(items) == total:
            ids = [_positive_integer(item.get("id")) for item in items]
            if len(ids) != len(set(ids)):
                raise ReleaseCIError("api_response_invalid")
            return items
    raise ReleaseCIError("pagination_limit")


def _run_snapshot(run: JsonObject, repository: str, sha: str, workflow_id: int) -> RunSnapshot:
    if (
        _positive_integer(run.get("workflow_id")) != workflow_id
        or run.get("path") != ".github/workflows/ci.yml"
        or run.get("event") != "push"
        or run.get("head_branch") != "main"
        or run.get("head_sha") != sha
        or _object(run.get("repository")).get("full_name") != repository
        or _object(run.get("head_repository")).get("full_name") != repository
    ):
        raise ReleaseCIError("ci_identity_mismatch")
    status, conclusion = run.get("status"), run.get("conclusion")
    if not isinstance(status, str) or (conclusion is not None and not isinstance(conclusion, str)):
        raise ReleaseCIError("api_response_invalid")
    return (
        _positive_integer(run.get("id")),
        _positive_integer(run.get("run_number")),
        _positive_integer(run.get("run_attempt")),
        status,
        conclusion,
    )


def _latest_run(
    fetch: FetchJson, repository: str, sha: str, workflow_id: int, token: str
) -> RunSnapshot:
    path = (
        f"/repos/{repository}/actions/workflows/{workflow_id}/runs"
        f"?branch=main&event=push&head_sha={sha}"
    )
    runs = [
        _run_snapshot(run, repository, sha, workflow_id)
        for run in _pages(fetch, path, token, "workflow_runs")
    ]
    if not runs:
        raise ReleaseCIError("ci_missing")
    if len({run[1] for run in runs}) != len(runs):
        raise ReleaseCIError("api_response_invalid")
    return max(runs, key=lambda run: run[1])


def verify_release_ci(environ: Mapping[str, str], *, fetch_json: FetchJson | None = None) -> int:
    token, repository, sha = _environment(environ)
    fetch = fetch_json if fetch_json is not None else _fetch_github_json
    prefix = f"/repos/{repository}/actions"
    workflow = _object(fetch(f"{prefix}/workflows/ci.yml", token))
    if workflow.get("path") != ".github/workflows/ci.yml" or workflow.get("state") != "active":
        raise ReleaseCIError("ci_identity_mismatch")
    workflow_id = _positive_integer(workflow.get("id"))
    run = _latest_run(fetch, repository, sha, workflow_id, token)
    run_id, _number, attempt, status, conclusion = run
    if (status, conclusion) != ("completed", "success"):
        raise ReleaseCIError("ci_not_successful")

    jobs = _pages(fetch, f"{prefix}/runs/{run_id}/attempts/{attempt}/jobs", token, "jobs")
    names: set[str] = set()
    for job in jobs:
        name = job.get("name")
        if not isinstance(name, str) or not 1 <= len(name) <= 200 or name in names:
            raise ReleaseCIError("api_response_invalid")
        names.add(name)
        if (
            _positive_integer(job.get("run_id")) != run_id
            or job.get("head_sha") != sha
            or ("run_attempt" in job and _positive_integer(job["run_attempt"]) != attempt)
        ):
            raise ReleaseCIError("ci_identity_mismatch")
        if job.get("status") != "completed" or job.get("conclusion") != "success":
            raise ReleaseCIError("ci_jobs_not_successful")
    if not REQUIRED_JOBS.issubset(names):
        raise ReleaseCIError("ci_jobs_missing")

    # GitHub does not offer a snapshot transaction across these endpoints.
    # Detect a newly selected run or a restarted attempt before accepting evidence.
    if _latest_run(fetch, repository, sha, workflow_id, token) != run:
        raise ReleaseCIError("ci_changed")
    current = _object(fetch(f"{prefix}/runs/{run_id}", token))
    if _run_snapshot(current, repository, sha, workflow_id) != run:
        raise ReleaseCIError("ci_changed")
    return run_id


def main(
    *,
    environ: Mapping[str, str] | None = None,
    fetch_json: FetchJson | None = None,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    try:
        verify_release_ci(os.environ if environ is None else environ, fetch_json=fetch_json)
    except ReleaseCIError as error:
        print(f"release CI verification failed: {error.code}", file=stderr)
        return 1
    print("Verified latest main-push CI and all required jobs for the release commit.", file=stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
