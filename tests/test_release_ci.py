from __future__ import annotations

import io
import json
import runpy
import unittest
from copy import deepcopy
from http.client import IncompleteRead
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.error import HTTPError, URLError

SCRIPT = runpy.run_path("scripts/check_release_ci.py")
ReleaseCIError = SCRIPT["ReleaseCIError"]
verify_release_ci = SCRIPT["verify_release_ci"]
fetch_github_json = SCRIPT["_fetch_github_json"]
decode_json = SCRIPT["_decode_json"]
main = SCRIPT["main"]

SHA = "a" * 40
TOKEN = "release-ci-token-sentinel"
PREFIX = "/repos/brainx/zeus/actions"
RUNS_PATH = f"{PREFIX}/workflows/7/runs?branch=main&event=push&head_sha={SHA}"
JOB_NAMES = (
    "test (3.11)",
    "test (3.12)",
    "test (3.13)",
    "python-3-14",
    "lifecycle-subprocess",
    "audit-docker-isolation",
    "real-hermes",
    "macos-process-lifecycle",
    "package",
)


def _environment() -> dict[str, str]:
    return {
        "GITHUB_TOKEN": TOKEN,
        "GITHUB_REPOSITORY": "brainx/zeus",
        "GITHUB_SHA": SHA,
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF_TYPE": "tag",
        "GITHUB_REF_NAME": "v0.6.0",
        "GITHUB_REF": "refs/tags/v0.6.0",
    }


def _run(number: int = 10, *, attempt: int = 1, **changes: Any) -> dict[str, Any]:
    value = {
        "id": number + 1000,
        "run_number": number,
        "run_attempt": attempt,
        "workflow_id": 7,
        "path": ".github/workflows/ci.yml",
        "event": "push",
        "head_branch": "main",
        "head_sha": SHA,
        "repository": {"full_name": "brainx/zeus"},
        "head_repository": {"full_name": "brainx/zeus"},
        "status": "completed",
        "conclusion": "success",
    }
    value.update(changes)
    return value


def _jobs(run: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "id": number + 2000,
            "name": name,
            "run_id": run["id"],
            "head_sha": SHA,
            "run_attempt": run["run_attempt"],
            "status": "completed",
            "conclusion": "success",
        }
        for number, name in enumerate(JOB_NAMES)
    ]


def _responses(runs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    runs = [_run()] if runs is None else runs
    data: dict[str, Any] = {
        f"{PREFIX}/workflows/ci.yml": {
            "id": 7,
            "path": ".github/workflows/ci.yml",
            "state": "active",
        },
    }
    for page in range(max(1, (len(runs) + 99) // 100)):
        data[f"{RUNS_PATH}&per_page=100&page={page + 1}"] = {
            "total_count": len(runs),
            "workflow_runs": runs[page * 100 : (page + 1) * 100],
        }
    if runs:
        latest = max(runs, key=lambda run: run["run_number"])
        data[f"{PREFIX}/runs/{latest['id']}"] = deepcopy(latest)
        data[
            f"{PREFIX}/runs/{latest['id']}/attempts/{latest['run_attempt']}/jobs?per_page=100&page=1"
        ] = {
            "total_count": len(JOB_NAMES),
            "jobs": _jobs(latest),
        }
    return data


def _jobs_page(data: dict[str, Any]) -> dict[str, Any]:
    return next(value for key, value in data.items() if "/jobs?" in key)


class ReleaseCITests(unittest.TestCase):
    def _verify(self, data: dict[str, Any]) -> int:
        return verify_release_ci(_environment(), fetch_json=lambda path, _token: data[path])

    def _reject(self, code: str, data: dict[str, Any]) -> None:
        with self.assertRaises(ReleaseCIError) as raised:
            self._verify(data)
        self.assertEqual(code, raised.exception.code)

    def test_complete_canonical_push_passes_and_rechecks_latest_run_and_attempt(self) -> None:
        data = _responses()
        calls = []

        def fetch(path: str, token: str) -> dict[str, Any]:
            self.assertEqual(TOKEN, token)
            calls.append(path)
            return data[path]

        self.assertEqual(1010, verify_release_ci(_environment(), fetch_json=fetch))
        self.assertEqual(
            [
                f"{PREFIX}/workflows/ci.yml",
                f"{RUNS_PATH}&per_page=100&page=1",
                f"{PREFIX}/runs/1010/attempts/1/jobs?per_page=100&page=1",
                f"{RUNS_PATH}&per_page=100&page=1",
                f"{PREFIX}/runs/1010",
            ],
            calls,
        )

    def test_invalid_environment_is_rejected_before_network(self) -> None:
        for key, value in (
            ("GITHUB_TOKEN", ""),
            ("GITHUB_TOKEN", "bad\nheader"),
            ("GITHUB_TOKEN", "\N{SNOWMAN}"),
            ("GITHUB_TOKEN", "a" * 4097),
            ("GITHUB_REPOSITORY", "brainx/zeus/../other"),
            ("GITHUB_SHA", "wrong"),
            ("GITHUB_EVENT_NAME", "workflow_dispatch"),
            ("GITHUB_REF_TYPE", "branch"),
            ("GITHUB_REF_NAME", "v0.6.0/extra"),
            ("GITHUB_REF", "refs/heads/main"),
        ):
            with self.subTest(key=key, value=value):
                env = _environment()
                env[key] = value

                def unexpected_fetch(_path: str, _token: str) -> dict[str, Any]:
                    self.fail("invalid environment must not make API requests")

                with self.assertRaises(ReleaseCIError) as raised:
                    verify_release_ci(env, fetch_json=unexpected_fetch)
                self.assertEqual("invalid_environment", raised.exception.code)

    def test_missing_ci_or_disabled_or_replaced_workflow_is_rejected(self) -> None:
        self._reject("ci_missing", _responses([]))
        for field, value in (
            ("path", ".github/workflows/fake.yml"),
            ("state", "disabled_manually"),
        ):
            with self.subTest(field=field):
                data = _responses()
                data[f"{PREFIX}/workflows/ci.yml"][field] = value
                self._reject("ci_identity_mismatch", data)

    def test_api_filter_is_not_trusted_to_establish_run_identity(self) -> None:
        for field, value in (
            ("workflow_id", 8),
            ("path", ".github/workflows/release.yml"),
            ("event", "pull_request"),
            ("event", "workflow_dispatch"),
            ("head_branch", "v0.6.0"),
            ("head_branch", "feature"),
            ("head_sha", "b" * 40),
            ("repository", {"full_name": "other/zeus"}),
            ("head_repository", {"full_name": "other/zeus"}),
        ):
            with self.subTest(field=field, value=value):
                self._reject("ci_identity_mismatch", _responses([_run(**{field: value})]))

    def test_newest_run_number_wins_even_when_older_success_is_first(self) -> None:
        for status, conclusion in (
            ("completed", "failure"),
            ("completed", "cancelled"),
            ("completed", "skipped"),
            ("completed", "neutral"),
            ("in_progress", None),
            ("queued", None),
        ):
            with self.subTest(status=status, conclusion=conclusion):
                self._reject(
                    "ci_not_successful",
                    _responses([_run(1), _run(2, status=status, conclusion=conclusion)]),
                )
        self.assertEqual(1002, self._verify(_responses([_run(2), _run(1, conclusion="failure")])))

    def test_bounded_pagination_does_not_hide_newer_runs(self) -> None:
        runs = [_run(number) for number in range(1, 102)]
        self.assertEqual(1101, self._verify(_responses(runs)))
        runs[-1]["conclusion"] = "failure"
        self._reject("ci_not_successful", _responses(runs))
        data = _responses()
        data[f"{RUNS_PATH}&per_page=100&page=1"]["total_count"] = 301
        self._reject("pagination_limit", data)

    def test_pagination_rejects_missing_rows_duplicates_and_changing_counts(self) -> None:
        data = _responses()
        data[f"{RUNS_PATH}&per_page=100&page=1"]["total_count"] = 2
        self._reject("api_response_invalid", data)
        self._reject("api_response_invalid", _responses([_run(), _run()]))
        self._reject("api_response_invalid", _responses([_run(), _run(id=9999)]))
        data = _responses([_run(number) for number in range(1, 102)])
        data[f"{RUNS_PATH}&per_page=100&page=2"]["total_count"] = 102
        self._reject("ci_changed", data)

    def test_every_required_job_must_be_present_and_successful_in_current_attempt(self) -> None:
        for name in JOB_NAMES:
            with self.subTest(missing=name):
                data = _responses([_run(attempt=2)])
                page = _jobs_page(data)
                page["jobs"] = [job for job in page["jobs"] if job["name"] != name]
                page["total_count"] -= 1
                self._reject("ci_jobs_missing", data)
            for status, conclusion in (
                ("completed", "failure"),
                ("completed", "cancelled"),
                ("completed", "skipped"),
                ("completed", "neutral"),
                ("in_progress", None),
            ):
                with self.subTest(name=name, status=status, conclusion=conclusion):
                    data = _responses()
                    job = next(job for job in _jobs_page(data)["jobs"] if job["name"] == name)
                    job.update(status=status, conclusion=conclusion)
                    self._reject("ci_jobs_not_successful", data)

    def test_jobs_cannot_borrow_identity_or_success_from_another_attempt(self) -> None:
        for field, value in (("run_id", 999), ("head_sha", "b" * 40), ("run_attempt", 1)):
            with self.subTest(field=field):
                data = _responses([_run(attempt=2)])
                _jobs_page(data)["jobs"][0][field] = value
                self._reject("ci_identity_mismatch", data)
        data = _responses()
        _jobs_page(data)["jobs"][1]["name"] = JOB_NAMES[0]
        self._reject("api_response_invalid", data)

    def test_jobs_without_optional_attempt_field_are_bound_by_attempt_endpoint(self) -> None:
        data = _responses([_run(attempt=2)])
        for job in _jobs_page(data)["jobs"]:
            del job["run_attempt"]
        self.assertEqual(1010, self._verify(data))

    def test_job_pagination_checks_additional_jobs_instead_of_stopping_after_required(self) -> None:
        data = _responses()
        path = f"{PREFIX}/runs/1010/attempts/1/jobs?per_page=100&page=1"
        jobs = _jobs_page(data)["jobs"]
        for number in range(9, 101):
            jobs.append({**jobs[0], "id": 2000 + number, "name": f"extra-{number}"})
        data[path] = {"total_count": 101, "jobs": jobs[:100]}
        data[path.replace("&page=1", "&page=2")] = {"total_count": 101, "jobs": jobs[100:]}
        self.assertEqual(1010, self._verify(data))
        jobs[-1]["conclusion"] = "failure"
        self._reject("ci_jobs_not_successful", data)

    def test_new_run_or_rerun_during_validation_invalidates_evidence(self) -> None:
        for change in ("new_run", "new_attempt", "failed", "detail_attempt"):
            with self.subTest(change=change):
                data = _responses()

                def fetch(path: str, _token: str, data=data, change=change) -> dict[str, Any]:
                    if "/jobs?" in path:
                        if change == "new_run":
                            data[f"{RUNS_PATH}&per_page=100&page=1"] = {
                                "total_count": 2,
                                "workflow_runs": [_run(), _run(11)],
                            }
                        elif change == "detail_attempt":
                            data[f"{PREFIX}/runs/1010"]["run_attempt"] = 2
                        else:
                            run = data[f"{RUNS_PATH}&per_page=100&page=1"]["workflow_runs"][0]
                            run["run_attempt" if change == "new_attempt" else "conclusion"] = (
                                2 if change == "new_attempt" else "failure"
                            )
                    return data[path]

                with self.assertRaises(ReleaseCIError) as raised:
                    verify_release_ci(_environment(), fetch_json=fetch)
                self.assertEqual("ci_changed", raised.exception.code)

    def test_malformed_metadata_and_boolean_ids_fail_closed(self) -> None:
        for field, value in (
            ("id", True),
            ("run_attempt", 0),
            ("status", []),
            ("workflow_id", True),
        ):
            with self.subTest(field=field):
                self._reject("api_response_invalid", _responses([_run(**{field: value})]))
        for payload in ([], {"total_count": True, "workflow_runs": []}, {"total_count": -1}):
            with self.subTest(payload=payload):
                data = _responses()
                data[f"{RUNS_PATH}&per_page=100&page=1"] = payload
                self._reject("api_response_invalid", data)

    def test_json_decoder_and_main_never_echo_untrusted_data(self) -> None:
        for body in (
            b'{"secret":"raw-body-sentinel",',
            b'{"a":NaN}',
            b'{"a":1,"a":2}',
            b"[]",
            b"\xff",
        ):
            with self.subTest(body=body), self.assertRaises(ReleaseCIError) as raised:
                decode_json(body)
            self.assertEqual("api_response_invalid", str(raised.exception))
        for success in (False, True):
            data = _responses() if success else _responses([_run(conclusion=TOKEN)])
            stdout, stderr = io.StringIO(), io.StringIO()
            self.assertEqual(
                0 if success else 1,
                main(
                    environ=_environment(),
                    fetch_json=lambda path, _token, data=data: data[path],
                    stdout=stdout,
                    stderr=stderr,
                ),
            )
            self.assertNotIn(TOKEN, stdout.getvalue() + stderr.getvalue())
            if not success:
                self.assertEqual(
                    "release CI verification failed: ci_not_successful\n", stderr.getvalue()
                )

    def test_transport_uses_fixed_origin_bounded_read_and_header_only_token(self) -> None:
        class Response(io.BytesIO):
            status = 200

            def read(self, size: int = -1) -> bytes:
                self.requested_size = size
                return super().read(size)

        response = Response(json.dumps({"id": 7}).encode())
        calls = []

        class Opener:
            def open(self, request: Any, *, timeout: int) -> Response:
                calls.append((request, timeout))
                return response

        self.assertEqual(
            {"id": 7}, fetch_github_json(f"{PREFIX}/workflows/ci.yml", TOKEN, opener=Opener())
        )
        request, timeout = calls[0]
        self.assertEqual(f"https://api.github.com{PREFIX}/workflows/ci.yml", request.full_url)
        self.assertEqual("GET", request.get_method())
        self.assertEqual(f"Bearer {TOKEN}", request.get_header("Authorization"))
        self.assertEqual(15, timeout)
        self.assertEqual(SCRIPT["MAX_RESPONSE_BYTES"] + 1, response.requested_size)
        self.assertNotIn(TOKEN, request.full_url)

    def test_transport_failures_size_and_redirects_are_safe(self) -> None:
        for error in (
            URLError(TOKEN),
            HTTPError("https://api.github.com", 302, TOKEN, {}, None),
            TimeoutError(TOKEN),
            IncompleteRead(TOKEN.encode()),
        ):
            with self.subTest(error=type(error).__name__):

                class FailingOpener:
                    def open(self, _request: Any, *, timeout: int, error=error) -> Any:
                        raise error

                with self.assertRaises(ReleaseCIError) as raised:
                    fetch_github_json(f"{PREFIX}/workflows/ci.yml", TOKEN, opener=FailingOpener())
                self.assertEqual("api_request_failed", str(raised.exception))
        for status, body, code in (
            (302, b"raw-body-sentinel", "api_request_failed"),
            (200, b"x" * (SCRIPT["MAX_RESPONSE_BYTES"] + 1), "api_response_too_large"),
        ):
            with self.subTest(status=status, code=code):
                response = io.BytesIO(body)
                response.status = status
                with (
                    patch.dict(
                        fetch_github_json.__globals__,
                        {
                            "build_opener": lambda handler, response=response: _fake_opener(
                                handler, response
                            )
                        },
                    ),
                    self.assertRaises(ReleaseCIError) as raised,
                ):
                    fetch_github_json(f"{PREFIX}/workflows/ci.yml", TOKEN)
                self.assertEqual(code, raised.exception.code)

    def test_workflow_gates_build_and_upload_with_build_only_actions_scope(self) -> None:
        workflow = Path(".github/workflows/release.yml").read_text()
        build, publish = workflow.split("\n  publish:", 1)
        self.assertEqual(2, build.count("run: python scripts/check_release_ci.py"))
        first = build.index("run: python scripts/check_release_ci.py")
        last = build.rindex("run: python scripts/check_release_ci.py")
        self.assertLess(first, build.index("run: make release-check"))
        self.assertLess(build.index("run: make release-check"), last)
        self.assertLess(last, build.index("name: Upload distribution artifacts"))
        self.assertIn("      actions: read", build.split("\n    steps:", 1)[0])
        self.assertNotIn("actions: read", publish)
        self.assertIn("needs: build", publish)
        self.assertEqual(2, build.count("timeout-minutes: 3"))
        self.assertEqual(frozenset(JOB_NAMES), SCRIPT["REQUIRED_JOBS"])


def _fake_opener(handler: Any, response: Any) -> Any:
    assert handler.redirect_request(None, None, 302, "", {}, "https://other.invalid") is None

    class Opener:
        def open(self, _request: Any, *, timeout: int) -> Any:
            return response

    return Opener()


if __name__ == "__main__":
    unittest.main()
