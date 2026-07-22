from __future__ import annotations

import io
import runpy
import unittest
from pathlib import Path
from typing import Any
from urllib.error import URLError

SCRIPT = runpy.run_path(str(Path("scripts/check_verified_release_ref.py")))
ReleaseVerificationError = SCRIPT["ReleaseVerificationError"]
decode_json = SCRIPT["_decode_json"]
fetch_github_json = SCRIPT["_fetch_github_json"]
main = SCRIPT["main"]
verify_release_ref = SCRIPT["verify_release_ref"]

TAG_OBJECT_SHA = "a" * 40
COMMIT_SHA = "b" * 40
TOKEN = "github-token-secret-sentinel"


def _environment() -> dict[str, str]:
    return {
        "GITHUB_TOKEN": TOKEN,
        "GITHUB_REPOSITORY": "brainx/zeus",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF": "refs/tags/v0.4.0",
        "GITHUB_REF_NAME": "v0.4.0",
        "GITHUB_REF_TYPE": "tag",
        "GITHUB_SHA": COMMIT_SHA,
    }


def _responses() -> dict[str, dict[str, Any]]:
    verified = {
        "verified": True,
        "reason": "valid",
        "verified_at": "2026-07-22T01:23:45Z",
    }
    return {
        "/repos/brainx/zeus/git/ref/tags/v0.4.0": {
            "ref": "refs/tags/v0.4.0",
            "object": {"type": "tag", "sha": TAG_OBJECT_SHA},
        },
        f"/repos/brainx/zeus/git/tags/{TAG_OBJECT_SHA}": {
            "tag": "v0.4.0",
            "sha": TAG_OBJECT_SHA,
            "object": {"type": "commit", "sha": COMMIT_SHA},
            "verification": verified,
        },
        f"/repos/brainx/zeus/git/commits/{COMMIT_SHA}": {
            "sha": COMMIT_SHA,
            "verification": verified,
        },
    }


def _fetch_from(responses: dict[str, Any]) -> Any:
    def fetch(path: str, _token: str) -> Any:
        return responses[path]

    return fetch


class VerifiedReleaseRefTests(unittest.TestCase):
    def test_accepts_verified_annotated_tag_bound_to_verified_event_commit(self) -> None:
        responses = _responses()
        calls: list[tuple[str, str]] = []

        def fetch(path: str, token: str) -> dict[str, Any]:
            calls.append((path, token))
            return responses[path]

        self.assertEqual(
            ("v0.4.0", COMMIT_SHA),
            verify_release_ref(_environment(), fetch_json=fetch),
        )
        self.assertEqual(list(responses), [path for path, _token in calls])
        self.assertTrue(all(token == TOKEN for _path, token in calls))

    def test_rejects_missing_or_malformed_workflow_environment_before_network(self) -> None:
        cases = {
            "missing token": ("GITHUB_TOKEN", ""),
            "non-ascii token": ("GITHUB_TOKEN", "token-\N{SNOWMAN}"),
            "wrong event": ("GITHUB_EVENT_NAME", "workflow_dispatch"),
            "wrong ref type": ("GITHUB_REF_TYPE", "branch"),
            "mismatched ref": ("GITHUB_REF", "refs/tags/v9.9.9"),
            "unsafe repository": ("GITHUB_REPOSITORY", "brainx/zeus/extra"),
            "unsafe tag": ("GITHUB_REF_NAME", "release/candidate"),
            "malformed sha": ("GITHUB_SHA", "not-a-sha"),
        }
        for label, (name, value) in cases.items():
            with self.subTest(case=label):
                environ = _environment()
                environ[name] = value

                def unexpected_fetch(_path: str, _token: str) -> dict[str, Any]:
                    raise AssertionError("network fetch must not run")

                with self.assertRaises(ReleaseVerificationError):
                    verify_release_ref(environ, fetch_json=unexpected_fetch)

    def test_rejects_lightweight_or_mismatched_tag_ref(self) -> None:
        for label, replacement in {
            "lightweight": {"type": "commit", "sha": COMMIT_SHA},
            "malformed tag object": {"type": "tag", "sha": "not-a-sha"},
        }.items():
            with self.subTest(case=label):
                responses = _responses()
                responses["/repos/brainx/zeus/git/ref/tags/v0.4.0"]["object"] = replacement
                with self.assertRaises(ReleaseVerificationError):
                    verify_release_ref(
                        _environment(),
                        fetch_json=_fetch_from(responses),
                    )

    def test_rejects_unverified_tag_or_commit(self) -> None:
        for endpoint in (
            f"/repos/brainx/zeus/git/tags/{TAG_OBJECT_SHA}",
            f"/repos/brainx/zeus/git/commits/{COMMIT_SHA}",
        ):
            with self.subTest(endpoint=endpoint):
                responses = _responses()
                responses[endpoint]["verification"] = {
                    "verified": False,
                    "reason": "unsigned",
                    "verified_at": None,
                }
                with self.assertRaises(ReleaseVerificationError):
                    verify_release_ref(
                        _environment(),
                        fetch_json=_fetch_from(responses),
                    )

    def test_rejects_tag_that_does_not_reference_event_commit(self) -> None:
        responses = _responses()
        responses[f"/repos/brainx/zeus/git/tags/{TAG_OBJECT_SHA}"]["object"] = {
            "type": "commit",
            "sha": "d" * 40,
        }

        with self.assertRaises(ReleaseVerificationError):
            verify_release_ref(
                _environment(),
                fetch_json=_fetch_from(responses),
            )

    def test_rejects_malformed_api_shapes(self) -> None:
        endpoints_and_payloads: tuple[tuple[str, Any], ...] = (
            ("/repos/brainx/zeus/git/ref/tags/v0.4.0", []),
            ("/repos/brainx/zeus/git/ref/tags/v0.4.0", {"ref": "refs/tags/v0.4.0"}),
            (
                f"/repos/brainx/zeus/git/tags/{TAG_OBJECT_SHA}",
                {"tag": "v0.4.0", "sha": TAG_OBJECT_SHA},
            ),
            (
                f"/repos/brainx/zeus/git/commits/{COMMIT_SHA}",
                {"sha": COMMIT_SHA, "verification": {"verified": "true"}},
            ),
        )
        for endpoint, payload in endpoints_and_payloads:
            with self.subTest(endpoint=endpoint, payload=payload):
                responses = _responses()
                responses[endpoint] = payload
                with self.assertRaises(ReleaseVerificationError):
                    verify_release_ref(
                        _environment(),
                        fetch_json=_fetch_from(responses),
                    )

    def test_json_decoder_rejects_duplicates_constants_and_raw_body_disclosure(self) -> None:
        secret_body = b'{"token":"raw-response-secret-sentinel",'
        for body in (
            secret_body,
            b'{"verification":NaN}',
            b'{"sha":"one","sha":"two"}',
            b"[]",
        ):
            with self.subTest(body=body):
                with self.assertRaises(ReleaseVerificationError) as raised:
                    decode_json(body)
                self.assertNotIn("raw-response-secret-sentinel", str(raised.exception))
                self.assertNotIn(body.decode("utf-8", errors="ignore"), str(raised.exception))

    def test_network_failure_is_redacted_and_token_is_header_only(self) -> None:
        class FailingOpener:
            request: Any = None
            assert_timeout: int | None = None

            def open(self, request: Any, *, timeout: int) -> Any:
                self.request = request
                self.assert_timeout = timeout
                raise URLError(f"network failure containing {TOKEN}")

        opener = FailingOpener()
        with self.assertRaises(ReleaseVerificationError) as raised:
            fetch_github_json("/repos/brainx/zeus/git/ref/tags/v0.4.0", TOKEN, opener=opener)

        self.assertNotIn(TOKEN, str(raised.exception))
        self.assertNotIn(TOKEN, opener.request.full_url)
        self.assertEqual(f"Bearer {TOKEN}", opener.request.get_header("Authorization"))
        self.assertEqual(15, opener.assert_timeout)

    def test_main_emits_only_fixed_success_or_redacted_failure_messages(self) -> None:
        responses = _responses()
        stdout = io.StringIO()
        stderr = io.StringIO()
        status = main(
            environ=_environment(),
            fetch_json=lambda path, _token: responses[path],
            stdout=stdout,
            stderr=stderr,
        )
        self.assertEqual(0, status)
        self.assertEqual("", stderr.getvalue())
        self.assertIn("v0.4.0", stdout.getvalue())
        self.assertNotIn(TOKEN, stdout.getvalue())

        stdout = io.StringIO()
        stderr = io.StringIO()

        def fail_fetch(_path: str, _token: str) -> dict[str, Any]:
            raise ReleaseVerificationError("GitHub API request failed")

        status = main(
            environ=_environment(),
            fetch_json=fail_fetch,
            stdout=stdout,
            stderr=stderr,
        )
        self.assertEqual(1, status)
        self.assertEqual("", stdout.getvalue())
        self.assertEqual(
            "release ref verification failed: GitHub API request failed\n",
            stderr.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
