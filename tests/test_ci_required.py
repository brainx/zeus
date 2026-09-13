from __future__ import annotations

import io
import json
import runpy
import unittest

SCRIPT = runpy.run_path("scripts/check_ci_required.py")
CIRequiredError = SCRIPT["CIRequiredError"]
ENVIRONMENT_VARIABLE = SCRIPT["ENVIRONMENT_VARIABLE"]
REQUIRED_DEPENDENCIES = SCRIPT["REQUIRED_DEPENDENCIES"]
evaluate_needs = SCRIPT["evaluate_needs"]
main = SCRIPT["main"]


def _needs() -> dict[str, object]:
    return {
        dependency: {"result": "success", "outputs": {}} for dependency in REQUIRED_DEPENDENCIES
    }


class CIRequiredTests(unittest.TestCase):
    def test_accepts_exact_successful_dependency_set(self) -> None:
        evaluate_needs(json.dumps(_needs()))

    def test_every_missing_or_unsuccessful_dependency_fails(self) -> None:
        for dependency in REQUIRED_DEPENDENCIES:
            with self.subTest(dependency=dependency, state="missing"):
                needs = _needs()
                del needs[dependency]
                with self.assertRaisesRegex(CIRequiredError, "invalid_needs"):
                    evaluate_needs(json.dumps(needs))
            for result in ("failure", "cancelled", "skipped", "neutral", None):
                with self.subTest(dependency=dependency, result=result):
                    needs = _needs()
                    needs[dependency] = {"result": result}
                    with self.assertRaisesRegex(CIRequiredError, "required_job_not_successful"):
                        evaluate_needs(json.dumps(needs))

    def test_malformed_ambiguous_and_extra_data_fails_closed(self) -> None:
        malformed = (
            "",
            "[]",
            "null",
            "{",
            '{"test":{"result":"success"},"test":{"result":"success"}}',
            '{"test":{"result":NaN}}',
            "x" * (SCRIPT["MAX_INPUT_CHARACTERS"] + 1),
        )
        for raw in malformed:
            with (
                self.subTest(raw=raw[:40]),
                self.assertRaisesRegex(CIRequiredError, "invalid_needs"),
            ):
                evaluate_needs(raw)
        needs = _needs()
        needs["unexpected"] = {"result": "success"}
        with self.assertRaisesRegex(CIRequiredError, "invalid_needs"):
            evaluate_needs(json.dumps(needs))

    def test_dependency_records_and_result_values_are_typed_strictly(self) -> None:
        dependency = next(iter(REQUIRED_DEPENDENCIES))
        for record in ("success", [], None, {"result": True}, {"result": 1}, {}):
            with self.subTest(record=record):
                needs = _needs()
                needs[dependency] = record
                with self.assertRaisesRegex(CIRequiredError, "required_job_not_successful"):
                    evaluate_needs(json.dumps(needs))

    def test_main_prefers_environment_and_falls_back_to_bounded_stdin(self) -> None:
        successful = json.dumps(_needs())
        for environ, stdin in (
            ({ENVIRONMENT_VARIABLE: successful}, io.StringIO("invalid")),
            ({}, io.StringIO(successful)),
        ):
            with self.subTest(environ=environ):
                stdout, stderr = io.StringIO(), io.StringIO()
                self.assertEqual(
                    0,
                    main(environ=environ, stdin=stdin, stdout=stdout, stderr=stderr),
                )
                self.assertEqual("", stderr.getvalue())
                self.assertIn("Verified all required CI", stdout.getvalue())

    def test_main_reports_only_fixed_failure_codes(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        self.assertEqual(
            1,
            main(
                environ={ENVIRONMENT_VARIABLE: "untrusted-sentinel"},
                stdout=stdout,
                stderr=stderr,
            ),
        )
        self.assertEqual("", stdout.getvalue())
        self.assertEqual(
            "required CI verification failed: invalid_needs\n",
            stderr.getvalue(),
        )
