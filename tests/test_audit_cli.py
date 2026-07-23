from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime
from io import StringIO
from unittest import mock

from zeus.cli import build_parser, main


class AuditCliContractTests(unittest.TestCase):
    def test_audit_commands_parse_without_normal_service_settings(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["audit", "show", "a" * 32, "--json"])
        self.assertEqual("audit", args.resource)
        self.assertEqual("show", args.action)
        self.assertTrue(args.as_json)

    def test_audit_dispatch_happens_before_normal_settings(self) -> None:
        with (
            mock.patch("zeus.cli._run_audit", return_value=7) as audit,
            mock.patch("zeus.cli.Settings.from_env", side_effect=AssertionError("normal settings")),
            mock.patch("zeus.cli._services", side_effect=AssertionError("normal services")),
        ):
            self.assertEqual(7, main(["audit", "list"]))
        audit.assert_called_once()

    def _report(self, status):
        from zeus.audit_models import (
            AuditCompleteness,
            AuditMetadata,
            AuditReport,
            SeverityCounts,
        )

        return AuditReport(
            1,
            "1" * 32,
            "2" * 64,
            status,
            AuditMetadata(
                "1",
                "0.19.0",
                "1",
                None,
                "a" * 40,
                datetime.now(UTC).isoformat(),
                datetime.now(UTC).isoformat(),
                None,
                None,
                None,
                True,
            ),
            "ok",
            (),
            (),
            (),
            SeverityCounts(),
            AuditCompleteness(
                status.value == "completed",
                reasons=() if status.value == "completed" else (status.value,),
            ),
        )

    def test_audit_doctor_human_json_and_exit_matrix(self) -> None:
        from zeus.audit_doctor import AuditDoctorCheck, AuditDoctorReport

        for as_json in (False, True):
            for ok in (False, True):
                with self.subTest(as_json=as_json, ok=ok):
                    service = mock.Mock()
                    service.doctor.return_value = AuditDoctorReport(
                        (AuditDoctorCheck("repository", ok, "checked"),)
                    )
                    with (
                        mock.patch("zeus.audit.AuditService.from_cwd", return_value=service),
                        mock.patch("sys.stdout", new_callable=StringIO) as stdout,
                    ):
                        exit_code = main(["audit", "doctor", *(["--json"] if as_json else [])])
                    self.assertEqual(0 if ok else 1, exit_code)
                    if as_json:
                        self.assertEqual(ok, json.loads(stdout.getvalue())["ok"])
                    else:
                        self.assertEqual(
                            f"{'ok' if ok else 'blocked'}\trepository\tchecked\n",
                            stdout.getvalue(),
                        )

    def test_audit_run_human_json_and_status_exit_matrix(self) -> None:
        from zeus.audit_models import AuditStatus

        for status in AuditStatus:
            for as_json in (False, True):
                with self.subTest(status=status, as_json=as_json):
                    report = self._report(status)
                    service = mock.Mock()
                    service.run.return_value = report
                    with (
                        mock.patch("zeus.audit.AuditService.from_cwd", return_value=service),
                        mock.patch("sys.stdout", new_callable=StringIO) as stdout,
                    ):
                        exit_code = main(["audit", "run", *(["--json"] if as_json else [])])
                    self.assertEqual(0 if status is AuditStatus.completed else 1, exit_code)
                    if as_json:
                        self.assertEqual(status.value, json.loads(stdout.getvalue())["status"])
                    else:
                        output = stdout.getvalue()
                        self.assertIn(f"status: {status.value}\n", output)
                        self.assertIn(f"run_id: {report.run_id}\n", output)
                        self.assertIn("target_commit: " + "a" * 40, output)
                        self.assertIn("severity_counts:", output)
                        self.assertIn(f"markdown: audits/{report.run_id}/report.md\n", output)

    def test_audit_list_and_show_human_json_matrix(self) -> None:
        from zeus.audit_models import AuditStatus

        completed = self._report(AuditStatus.completed)
        partial = self._report(AuditStatus.partial)
        partial = partial.__class__(
            partial.schema_version,
            "3" * 32,
            partial.repository_id,
            partial.status,
            partial.metadata,
            partial.summary,
            partial.checks,
            partial.skipped_content,
            partial.findings,
            partial.severity_counts,
            partial.completeness,
        )
        service = mock.Mock()
        service.list_reports.return_value = (partial, completed)
        service.show.return_value = completed
        service.show_markdown.return_value = "# Audit\n"
        for action in ("list", "show"):
            for as_json in (False, True):
                with self.subTest(action=action, as_json=as_json):
                    argv = ["audit", action]
                    if action == "show":
                        argv.append(completed.run_id)
                    if as_json:
                        argv.append("--json")
                    with (
                        mock.patch("zeus.audit.AuditService.from_cwd", return_value=service),
                        mock.patch("sys.stdout", new_callable=StringIO) as stdout,
                    ):
                        self.assertEqual(0, main(argv))
                    output = stdout.getvalue()
                    if as_json:
                        value = json.loads(output)
                        if action == "list":
                            self.assertEqual(
                                [partial.run_id, completed.run_id],
                                [item["run_id"] for item in value],
                            )
                        else:
                            self.assertEqual(completed.run_id, value["run_id"])
                    elif action == "list":
                        self.assertEqual(
                            f"{partial.run_id}\tpartial\t{'a' * 40}\n"
                            f"{completed.run_id}\tcompleted\t{'a' * 40}\n",
                            output,
                        )
                    else:
                        self.assertEqual("# Audit\n", output)

    def test_audit_errors_use_human_or_json_output_and_exit_one(self) -> None:
        service = mock.Mock()
        service.list_reports.side_effect = OSError("audit unavailable")
        for as_json in (False, True):
            with self.subTest(as_json=as_json):
                with (
                    mock.patch("zeus.audit.AuditService.from_cwd", return_value=service),
                    mock.patch("sys.stdout", new_callable=StringIO) as stdout,
                    mock.patch("sys.stderr", new_callable=StringIO) as stderr,
                ):
                    self.assertEqual(
                        1,
                        main(["audit", "list", *(["--json"] if as_json else [])]),
                    )
                if as_json:
                    self.assertEqual(
                        "audit_error",
                        json.loads(stdout.getvalue())["error"]["code"],
                    )
                    self.assertEqual("", stderr.getvalue())
                else:
                    self.assertEqual("", stdout.getvalue())
                    self.assertEqual("audit unavailable\n", stderr.getvalue())

    def test_audit_run_human_output_uses_relative_artifact_path(self) -> None:
        from datetime import UTC, datetime
        from io import StringIO

        from zeus.audit_models import (
            AuditCompleteness,
            AuditMetadata,
            AuditReport,
            AuditStatus,
            SeverityCounts,
        )

        report = AuditReport(
            1,
            "1" * 32,
            "2" * 64,
            AuditStatus.completed,
            AuditMetadata(
                "1",
                "0.19.0",
                "1",
                None,
                "a" * 40,
                datetime.now(UTC).isoformat(),
                datetime.now(UTC).isoformat(),
                None,
                None,
                None,
                True,
            ),
            "ok",
            (),
            (),
            (),
            SeverityCounts(),
            AuditCompleteness(True),
        )
        service = mock.Mock()
        service.run.return_value = report
        with (
            mock.patch("zeus.audit.AuditService.from_cwd", return_value=service),
            mock.patch("sys.stdout", new_callable=StringIO) as stdout,
        ):
            self.assertEqual(0, main(["audit", "run"]))
        self.assertIn(f"markdown: audits/{report.run_id}/report.md", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
