from __future__ import annotations

import unittest
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
        ):
            self.assertEqual(7, main(["audit", "list"]))
        audit.assert_called_once()


if __name__ == "__main__":
    unittest.main()
