from __future__ import annotations

import configparser
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import Mock, patch

from tests.fixtures.service_recovery_drill import (
    Drill,
    command_failure_details,
    render_unit,
    require_plain_tree,
    validate_root,
)
from tests.test_repo_contracts import _job_run_commands, _workflow_job_bodies
from zeus.cli import build_parser

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify_service_recovery.sh"


class ServiceRecoveryContractTests(unittest.TestCase):
    def test_script_refuses_non_disposable_environments_before_setup(self) -> None:
        base = {"PATH": "/usr/bin:/bin"}
        cases = (
            ({}, "explicit CI opt-in"),
            ({"ZEUS_SERVICE_RECOVERY_DRILL": "1"}, "GitHub Actions is required"),
            (
                {"ZEUS_SERVICE_RECOVERY_DRILL": "1", "GITHUB_ACTIONS": "true"},
                "disposable GitHub-hosted runner",
            ),
            (
                {
                    "ZEUS_SERVICE_RECOVERY_DRILL": "1",
                    "GITHUB_ACTIONS": "true",
                    "RUNNER_ENVIRONMENT": "github-hosted",
                    "RUNNER_OS": "macOS",
                },
                "Linux is required",
            ),
        )
        for environment, message in cases:
            with self.subTest(message=message):
                result = subprocess.run(
                    ["/bin/sh", str(SCRIPT)],
                    env=base | environment,
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn(message, result.stderr)

    def test_script_requires_root_before_any_setup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tools = Path(temporary)
            for name, answer in (("uname", "Linux"), ("id", "1000")):
                command = tools / name
                command.write_text(f"#!/bin/sh\nprintf '%s\\n' '{answer}'\n")
                command.chmod(0o700)
            result = subprocess.run(
                ["/bin/sh", str(SCRIPT)],
                env={
                    "PATH": str(tools),
                    "ZEUS_SERVICE_RECOVERY_DRILL": "1",
                    "GITHUB_ACTIONS": "true",
                    "RUNNER_ENVIRONMENT": "github-hosted",
                    "RUNNER_OS": "Linux",
                },
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn("run through sudo", result.stderr)

    def test_driver_rejects_non_disposable_roots_without_touching_them(self) -> None:
        for root in (Path("/var/lib/zeus"), Path("/run/zeus"), Path("/run/zeus-service-recovery")):
            with self.subTest(root=root), patch.object(Path, "lstat") as metadata:
                with self.assertRaises(RuntimeError):
                    validate_root(root, 1000)
                metadata.assert_not_called()

    def test_bundled_units_keep_lifecycle_and_hardening_in_the_drill(self) -> None:
        root = Path("/run/zeus-service-recovery.aB123456")
        for name in ("zeus-api.service", "zeus-reconcile.service", "zeus-reconcile.timer"):
            with self.subTest(unit=name):
                source = (ROOT / "systemd" / name).read_text()
                rendered = render_unit(source, root, "runner", "runner", 49153)
                unit = configparser.ConfigParser(interpolation=None, strict=False)
                unit.read_string(rendered)
                self.assertNotIn("/var/lib/zeus", rendered)
                self.assertNotIn("/opt/zeus", rendered)
                if name.endswith(".timer"):
                    self.assertEqual(unit["Timer"]["Unit"], f"{root.name}-reconcile.service")
                    self.assertEqual(unit["Timer"]["OnUnitActiveSec"], "1s")
                    continue
                service = unit["Service"]
                self.assertEqual(service["User"], "runner")
                self.assertEqual(service["WorkingDirectory"], f"{root}/work")
                self.assertEqual(service["ReadWritePaths"], f"{root}/state")
                self.assertEqual(service["ProtectSystem"], "strict")
                self.assertEqual(service["ProtectHome"], "true")
                self.assertEqual(service["NoNewPrivileges"], "true")
                self.assertIn(f"{root}/venv/bin/", service["ExecStart"])
                self.assertIn("ZEUS_SQLITE_SYNCHRONOUS=FULL", rendered)
                if name == "zeus-reconcile.service":
                    self.assertEqual(service["Type"], "oneshot")
                    self.assertEqual(service["KillMode"], "process")
                    self.assertTrue(service["ExecStart"].endswith("zeus bot reconcile"))
                else:
                    self.assertEqual(service.get("KillMode", "control-group"), "control-group")
                    self.assertEqual(service["Restart"], "on-failure")
                    self.assertIn("ZEUS_PORT=49153", rendered)

    def test_drill_is_a_required_package_gate_before_artifact_publication(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        package = _workflow_job_bodies(workflow)["package"]
        commands = _job_run_commands(package)
        drill = next(command for command in commands if "verify_service_recovery.sh" in command)
        position = commands.index(drill)
        self.assertIn("wheel_smoke.sh", commands[position - 2])
        self.assertEqual(commands[position - 1], "twine check dist/*")
        self.assertEqual(commands[position + 1], "sh scripts/generate_checksums.sh dist")
        self.assertTrue(drill.startswith("sudo --preserve-env="))
        self.assertIn('ZEUS_SERVICE_RECOVERY_DRILL: "1"', package)
        self.assertNotIn("continue-on-error", package)
        self.assertNotIn("if: always()", package)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertNotIn("permissions:", package)
        self.assertLess(
            package.index("verify_service_recovery.sh"), package.index("upload-artifact@")
        )

    def test_cleanup_rechecks_generation_before_signaling(self) -> None:
        for fingerprint, expected in (("original", [(42, signal.SIGTERM)]), ("reused", [])):
            with self.subTest(fingerprint=fingerprint):
                drill = object.__new__(Drill)
                drill.processes = Mock(side_effect=[{42: "original"}, {}, {}, {}, {}])
                drill.process_identity = Mock(return_value=fingerprint)
                with patch("tests.fixtures.service_recovery_drill.os.kill") as kill:
                    drill.terminate_owned_gateways()
                self.assertEqual([call.args for call in kill.call_args_list], expected)

    def test_cleanup_escalates_only_the_still_owned_fixture_generation(self) -> None:
        drill = object.__new__(Drill)
        drill.processes = Mock(side_effect=[{42: "original"}] * 3 + [{}, {}])
        drill.process_identity = Mock(return_value="original")
        with (
            patch("tests.fixtures.service_recovery_drill.os.kill") as kill,
            patch("tests.fixtures.service_recovery_drill.time.monotonic", side_effect=[0, 4, 5]),
        ):
            drill.terminate_owned_gateways()
        self.assertEqual(
            [call.args for call in kill.call_args_list],
            [(42, signal.SIGTERM), (42, signal.SIGKILL)],
        )

    def test_snapshot_refuses_links_before_copying_outside_data(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "outside").write_text("must not be copied")
            state = root / "state"
            state.mkdir()
            (state / "linked").symlink_to(root / "outside")
            with self.assertRaisesRegex(RuntimeError, "link or special file"):
                require_plain_tree(state)

    def test_database_observation_uses_the_service_identity(self) -> None:
        drill = object.__new__(Drill)
        drill.root = Path("/run/zeus-service-recovery.aB123456")
        drill.database = drill.root / "state/zeus.db"
        drill.user = "runner"
        drill.command = Mock(return_value=subprocess.CompletedProcess([], 0, '[{"count":1}]'))
        self.assertEqual(drill.rows("SELECT count(*) AS count FROM bots"), [{"count": 1}])
        arguments = drill.command.call_args.args
        self.assertEqual(arguments[:4], ("runuser", "--user", "runner", "--"))
        self.assertEqual(arguments[4:7], (str(drill.root / "venv/bin/python"), "-I", "-c"))
        self.assertIn(str(drill.database), arguments)
        self.assertNotIn("immutable=1", arguments[7])

    def test_command_diagnostics_are_bounded_and_redact_the_fixture_key(self) -> None:
        error = subprocess.CalledProcessError(
            1, ["runuser"], output="x" * 5000 + "fixture-key", stderr="\x1bproblem fixture-key"
        )
        details = command_failure_details(error, "fixture-key")
        self.assertNotIn("fixture-key", details)
        self.assertNotIn("\x1b", details)
        self.assertIn("[redacted]", details)
        self.assertIn("stderr: problem", details)
        self.assertLessEqual(len(details), 2 * 2048 + len("stdout: \nstderr: "))

    def test_backup_restore_round_trip_is_quiesced_and_preserves_ledger_and_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            profile = state / "hermes/profiles/recovery-bot"
            (profile / "cron").mkdir(parents=True)
            names = ("config.yaml", ".env", "SOUL.md", "mcp.json", "cron/jobs.json")
            for name in names:
                (profile / name).write_text(f"fixture {name}\n")
            database = state / "zeus.db"
            with closing(sqlite3.connect(database)) as connection, connection:
                connection.execute("CREATE TABLE bots (bot_id, profile_path, desired_state)")
                connection.execute(
                    "INSERT INTO bots VALUES ('recovery-bot', ?, 'running')", (str(profile),)
                )
                connection.execute("CREATE TABLE lifecycle_events (event_id, action)")
                connection.execute("INSERT INTO lifecycle_events VALUES (1, 'start')")

            def stop(*args: str) -> dict[str, object]:
                parsed = build_parser().parse_args(args)
                self.assertEqual((parsed.resource, parsed.action), ("bot", "stop"))
                self.assertEqual(parsed.bot_id, "recovery-bot")
                self.assertFalse((root / "backup").exists())
                with closing(sqlite3.connect(database)) as connection, connection:
                    connection.execute("UPDATE bots SET desired_state = 'stopped'")
                    connection.execute("INSERT INTO lifecycle_events VALUES (2, 'stop')")
                return {}

            drill = object.__new__(Drill)
            drill.root, drill.state, drill.database = root, state, database
            drill.uid, drill.gid = os.getuid(), os.getgid()
            drill.cli, drill.processes = Mock(side_effect=stop), Mock(return_value={})
            drill.database_command = lambda script, *args: subprocess.run(
                [sys.executable, "-I", "-c", script, str(database), *args],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
            with patch("tests.fixtures.service_recovery_drill.os.chown") as chown:
                drill.backup_restore()
            self.assertEqual(drill.bot()["desired_state"], "stopped")
            self.assertEqual(
                [
                    tuple(row.values())
                    for row in drill.rows("SELECT * FROM lifecycle_events ORDER BY event_id")
                ],
                [(1, "start"), (2, "stop")],
            )
            for name in names:
                self.assertEqual((profile / name).read_text(), f"fixture {name}\n")
            self.assertTrue((root / "retired-state/zeus.db").is_file())
            self.assertFalse((root / "backup/state/zeus.db").exists())
            chown.assert_any_call(state, drill.uid, drill.gid)


if __name__ == "__main__":
    unittest.main()
