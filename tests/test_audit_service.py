from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from subprocess import DEVNULL, run
from types import SimpleNamespace
from unittest import mock


class AuditServiceContractTests(unittest.TestCase):
    def _repository(self, root: Path, *, ignored_state: bool = True) -> None:
        run(("git", "init", "-q", str(root)), check=True, stdin=DEVNULL)
        run(
            ("git", "-C", str(root), "config", "user.email", "test@example.invalid"),
            check=True,
            stdin=DEVNULL,
        )
        run(("git", "-C", str(root), "config", "user.name", "Test"), check=True, stdin=DEVNULL)
        if ignored_state:
            (root / ".gitignore").write_text(".zeus/\n", encoding="utf-8")
        (root / "README").write_text("test\n", encoding="utf-8")
        names = ["README"] + ([".gitignore"] if ignored_state else [])
        run(("git", "-C", str(root), "add", *names), check=True, stdin=DEVNULL)
        run(("git", "-C", str(root), "commit", "-qm", "initial"), check=True, stdin=DEVNULL)

    def test_public_service_interface_is_available(self) -> None:
        from zeus.audit import AuditService

        self.assertTrue(callable(AuditService.from_cwd))
        for name in ("doctor", "run", "list_reports", "show", "show_markdown"):
            self.assertTrue(callable(getattr(AuditService, name)))

    def test_default_state_dir_is_repository_local_after_discovery(self) -> None:
        from zeus.audit import AuditService

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            service = AuditService.from_cwd(cwd=root, env={})
            self.assertEqual(root / ".zeus", service.settings.state_dir)

    def test_explicit_state_dir_is_honored(self) -> None:
        from zeus.audit import AuditService

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            explicit = root.parent / "external-state"
            self.assertEqual(
                explicit,
                AuditService.from_cwd(
                    cwd=root, env={"ZEUS_STATE_DIR": str(explicit)}
                ).settings.state_dir,
            )

    def test_empty_state_dir_uses_repository_default(self) -> None:
        from zeus.audit import AuditService

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            self.assertEqual(
                root / ".zeus",
                AuditService.from_cwd(cwd=root, env={"ZEUS_STATE_DIR": ""}).settings.state_dir,
            )

    def test_run_rejects_untracked_but_not_ignored_in_repository_state(self) -> None:
        from zeus.audit import AuditService, AuditServiceError

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root, ignored_state=False)
            with self.assertRaisesRegex(AuditServiceError, "ignored and untracked"):
                AuditService.from_cwd(cwd=root, env={}).run()

    def test_doctor_reports_repository_state_policy_without_creating_a_run(self) -> None:
        from zeus.audit import AuditService
        from zeus.audit_doctor import AuditDoctorReport

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root, ignored_state=False)
            service = AuditService.from_cwd(cwd=root, env={})
            with mock.patch("zeus.audit.run_audit_doctor", return_value=AuditDoctorReport(())):
                report = service.doctor()
            checks = {check.name: check for check in report.checks}
            self.assertFalse(checks["state_repository"].ok)
            self.assertIn("ignored and untracked", checks["state_repository"].observation)
            self.assertFalse((root / ".zeus" / "audits").exists())

    def test_service_rejects_immediate_repository_lock_contention(self) -> None:
        from zeus.audit import AuditService, AuditServiceError
        from zeus.private_io import ensure_private_directory
        from zeus.process_lock import BotProcessLock

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            service = AuditService.from_cwd(cwd=root, env={"ZEUS_HERMES_BIN": "missing"})
            ensure_private_directory(service.settings.state_dir)
            path = (
                service.settings.state_dir
                / "locks"
                / "audits"
                / f"{service.location.repository_id}.lock"
            )
            with (
                BotProcessLock(path, timeout_seconds=0),
                self.assertRaisesRegex(AuditServiceError, "already running"),
            ):
                service.run()

    def test_state_policy_git_timeouts_are_resampled_for_each_command(self) -> None:
        from zeus.audit import AuditService

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            service = AuditService.from_cwd(cwd=root, env={})
            timeouts: list[float] = []

            def command(*_args, **kwargs):
                timeouts.append(kwargs["timeout"])
                return SimpleNamespace(returncode=1 if len(timeouts) == 1 else 0)

            with (
                mock.patch("zeus.audit.time.monotonic", side_effect=(100.0, 101.5)),
                mock.patch("zeus.audit.subprocess.run", side_effect=command),
            ):
                service._validate_state_path(deadline=105.0)
            self.assertEqual([5.0, 3.5], timeouts)

    def test_run_revalidates_head_after_acquiring_repository_lock(self) -> None:
        from zeus.audit import AuditService, AuditServiceError
        from zeus.audit_workspace import AuditWorkspaceError

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            service = AuditService.from_cwd(cwd=root, env={})
            with (
                mock.patch.object(
                    service.workspace,
                    "revalidate",
                    side_effect=(None, AuditWorkspaceError("HEAD changed")),
                ),
                self.assertRaisesRegex(AuditServiceError, "changed while waiting"),
            ):
                service.run()
            self.assertFalse((root / ".zeus" / "audits").exists())

    def test_run_revalidates_state_policy_immediately_after_repository_lock(self) -> None:
        from zeus.audit import AuditService, AuditServiceError

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            service = AuditService.from_cwd(cwd=root, env={})
            with (
                mock.patch.object(
                    service,
                    "_validate_state_path",
                    side_effect=(None, AuditServiceError("state policy changed")),
                ) as state_policy,
                self.assertRaisesRegex(AuditServiceError, "state policy changed"),
            ):
                service.run()
            self.assertEqual(2, state_policy.call_count)
            self.assertFalse((root / ".zeus" / "audits").exists())

    def test_blocked_preflight_rechecks_state_before_report_installation(self) -> None:
        from zeus.audit import AuditService, AuditServiceError

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            service = AuditService.from_cwd(
                cwd=root,
                env={"ZEUS_HERMES_BIN": "missing-hermes-for-test"},
            )
            with (
                mock.patch.object(
                    service,
                    "_validate_state_path",
                    side_effect=(
                        None,
                        None,
                        AuditServiceError("state policy changed"),
                    ),
                ) as state_policy,
                self.assertRaisesRegex(AuditServiceError, "state policy changed"),
            ):
                service.run()
            self.assertEqual(3, state_policy.call_count)
            self.assertFalse((root / ".zeus" / "audits").exists())

    def test_run_blocks_after_lock_and_persists_a_report_when_preflight_fails(self) -> None:
        from zeus.audit import AuditService
        from zeus.audit_models import AuditStatus

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            run(("git", "init", "-q", str(root)), check=True, stdin=DEVNULL)
            run(
                ("git", "-C", str(root), "config", "user.email", "test@example.invalid"),
                check=True,
                stdin=DEVNULL,
            )
            run(("git", "-C", str(root), "config", "user.name", "Test"), check=True, stdin=DEVNULL)
            (root / ".gitignore").write_text(".zeus/\n", encoding="utf-8")
            (root / "README").write_text("test\n", encoding="utf-8")
            run(("git", "-C", str(root), "add", ".gitignore", "README"), check=True, stdin=DEVNULL)
            run(("git", "-C", str(root), "commit", "-qm", "initial"), check=True, stdin=DEVNULL)

            report = AuditService.from_cwd(
                cwd=root,
                env={"ZEUS_HERMES_BIN": "missing-hermes-for-test"},
            ).run()

            self.assertEqual(AuditStatus.blocked, report.status)
            self.assertTrue((root / ".zeus" / "audits" / report.run_id / "report.json").is_file())
            self.assertFalse((root / ".zeus" / "zeus.db").exists())

    def test_run_rejects_tracked_in_repository_state_before_creating_a_report(self) -> None:
        from zeus.audit import AuditService, AuditServiceError

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            run(("git", "init", "-q", str(root)), check=True, stdin=DEVNULL)
            run(
                ("git", "-C", str(root), "config", "user.email", "test@example.invalid"),
                check=True,
                stdin=DEVNULL,
            )
            run(("git", "-C", str(root), "config", "user.name", "Test"), check=True, stdin=DEVNULL)
            config = root / ".zeus" / "audit" / "config.json"
            config.parent.mkdir(parents=True)
            config.write_text('{"schema_version":1}\n', encoding="utf-8")
            run(
                ("git", "-C", str(root), "add", ".zeus/audit/config.json"),
                check=True,
                stdin=DEVNULL,
            )
            run(("git", "-C", str(root), "commit", "-qm", "initial"), check=True, stdin=DEVNULL)

            with self.assertRaisesRegex(AuditServiceError, "tracked"):
                AuditService.from_cwd(cwd=root, env={}).run()

            self.assertFalse((root / ".zeus" / "audits").exists())

    def test_snapshot_line_counts_accept_committed_utf8_sources_only(self) -> None:
        from zeus import audit
        from zeus.audit_workspace import SnapshotManifestEntry

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "src").mkdir()
            (root / "src" / "ok.py").write_bytes(b"one\ntwo\n")
            (root / "nul.txt").write_bytes(b"text\x00data\n")
            (root / "control.txt").write_bytes(b"text\x01data\n")
            (root / "binary.dat").write_bytes(b"\xff")
            snapshot = mock.Mock(
                root=root,
                manifest=(
                    SnapshotManifestEntry(
                        "src/ok.py",
                        "a" * 40,
                        "100644",
                        0o644,
                        8,
                        hashlib.sha256(b"one\ntwo\n").hexdigest(),
                    ),
                    SnapshotManifestEntry(
                        "nul.txt",
                        "b" * 40,
                        "100644",
                        0o644,
                        10,
                        hashlib.sha256(b"text\x00data\n").hexdigest(),
                    ),
                    SnapshotManifestEntry(
                        "control.txt",
                        "c" * 40,
                        "100644",
                        0o644,
                        10,
                        hashlib.sha256(b"text\x01data\n").hexdigest(),
                    ),
                    SnapshotManifestEntry(
                        "binary.dat",
                        "d" * 40,
                        "100644",
                        0o644,
                        1,
                        hashlib.sha256(b"\xff").hexdigest(),
                    ),
                    SnapshotManifestEntry("link", "e" * 40, "120000", 0o777, 6, "f" * 64, "ok.py"),
                ),
            )
            read_sizes: list[int] = []
            real_read = audit.os.read

            def bounded_read(descriptor: int, size: int) -> bytes:
                read_sizes.append(size)
                return real_read(descriptor, size)

            with (
                mock.patch.object(Path, "read_bytes", side_effect=AssertionError("path read")),
                mock.patch("zeus.audit.os.read", side_effect=bounded_read),
            ):
                self.assertEqual({"src/ok.py": 2}, audit.snapshot_source_line_counts(snapshot))
            self.assertTrue(read_sizes)
            self.assertLessEqual(max(read_sizes), 64 * 1024)

    def test_snapshot_line_counts_fail_closed_on_manifest_size_or_hash_drift(self) -> None:
        from zeus.audit import AuditServiceError, snapshot_source_line_counts
        from zeus.audit_workspace import SnapshotManifestEntry

        data = b"one\ntwo\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "source.py").write_bytes(data)
            valid = SnapshotManifestEntry(
                "source.py",
                "a" * 40,
                "100644",
                0o644,
                len(data),
                hashlib.sha256(data).hexdigest(),
            )
            for entry in (
                SnapshotManifestEntry(
                    valid.path,
                    valid.object_id,
                    valid.git_mode,
                    valid.mode,
                    valid.size - 1,
                    valid.sha256,
                ),
                SnapshotManifestEntry(
                    valid.path,
                    valid.object_id,
                    valid.git_mode,
                    valid.mode,
                    valid.size,
                    "0" * 64,
                ),
            ):
                with (
                    self.subTest(size=entry.size, digest=entry.sha256),
                    self.assertRaisesRegex(AuditServiceError, "snapshot source"),
                ):
                    snapshot_source_line_counts(mock.Mock(root=root, manifest=(entry,)))

    def test_snapshot_line_counts_fail_closed_on_binding_replacement(self) -> None:
        from zeus import audit
        from zeus.audit import AuditServiceError
        from zeus.audit_workspace import SnapshotManifestEntry

        data = b"one\ntwo\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "source.py"
            source.write_bytes(data)
            entry = SnapshotManifestEntry(
                "source.py",
                "a" * 40,
                "100644",
                0o644,
                len(data),
                hashlib.sha256(data).hexdigest(),
            )
            real_read = audit.os.read
            replaced = False

            def replace_after_read(descriptor: int, size: int) -> bytes:
                nonlocal replaced
                chunk = real_read(descriptor, size)
                if chunk and not replaced:
                    replaced = True
                    source.replace(root / "old-source.py")
                    source.write_bytes(data)
                return chunk

            with (
                mock.patch("zeus.audit.os.read", side_effect=replace_after_read),
                self.assertRaisesRegex(AuditServiceError, "binding changed"),
            ):
                audit.snapshot_source_line_counts(mock.Mock(root=root, manifest=(entry,)))

    def test_snapshot_line_counts_honor_the_overall_deadline(self) -> None:
        from zeus.audit import AuditServiceError, snapshot_source_line_counts
        from zeus.audit_workspace import SnapshotManifestEntry

        data = b"line\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "source.py").write_bytes(data)
            entry = SnapshotManifestEntry(
                "source.py",
                "a" * 40,
                "100644",
                0o644,
                len(data),
                hashlib.sha256(data).hexdigest(),
            )
            with (
                mock.patch("zeus.audit.time.monotonic", return_value=11.0),
                self.assertRaisesRegex(AuditServiceError, "deadline"),
            ):
                snapshot_source_line_counts(
                    mock.Mock(root=root, manifest=(entry,)),
                    deadline=10.0,
                )

    def test_private_audit_profile_uses_the_invoked_profile_name(self) -> None:
        from zeus.audit import install_audit_profile
        from zeus.audit_config import parse_audit_config
        from zeus.audit_profile import MAX_AUDIT_PROFILE_CONFIG_BYTES, build_audit_profile

        profile = build_audit_profile(parse_audit_config({"schema_version": 1}))
        with tempfile.TemporaryDirectory() as temporary:
            hermes_home = Path(temporary).resolve() / "hermes"
            invoked_name = "audit-" + "1" * 32
            installed = install_audit_profile(hermes_home, invoked_name, profile)
            self.assertEqual(hermes_home / "profiles" / invoked_name, installed)
            self.assertEqual(0o700, installed.stat().st_mode & 0o777)
            self.assertEqual(0o600, (installed / "config.yaml").stat().st_mode & 0o777)
            config = (installed / "config.yaml").read_bytes()
            self.assertLessEqual(len(config), MAX_AUDIT_PROFILE_CONFIG_BYTES)
            text = config.decode("utf-8", errors="strict")
            self.assertIn("gateway:\n  enabled: false", text)
            self.assertIn("docker_volumes: []", text)
            self.assertIn("environment: {}", text)

    def test_source_evidence_is_validated_against_snapshot_line_counts(self) -> None:
        from zeus.audit_config import parse_audit_config
        from zeus.audit_models import AuditCategory, AuditCheck, CheckDisposition
        from zeus.audit_report import validate_model_output

        config = parse_audit_config({"schema_version": 1})
        payload = (
            b'{"summary":"ok","findings":[{"category":"security","severity":"low",'
            b'"confidence":"high","title":"source","evidence":[{"type":"source",'
            b'"path":"src/ok.py","start_line":2,"observation":"line"}],"impact":"i",'
            b'"recommendation":"r","verification":"v"}],"skipped_checks":[]}'
        )
        result = validate_model_output(
            payload,
            run_id="1" * 32,
            allowed_categories=frozenset({AuditCategory.security}),
            source_line_counts={"src/ok.py": 2},
            checks=(AuditCheck("check", CheckDisposition.passed, 0.0, "ok"),),
            limits=config.limits,
        )
        self.assertEqual(1, len(result.findings))

    def test_runner_outcome_status_and_cleanup_matrix(self) -> None:
        from zeus.audit import _status_for_outcome
        from zeus.audit_models import AuditStatus
        from zeus.audit_runner import AuditRunnerOutcome

        expected = {
            AuditRunnerOutcome.completed: AuditStatus.completed,
            AuditRunnerOutcome.cleanup_failed: AuditStatus.partial,
            AuditRunnerOutcome.cancelled: AuditStatus.cancelled,
            AuditRunnerOutcome.launch_failed: AuditStatus.failed,
            AuditRunnerOutcome.process_failed: AuditStatus.failed,
            AuditRunnerOutcome.timed_out: AuditStatus.failed,
            AuditRunnerOutcome.model_output_limit: AuditStatus.failed,
            AuditRunnerOutcome.stderr_output_limit: AuditStatus.failed,
            AuditRunnerOutcome.broker_breach: AuditStatus.failed,
            AuditRunnerOutcome.invalid_output: AuditStatus.failed,
        }
        self.assertEqual(
            expected,
            {outcome: _status_for_outcome(outcome) for outcome in AuditRunnerOutcome},
        )

    def test_incomplete_cleanup_marks_an_otherwise_valid_result_incomplete(self) -> None:
        from zeus.audit import _with_cleanup_completeness
        from zeus.audit_models import AuditCompleteness, ModelAuditResult

        result = ModelAuditResult("ok", (), (), AuditCompleteness(True))
        self.assertIs(result, _with_cleanup_completeness(result, cleanup_complete=True))
        incomplete = _with_cleanup_completeness(result, cleanup_complete=False)
        self.assertFalse(incomplete.completeness.complete)
        self.assertIn("audit cleanup was incomplete", incomplete.completeness.reasons)

    def test_successful_run_composes_profile_snapshot_and_real_output_validator(self) -> None:
        from zeus.audit import (
            AuditService,
        )
        from zeus.audit import (
            snapshot_source_line_counts as real_line_counts,
        )
        from zeus.audit_container import PreparedAuditContainer
        from zeus.audit_models import AuditStatus
        from zeus.audit_runner import AuditRunnerOutcome, AuditRunnerResult

        payload = json.dumps(
            {
                "summary": "verified",
                "findings": [
                    {
                        "category": "security",
                        "severity": "low",
                        "confidence": "high",
                        "title": "Committed source evidence",
                        "evidence": [
                            {
                                "type": "source",
                                "path": "README",
                                "start_line": 1,
                                "observation": "committed line",
                            }
                        ],
                        "impact": "impact",
                        "recommendation": "recommendation",
                        "verification": "verification",
                    }
                ],
                "skipped_checks": [],
            },
            separators=(",", ":"),
        ).encode()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            tool = root / "audit-tool"
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            tool.chmod(0o700)
            service = AuditService.from_cwd(cwd=root, env={})
            prepared_snapshot = None
            line_count_calls = 0
            profile_paths: list[Path] = []

            def prepare(runtime, **kwargs):
                nonlocal prepared_snapshot
                prepared_snapshot = kwargs["snapshot"]
                run_id = kwargs["run_id"]
                broker_dir = runtime._control_dir / "broker"
                return PreparedAuditContainer(
                    "1" * 64,
                    f"zeus-audit-{run_id}",
                    f"audit-{run_id}",
                    kwargs["image_ref"],
                    "sha256:" + "2" * 64,
                    broker_dir,
                    broker_dir / "state.json",
                )

            def line_counts(snapshot, *, deadline=None):
                nonlocal line_count_calls
                line_count_calls += 1
                return real_line_counts(snapshot, deadline=deadline)

            def run_hermes(_runner, **kwargs):
                self.assertEqual(1, line_count_calls)
                profile_path = (
                    service.settings.state_dir
                    / "audit"
                    / "runs"
                    / kwargs["profile_name"].removeprefix("audit-")
                    / "hermes"
                    / "profiles"
                    / kwargs["profile_name"]
                    / "config.yaml"
                )
                profile_paths.append(profile_path)
                self.assertTrue(profile_path.is_file())
                model_result = kwargs["validate_output"](payload)
                self.assertEqual(1, len(model_result.findings))
                return AuditRunnerResult(
                    AuditRunnerOutcome.completed,
                    model_result,
                    None,
                    0,
                    True,
                    True,
                )

            with (
                mock.patch("zeus.audit._executable", return_value=tool),
                mock.patch("zeus.audit_doctor._executable", return_value=tool),
                mock.patch("zeus.audit_doctor._command", return_value=(True, "available")),
                mock.patch(
                    "zeus.audit_doctor._pinned_hermes_version",
                    return_value=(True, "version 0.19.0"),
                ),
                mock.patch("zeus.audit_doctor._broker_isolation_supported", return_value=True),
                mock.patch(
                    "zeus.audit.AuditContainerRuntime.prepare",
                    autospec=True,
                    side_effect=prepare,
                ),
                mock.patch(
                    "zeus.audit.install_audit_docker_broker",
                    side_effect=lambda prepared, **_kwargs: prepared.broker_dir / "docker",
                ),
                mock.patch(
                    "zeus.audit.snapshot_source_line_counts",
                    side_effect=line_counts,
                ),
                mock.patch(
                    "zeus.audit.AuditRunner.run",
                    autospec=True,
                    side_effect=run_hermes,
                ),
            ):
                report = service.run()

            self.assertIsNotNone(prepared_snapshot, report.checks)
            self.assertEqual(AuditStatus.completed, report.status)
            self.assertTrue(report.completeness.complete)
            self.assertEqual(1, len(report.findings))
            self.assertEqual(1, line_count_calls)
            self.assertEqual(1, len(profile_paths))
            self.assertEqual(0o600, profile_paths[0].stat().st_mode & 0o777)


if __name__ == "__main__":
    unittest.main()
