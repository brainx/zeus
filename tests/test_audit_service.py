from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from contextlib import ExitStack, suppress
from pathlib import Path
from subprocess import DEVNULL, run
from types import SimpleNamespace
from unittest import mock


class AuditServiceContractTests(unittest.TestCase):
    def _configured_service(self, service):
        from zeus.audit_config import parse_audit_config

        service.env["TEST_PROVIDER_API_KEY"] = "test-provider-value"
        config = parse_audit_config(
            {
                "schema_version": 1,
                "provider": "test-provider",
                "model": "test-model",
                "provider_env": ["TEST_PROVIDER_API_KEY"],
            }
        )
        return mock.patch("zeus.audit.load_audit_config", return_value=config)

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

    def _prepared_container(self, runtime, **kwargs):
        from zeus.audit_container import PreparedAuditContainer

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

    def _completed_runner_result(self):
        from zeus.audit_models import AuditCompleteness, ModelAuditResult
        from zeus.audit_runner import AuditRunnerOutcome, AuditRunnerResult

        return AuditRunnerResult(
            AuditRunnerOutcome.completed,
            ModelAuditResult("ok", (), (), (), AuditCompleteness(True)),
            None,
            0,
            True,
            True,
        )

    def _run_with_external_audit_boundaries(
        self,
        service,
        tool: Path,
        *,
        runner_side_effect,
        cleanup_side_effect=None,
    ):
        patches = [
            self._configured_service(service),
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
                side_effect=self._prepared_container,
            ),
            mock.patch(
                "zeus.audit.install_audit_docker_broker",
                side_effect=lambda prepared, **_kwargs: prepared.broker_dir / "docker",
            ),
            mock.patch(
                "zeus.audit.AuditRunner.run",
                autospec=True,
                side_effect=runner_side_effect,
            ),
        ]
        if cleanup_side_effect is not None:
            patches.append(
                mock.patch(
                    "zeus.audit.AuditContainerRuntime.cleanup",
                    autospec=True,
                    side_effect=cleanup_side_effect,
                )
            )
        with ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            return service.run()

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

    def test_state_policy_rejects_narrow_probe_only_and_dirty_ignore_rules(self) -> None:
        from zeus.audit import AuditService, AuditServiceError

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root, ignored_state=False)
            gitignore = root / ".gitignore"

            gitignore.write_text(".zeus/.zeus-audit-ignore-probe\n", encoding="utf-8")
            run(("git", "-C", str(root), "add", ".gitignore"), check=True, stdin=DEVNULL)
            run(
                ("git", "-C", str(root), "commit", "-qm", "narrow ignore"),
                check=True,
                stdin=DEVNULL,
            )
            with self.assertRaisesRegex(AuditServiceError, "ignored and untracked"):
                AuditService.from_cwd(cwd=root, env={})._validate_state_path()

            gitignore.write_text(".zeus/\n", encoding="utf-8")
            with self.assertRaisesRegex(AuditServiceError, "ignored and untracked"):
                AuditService.from_cwd(cwd=root, env={})._validate_state_path()

            run(("git", "-C", str(root), "add", ".gitignore"), check=True, stdin=DEVNULL)
            run(
                ("git", "-C", str(root), "commit", "-qm", "broad ignore"),
                check=True,
                stdin=DEVNULL,
            )
            gitignore.write_text(
                ".zeus/.zeus-audit-ignore-probe\n",
                encoding="utf-8",
            )
            AuditService.from_cwd(cwd=root, env={})._validate_state_path()

    def test_state_policy_ignores_ambient_excludes_and_rejects_magic_state_paths(self) -> None:
        from zeus.audit import AuditService, AuditServiceError

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root, ignored_state=False)
            (root / ".git" / "info" / "exclude").write_text(".zeus/\n", encoding="utf-8")
            with self.assertRaisesRegex(AuditServiceError, "ignored and untracked"):
                AuditService.from_cwd(cwd=root, env={})._validate_state_path()

            with self.assertRaisesRegex(AuditServiceError, "pathspec syntax"):
                AuditService.from_cwd(
                    cwd=root,
                    env={"ZEUS_STATE_DIR": str(root / ":(glob).zeus")},
                )._validate_state_path()

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
            policy_deadlines: list[float] = []

            def command(*_args, **kwargs):
                timeouts.append(kwargs["timeout"])
                return SimpleNamespace(returncode=1, stdout=b"")

            def committed_policy(*_args, **kwargs):
                policy_deadlines.append(kwargs["deadline"])
                return {}

            with (
                mock.patch(
                    "zeus.audit.time.monotonic",
                    side_effect=(100.0,),
                ),
                mock.patch("zeus.audit.subprocess.run", side_effect=command),
                mock.patch.object(
                    service.workspace,
                    "committed_ignore_matches",
                    side_effect=committed_policy,
                ),
            ):
                service._validate_state_path(deadline=105.0)
            self.assertEqual([5.0], timeouts)
            self.assertEqual([105.0], policy_deadlines)

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
            b'"recommendation":"r","verification":"v"}],"checks":[],"skipped_checks":[]}'
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

        result = ModelAuditResult("ok", (), (), (), AuditCompleteness(True))
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
        from zeus.audit_config import parse_audit_config
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
                "checks": [],
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
            config = parse_audit_config(
                {
                    "schema_version": 1,
                    "provider": "test-provider",
                    "model": "test-model",
                    "provider_env": ["TEST_PROVIDER_API_KEY"],
                }
            )
            service = AuditService.from_cwd(
                cwd=root,
                env={"TEST_PROVIDER_API_KEY": "test-value"},
            )
            prepared_snapshot = None
            line_count_calls = 0
            profile_paths: list[Path] = []
            profile_modes: list[int] = []
            control_paths: list[Path] = []

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
                profile_modes.append(profile_path.stat().st_mode & 0o777)
                control_paths.append(kwargs["control_dir"])
                (kwargs["control_dir"] / "home" / "ephemeral.raw").write_bytes(b"raw")
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
                mock.patch("zeus.audit.load_audit_config", return_value=config),
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
            self.assertEqual([0o600], profile_modes)
            self.assertEqual(1, len(control_paths))
            self.assertFalse(control_paths[0].exists())
            cleanup = {check.name: check for check in report.checks}["control_cleanup"]
            self.assertEqual("passed", cleanup.disposition.value)

    def test_execution_failure_removes_control_after_container_cleanup(self) -> None:
        from zeus.audit import AuditService
        from zeus.audit_container import CleanupResult
        from zeus.audit_models import AuditStatus
        from zeus.audit_runner import AuditRunnerError

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            tool = root / "audit-tool"
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            tool.chmod(0o700)
            service = AuditService.from_cwd(cwd=root, env={})
            control_paths: list[Path] = []
            cleanup_order: list[str] = []

            def fail_runner(_runner, **kwargs):
                control = kwargs["control_dir"]
                control_paths.append(control)
                (control / "home" / "ephemeral.raw").write_bytes(b"raw")
                raise AuditRunnerError("runner failed after process cleanup")

            def cleanup_container(_runtime, prepared):
                self.assertTrue(prepared.broker_dir.parent.exists())
                cleanup_order.append("container")
                return CleanupResult(True, False, "removed")

            report = self._run_with_external_audit_boundaries(
                service,
                tool,
                runner_side_effect=fail_runner,
                cleanup_side_effect=cleanup_container,
            )

            self.assertEqual(AuditStatus.failed, report.status)
            self.assertEqual(["container"], cleanup_order)
            self.assertEqual(1, len(control_paths))
            self.assertFalse(control_paths[0].exists())
            cleanup = {check.name: check for check in report.checks}["control_cleanup"]
            self.assertEqual("passed", cleanup.disposition.value)

    def test_control_cleanup_symlink_failure_is_partial_and_does_not_follow_target(self) -> None:
        from zeus.audit import AuditService
        from zeus.audit_models import AuditStatus

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            tool = root / "audit-tool"
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            tool.chmod(0o700)
            service = AuditService.from_cwd(cwd=root, env={})
            outside = root / "outside.txt"
            outside.write_text("preserve\n", encoding="utf-8")
            control_paths: list[Path] = []

            def run_runner(_runner, **kwargs):
                control = kwargs["control_dir"]
                control_paths.append(control)
                (control / "escape").symlink_to(outside)
                return self._completed_runner_result()

            report = self._run_with_external_audit_boundaries(
                service,
                tool,
                runner_side_effect=run_runner,
            )

            self.assertEqual(AuditStatus.partial, report.status)
            self.assertFalse(report.completeness.complete)
            self.assertIn(
                "audit control directory cleanup was incomplete",
                report.completeness.reasons,
            )
            cleanup = {check.name: check for check in report.checks}["control_cleanup"]
            self.assertEqual("failed", cleanup.disposition.value)
            self.assertIn("symbolic link", cleanup.observation)
            self.assertEqual("preserve\n", outside.read_text(encoding="utf-8"))
            self.assertTrue(control_paths[0].exists())

    def test_control_cleanup_fails_closed_on_run_directory_replacement(self) -> None:
        from zeus.audit import AuditService
        from zeus.audit_models import AuditStatus

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            tool = root / "audit-tool"
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            tool.chmod(0o700)
            service = AuditService.from_cwd(cwd=root, env={})
            paths: list[tuple[Path, Path]] = []

            def run_runner(_runner, **kwargs):
                control = kwargs["control_dir"]
                moved = control.with_name(control.name + ".moved")
                control.rename(moved)
                control.mkdir(mode=0o700)
                paths.append((control, moved))
                return self._completed_runner_result()

            report = self._run_with_external_audit_boundaries(
                service,
                tool,
                runner_side_effect=run_runner,
            )

            self.assertEqual(AuditStatus.partial, report.status)
            cleanup = {check.name: check for check in report.checks}["control_cleanup"]
            self.assertEqual("failed", cleanup.disposition.value)
            self.assertIn("binding", cleanup.observation)
            self.assertTrue(paths[0][0].is_dir())
            self.assertTrue(paths[0][1].is_dir())

    def test_control_cleanup_rejects_root_replacement_during_final_rmdir(self) -> None:
        from zeus.audit import AuditService
        from zeus.audit_models import AuditStatus

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            tool = root / "audit-tool"
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            tool.chmod(0o700)
            service = AuditService.from_cwd(cwd=root, env={})
            control_paths: list[Path] = []
            moved_paths: list[Path] = []
            real_rmdir = __import__("os").rmdir

            def run_runner(_runner, **kwargs):
                control_paths.append(kwargs["control_dir"])
                return self._completed_runner_result()

            def replace_root_during_rmdir(path, *args, **kwargs):
                control = control_paths[0] if control_paths else None
                if (
                    control is not None
                    and path == control.name
                    and kwargs.get("dir_fd") is not None
                ):
                    moved = control.with_name(control.name + ".moved")
                    control.rename(moved)
                    control.mkdir(mode=0o700)
                    moved_paths.append(moved)
                return real_rmdir(path, *args, **kwargs)

            with mock.patch("zeus.audit.os.rmdir", side_effect=replace_root_during_rmdir):
                report = self._run_with_external_audit_boundaries(
                    service,
                    tool,
                    runner_side_effect=run_runner,
                )

            self.assertEqual(AuditStatus.partial, report.status)
            cleanup = {check.name: check for check in report.checks}["control_cleanup"]
            self.assertEqual("failed", cleanup.disposition.value)
            self.assertIn("identity remained linked", cleanup.observation)
            self.assertEqual(1, len(moved_paths), cleanup.observation)
            self.assertTrue(moved_paths[0].is_dir())

    def test_control_cleanup_rejects_nested_replacement_during_final_rmdir(self) -> None:
        from zeus.audit import AuditService
        from zeus.audit_models import AuditStatus

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            tool = root / "audit-tool"
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            tool.chmod(0o700)
            service = AuditService.from_cwd(cwd=root, env={})
            nested_paths: list[Path] = []
            moved_paths: list[Path] = []
            real_rmdir = __import__("os").rmdir

            def run_runner(_runner, **kwargs):
                nested = kwargs["control_dir"] / "home" / "nested"
                nested.mkdir(mode=0o700)
                nested_paths.append(nested)
                return self._completed_runner_result()

            def replace_nested_during_rmdir(path, *args, **kwargs):
                if path == "nested" and kwargs.get("dir_fd") is not None:
                    nested = nested_paths[0]
                    moved = nested.parents[2] / (nested.parents[1].name + ".nested-moved")
                    nested.rename(moved)
                    nested.mkdir(mode=0o700)
                    moved_paths.append(moved)
                return real_rmdir(path, *args, **kwargs)

            with mock.patch("zeus.audit.os.rmdir", side_effect=replace_nested_during_rmdir):
                report = self._run_with_external_audit_boundaries(
                    service,
                    tool,
                    runner_side_effect=run_runner,
                )

            self.assertEqual(AuditStatus.partial, report.status)
            cleanup = {check.name: check for check in report.checks}["control_cleanup"]
            self.assertEqual("failed", cleanup.disposition.value)
            self.assertIn("identity remained linked", cleanup.observation)
            self.assertEqual(1, len(moved_paths), cleanup.observation)
            self.assertTrue(moved_paths[0].is_dir())

    def test_control_creation_surfaces_unverified_cleanup_after_post_mkdir_lstat_failure(
        self,
    ) -> None:
        from zeus.audit import (
            AuditServiceError,
            _AuditRunControlLifecycle,
            _create_audit_run_control,
        )
        from zeus.private_io import ensure_private_directory

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve() / "runs"
            ensure_private_directory(parent)
            run_id = "a" * 32
            control = parent / run_id
            real_lstat = __import__("os").lstat
            failed = False

            def fail_first_control_lstat(path, *args, **kwargs):
                nonlocal failed
                if path == run_id and kwargs.get("dir_fd") is not None and not failed:
                    failed = True
                    raise OSError("injected post-mkdir lstat failure")
                return real_lstat(path, *args, **kwargs)

            with (
                mock.patch("zeus.audit.os.lstat", side_effect=fail_first_control_lstat),
                self.assertRaisesRegex(AuditServiceError, "cleanup could not be verified"),
            ):
                _create_audit_run_control(
                    parent,
                    control,
                    run_id,
                    _AuditRunControlLifecycle(),
                )

            self.assertTrue(failed)
            self.assertTrue(control.is_dir())

    def test_control_deletion_failure_marks_completed_run_partial(self) -> None:
        from zeus.audit import AuditService
        from zeus.audit_models import AuditStatus

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            tool = root / "audit-tool"
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            tool.chmod(0o700)
            service = AuditService.from_cwd(cwd=root, env={})
            real_unlink = __import__("os").unlink

            def run_runner(_runner, **kwargs):
                (kwargs["control_dir"] / "retained").write_bytes(b"raw")
                return self._completed_runner_result()

            def fail_retained_unlink(path, *args, **kwargs):
                if path == "retained" and kwargs.get("dir_fd") is not None:
                    raise OSError("injected deletion failure")
                return real_unlink(path, *args, **kwargs)

            with mock.patch("zeus.audit.os.unlink", side_effect=fail_retained_unlink):
                report = self._run_with_external_audit_boundaries(
                    service,
                    tool,
                    runner_side_effect=run_runner,
                )

            self.assertEqual(AuditStatus.partial, report.status)
            cleanup = {check.name: check for check in report.checks}["control_cleanup"]
            self.assertEqual("failed", cleanup.disposition.value)
            self.assertIn("could not be removed", cleanup.observation)

    def test_control_removal_waits_for_verified_runner_cleanup(self) -> None:
        from zeus.audit import AuditService
        from zeus.audit_runner import AuditRunnerOutcome, AuditRunnerResult

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            tool = root / "audit-tool"
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            tool.chmod(0o700)
            service = AuditService.from_cwd(cwd=root, env={})
            control_paths: list[Path] = []

            def run_runner(_runner, **kwargs):
                control = kwargs["control_dir"]
                control_paths.append(control)
                (control / "retained").write_bytes(b"raw")
                return AuditRunnerResult(
                    AuditRunnerOutcome.cleanup_failed,
                    None,
                    "process cleanup could not be verified",
                    0,
                    False,
                    False,
                )

            report = self._run_with_external_audit_boundaries(
                service,
                tool,
                runner_side_effect=run_runner,
            )

            self.assertTrue(control_paths[0].exists())
            cleanup = {check.name: check for check in report.checks}["control_cleanup"]
            self.assertEqual("failed", cleanup.disposition.value)
            self.assertIn("process/container cleanup", cleanup.observation)

    def test_interrupt_before_external_setup_removes_control_and_persists_cancelled_report(
        self,
    ) -> None:
        from zeus.audit import AuditService
        from zeus.audit_models import AuditStatus

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            tool = root / "audit-tool"
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            tool.chmod(0o700)
            service = AuditService.from_cwd(cwd=root, env={})

            with (
                self._configured_service(service),
                mock.patch("zeus.audit._executable", side_effect=KeyboardInterrupt("stop")),
                mock.patch("zeus.audit_doctor._executable", return_value=tool),
                mock.patch("zeus.audit_doctor._command", return_value=(True, "available")),
                mock.patch(
                    "zeus.audit_doctor._pinned_hermes_version",
                    return_value=(True, "version 0.19.0"),
                ),
                mock.patch("zeus.audit_doctor._broker_isolation_supported", return_value=True),
            ):
                try:
                    report = service.run()
                except KeyboardInterrupt:
                    self.fail("service propagated an interrupt before external setup")

            self.assertEqual(AuditStatus.cancelled, report.status)
            self.assertFalse(report.completeness.complete)
            cleanup = {check.name: check for check in report.checks}["control_cleanup"]
            self.assertEqual("passed", cleanup.disposition.value, cleanup.observation)
            control = service.settings.state_dir / "audit" / "runs" / report.run_id
            self.assertFalse(control.exists())
            self.assertTrue(
                (service.settings.state_dir / "audits" / report.run_id / "report.json").is_file()
            )

    def test_interrupt_after_control_mkdir_records_unverified_creation_cleanup(self) -> None:
        from zeus.audit import AuditService
        from zeus.audit_models import AuditStatus

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            tool = root / "audit-tool"
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            tool.chmod(0o700)
            service = AuditService.from_cwd(cwd=root, env={})
            real_lstat = __import__("os").lstat
            interrupted = False

            def interrupt_first_control_lstat(path, *args, **kwargs):
                nonlocal interrupted
                if (
                    not interrupted
                    and isinstance(path, str)
                    and len(path) == 32
                    and all(character in "0123456789abcdef" for character in path)
                    and kwargs.get("dir_fd") is not None
                ):
                    interrupted = True
                    raise KeyboardInterrupt("stop")
                return real_lstat(path, *args, **kwargs)

            with (
                self._configured_service(service),
                mock.patch("zeus.audit.os.lstat", side_effect=interrupt_first_control_lstat),
                mock.patch("zeus.audit_doctor._executable", return_value=tool),
                mock.patch("zeus.audit_doctor._command", return_value=(True, "available")),
                mock.patch(
                    "zeus.audit_doctor._pinned_hermes_version",
                    return_value=(True, "version 0.19.0"),
                ),
                mock.patch("zeus.audit_doctor._broker_isolation_supported", return_value=True),
            ):
                try:
                    report = service.run()
                except KeyboardInterrupt:
                    self.fail("service propagated an interrupt during control creation")

            self.assertTrue(interrupted)
            self.assertEqual(AuditStatus.cancelled, report.status)
            self.assertFalse(report.completeness.complete)
            checks = {check.name: check for check in report.checks}
            self.assertIn("control_cleanup", checks)
            cleanup = checks["control_cleanup"]
            self.assertEqual("failed", cleanup.disposition.value)
            self.assertIn("interrupted creation", cleanup.observation)
            control = service.settings.state_dir / "audit" / "runs" / report.run_id
            self.assertTrue(control.is_dir())
            self.assertTrue(
                (service.settings.state_dir / "audits" / report.run_id / "report.json").is_file()
            )

    def test_interrupt_at_control_mkdir_return_records_unverified_creation_cleanup(
        self,
    ) -> None:
        from zeus.audit import AuditService
        from zeus.audit_models import AuditStatus

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            tool = root / "audit-tool"
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            tool.chmod(0o700)
            service = AuditService.from_cwd(cwd=root, env={})
            real_mkdir = __import__("os").mkdir
            interrupted_run_ids: list[str] = []

            def mkdir_then_interrupt(path, *args, **kwargs):
                result = real_mkdir(path, *args, **kwargs)
                if (
                    not interrupted_run_ids
                    and isinstance(path, str)
                    and len(path) == 32
                    and all(character in "0123456789abcdef" for character in path)
                    and kwargs.get("dir_fd") is not None
                ):
                    interrupted_run_ids.append(path)
                    raise KeyboardInterrupt("stop after mkdir")
                return result

            with (
                self._configured_service(service),
                mock.patch("zeus.audit.os.mkdir", side_effect=mkdir_then_interrupt),
                mock.patch("zeus.audit_doctor._executable", return_value=tool),
                mock.patch("zeus.audit_doctor._command", return_value=(True, "available")),
                mock.patch(
                    "zeus.audit_doctor._pinned_hermes_version",
                    return_value=(True, "version 0.19.0"),
                ),
                mock.patch("zeus.audit_doctor._broker_isolation_supported", return_value=True),
            ):
                try:
                    report = service.run()
                except KeyboardInterrupt:
                    self.fail("service propagated an interrupt at the mkdir syscall boundary")

            self.assertEqual(AuditStatus.cancelled, report.status)
            self.assertFalse(report.completeness.complete)
            self.assertEqual([report.run_id], interrupted_run_ids)
            cleanup = {check.name: check for check in report.checks}["control_cleanup"]
            self.assertEqual("failed", cleanup.disposition.value)
            self.assertIn("could not be verified", cleanup.observation)
            control = service.settings.state_dir / "audit" / "runs" / report.run_id
            self.assertTrue(control.is_dir())
            self.assertTrue(
                (service.settings.state_dir / "audits" / report.run_id / "report.json").is_file()
            )

    def test_interrupt_at_control_handle_return_boundary_uses_published_handle(
        self,
    ) -> None:
        from zeus.audit import AuditService, _create_audit_run_control
        from zeus.audit_models import AuditStatus

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            tool = root / "audit-tool"
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            tool.chmod(0o700)
            service = AuditService.from_cwd(cwd=root, env={})
            real_fstat = __import__("os").fstat
            real_close = __import__("os").close
            created_handles = []

            def create_then_interrupt(*args, **kwargs):
                handle = _create_audit_run_control(*args, **kwargs)
                created_handles.append(handle)
                raise KeyboardInterrupt("stop after control handle return")

            try:
                with (
                    self._configured_service(service),
                    mock.patch(
                        "zeus.audit._create_audit_run_control",
                        side_effect=create_then_interrupt,
                    ),
                    mock.patch("zeus.audit_doctor._executable", return_value=tool),
                    mock.patch("zeus.audit_doctor._command", return_value=(True, "available")),
                    mock.patch(
                        "zeus.audit_doctor._pinned_hermes_version",
                        return_value=(True, "version 0.19.0"),
                    ),
                    mock.patch(
                        "zeus.audit_doctor._broker_isolation_supported",
                        return_value=True,
                    ),
                ):
                    try:
                        report = service.run()
                    except KeyboardInterrupt:
                        self.fail("service propagated an interrupt after control handle return")

                self.assertEqual(1, len(created_handles))
                handle = created_handles[0]
                self.assertEqual(AuditStatus.cancelled, report.status)
                self.assertFalse(report.completeness.complete)
                cleanup = {check.name: check for check in report.checks}["control_cleanup"]
                self.assertEqual("passed", cleanup.disposition.value, cleanup.observation)
                self.assertFalse((handle.parent_path / handle.name).exists())
                with self.assertRaises(OSError):
                    real_fstat(handle.descriptor)
                self.assertTrue(
                    (
                        service.settings.state_dir / "audits" / report.run_id / "report.json"
                    ).is_file()
                )
            finally:
                for handle in created_handles:
                    with suppress(OSError):
                        real_close(handle.descriptor)

    def test_interrupt_at_control_cleanup_return_boundary_persists_unverified_result(
        self,
    ) -> None:
        from zeus.audit import (
            AuditService,
            _cleanup_audit_run_control,
            _create_audit_run_control,
        )
        from zeus.audit_models import AuditStatus

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            tool = root / "audit-tool"
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            tool.chmod(0o700)
            service = AuditService.from_cwd(cwd=root, env={})
            real_fstat = __import__("os").fstat
            created_handles = []
            cleanup_results = []

            def track_creation(*args, **kwargs):
                handle = _create_audit_run_control(*args, **kwargs)
                created_handles.append(handle)
                return handle

            def cleanup_then_interrupt(control):
                result = _cleanup_audit_run_control(control)
                cleanup_results.append(result)
                raise KeyboardInterrupt("stop after control cleanup return")

            with (
                self._configured_service(service),
                mock.patch(
                    "zeus.audit._create_audit_run_control",
                    side_effect=track_creation,
                ),
                mock.patch(
                    "zeus.audit._cleanup_audit_run_control",
                    side_effect=cleanup_then_interrupt,
                ),
                mock.patch("zeus.audit._executable", side_effect=KeyboardInterrupt("stop")),
                mock.patch("zeus.audit_doctor._executable", return_value=tool),
                mock.patch("zeus.audit_doctor._command", return_value=(True, "available")),
                mock.patch(
                    "zeus.audit_doctor._pinned_hermes_version",
                    return_value=(True, "version 0.19.0"),
                ),
                mock.patch("zeus.audit_doctor._broker_isolation_supported", return_value=True),
            ):
                try:
                    report = service.run()
                except KeyboardInterrupt:
                    self.fail("service propagated an interrupt after control cleanup return")

            self.assertEqual(1, len(created_handles))
            self.assertEqual(1, len(cleanup_results))
            self.assertTrue(cleanup_results[0].complete)
            handle = created_handles[0]
            self.assertEqual(AuditStatus.cancelled, report.status)
            self.assertFalse(report.completeness.complete)
            cleanup = {check.name: check for check in report.checks}["control_cleanup"]
            self.assertEqual("failed", cleanup.disposition.value)
            self.assertIn("could not be verified", cleanup.observation)
            self.assertFalse((handle.parent_path / handle.name).exists())
            with self.assertRaises(OSError):
                real_fstat(handle.descriptor)
            self.assertTrue(
                (service.settings.state_dir / "audits" / report.run_id / "report.json").is_file()
            )

    def test_interrupted_creation_cleanup_rejects_identity_swap_during_rmdir(self) -> None:
        from zeus.audit import AuditService
        from zeus.audit_models import AuditStatus

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            tool = root / "audit-tool"
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            tool.chmod(0o700)
            service = AuditService.from_cwd(cwd=root, env={})
            real_open = __import__("os").open
            real_rmdir = __import__("os").rmdir
            interrupted_run_ids: list[str] = []
            moved_paths: list[Path] = []

            def interrupt_control_open(path, flags, *args, **kwargs):
                if (
                    not interrupted_run_ids
                    and isinstance(path, str)
                    and len(path) == 32
                    and all(character in "0123456789abcdef" for character in path)
                    and kwargs.get("dir_fd") is not None
                ):
                    interrupted_run_ids.append(path)
                    raise KeyboardInterrupt("stop")
                return real_open(path, flags, *args, **kwargs)

            def replace_creation_during_rmdir(path, *args, **kwargs):
                if (
                    interrupted_run_ids
                    and path == interrupted_run_ids[0]
                    and kwargs.get("dir_fd") is not None
                ):
                    control = service.settings.state_dir / "audit" / "runs" / interrupted_run_ids[0]
                    moved = control.with_name(control.name + ".moved")
                    control.rename(moved)
                    control.mkdir(mode=0o700)
                    moved_paths.append(moved)
                return real_rmdir(path, *args, **kwargs)

            with (
                self._configured_service(service),
                mock.patch("zeus.audit.os.open", side_effect=interrupt_control_open),
                mock.patch("zeus.audit.os.rmdir", side_effect=replace_creation_during_rmdir),
                mock.patch("zeus.audit_doctor._executable", return_value=tool),
                mock.patch("zeus.audit_doctor._command", return_value=(True, "available")),
                mock.patch(
                    "zeus.audit_doctor._pinned_hermes_version",
                    return_value=(True, "version 0.19.0"),
                ),
                mock.patch("zeus.audit_doctor._broker_isolation_supported", return_value=True),
            ):
                try:
                    report = service.run()
                except KeyboardInterrupt:
                    self.fail("service propagated an identity-known creation interrupt")

            self.assertEqual(AuditStatus.cancelled, report.status)
            self.assertEqual([report.run_id], interrupted_run_ids)
            cleanup = {check.name: check for check in report.checks}["control_cleanup"]
            self.assertEqual("failed", cleanup.disposition.value)
            self.assertIn("interrupted creation", cleanup.observation)
            self.assertEqual(1, len(moved_paths), cleanup.observation)
            self.assertTrue(moved_paths[0].is_dir())
            self.assertTrue(
                (service.settings.state_dir / "audits" / report.run_id / "report.json").is_file()
            )

    def test_second_interrupt_during_creation_cleanup_records_unverified_result(self) -> None:
        from zeus.audit import AuditService
        from zeus.audit_models import AuditStatus

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            tool = root / "audit-tool"
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            tool.chmod(0o700)
            service = AuditService.from_cwd(cwd=root, env={})
            real_open = __import__("os").open
            real_fsync = __import__("os").fsync
            interrupted_run_ids: list[str] = []
            cleanup_interrupted = False

            def interrupt_control_open(path, flags, *args, **kwargs):
                if (
                    not interrupted_run_ids
                    and isinstance(path, str)
                    and len(path) == 32
                    and all(character in "0123456789abcdef" for character in path)
                    and kwargs.get("dir_fd") is not None
                ):
                    interrupted_run_ids.append(path)
                    raise KeyboardInterrupt("first stop")
                return real_open(path, flags, *args, **kwargs)

            def interrupt_cleanup_fsync(descriptor):
                nonlocal cleanup_interrupted
                if interrupted_run_ids and not cleanup_interrupted:
                    cleanup_interrupted = True
                    raise KeyboardInterrupt("second stop")
                return real_fsync(descriptor)

            with (
                self._configured_service(service),
                mock.patch("zeus.audit.os.open", side_effect=interrupt_control_open),
                mock.patch("zeus.audit.os.fsync", side_effect=interrupt_cleanup_fsync),
                mock.patch("zeus.audit_doctor._executable", return_value=tool),
                mock.patch("zeus.audit_doctor._command", return_value=(True, "available")),
                mock.patch(
                    "zeus.audit_doctor._pinned_hermes_version",
                    return_value=(True, "version 0.19.0"),
                ),
                mock.patch("zeus.audit_doctor._broker_isolation_supported", return_value=True),
            ):
                report = service.run()

            self.assertTrue(cleanup_interrupted)
            self.assertEqual(AuditStatus.cancelled, report.status)
            self.assertEqual([report.run_id], interrupted_run_ids)
            checks = {check.name: check for check in report.checks}
            self.assertIn("control_cleanup", checks)
            cleanup = checks["control_cleanup"]
            self.assertEqual("failed", cleanup.disposition.value)
            self.assertIn(
                "cleanup after interrupted creation could not be verified",
                cleanup.observation,
            )
            self.assertTrue(
                (service.settings.state_dir / "audits" / report.run_id / "report.json").is_file()
            )

    def test_interrupt_after_container_prepare_cleans_container_then_control(self) -> None:
        from zeus.audit import AuditService
        from zeus.audit_container import CleanupResult
        from zeus.audit_models import AuditStatus

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            tool = root / "audit-tool"
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            tool.chmod(0o700)
            service = AuditService.from_cwd(cwd=root, env={})
            cleanup_order: list[str] = []
            control_paths: list[Path] = []

            def prepare(runtime, **kwargs):
                control_paths.append(runtime._control_dir)
                return self._prepared_container(runtime, **kwargs)

            def cleanup_container(_runtime, prepared):
                self.assertTrue(prepared.broker_dir.parent.exists())
                cleanup_order.append("container")
                return CleanupResult(True, False, "removed")

            with (
                self._configured_service(service),
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
                    side_effect=KeyboardInterrupt("stop"),
                ),
                mock.patch(
                    "zeus.audit.AuditContainerRuntime.cleanup",
                    autospec=True,
                    side_effect=cleanup_container,
                ),
            ):
                try:
                    report = service.run()
                except KeyboardInterrupt:
                    self.fail("service propagated an interrupt after container preparation")

            self.assertEqual(AuditStatus.cancelled, report.status)
            self.assertFalse(report.completeness.complete)
            self.assertEqual(["container"], cleanup_order)
            self.assertEqual(1, len(control_paths))
            cleanup = {check.name: check for check in report.checks}["control_cleanup"]
            self.assertFalse(control_paths[0].exists(), cleanup.observation)
            self.assertEqual("passed", cleanup.disposition.value)

    def test_interrupt_during_unidentified_container_setup_retains_control_and_reports_it(
        self,
    ) -> None:
        from zeus.audit import AuditService
        from zeus.audit_models import AuditStatus

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            tool = root / "audit-tool"
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            tool.chmod(0o700)
            service = AuditService.from_cwd(cwd=root, env={})

            with (
                self._configured_service(service),
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
                    side_effect=KeyboardInterrupt("stop"),
                ),
            ):
                try:
                    report = service.run()
                except KeyboardInterrupt:
                    self.fail("service propagated an interrupt during container setup")

            self.assertEqual(AuditStatus.cancelled, report.status)
            self.assertFalse(report.completeness.complete)
            cleanup = {check.name: check for check in report.checks}["control_cleanup"]
            self.assertEqual("failed", cleanup.disposition.value)
            self.assertIn("external resource cleanup", cleanup.observation)
            control = service.settings.state_dir / "audit" / "runs" / report.run_id
            self.assertTrue(control.is_dir())
            self.assertTrue(
                (service.settings.state_dir / "audits" / report.run_id / "report.json").is_file()
            )

    def test_prepared_container_cleanup_exception_preserves_primary_failed_report(self) -> None:
        from zeus.audit import AuditService
        from zeus.audit_container import AuditContainerError
        from zeus.audit_docker_broker import AuditDockerBrokerError
        from zeus.audit_models import AuditStatus

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            tool = root / "audit-tool"
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            tool.chmod(0o700)
            service = AuditService.from_cwd(cwd=root, env={})
            control_paths: list[Path] = []

            def prepare(runtime, **kwargs):
                control_paths.append(runtime._control_dir)
                return self._prepared_container(runtime, **kwargs)

            with (
                self._configured_service(service),
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
                    side_effect=AuditDockerBrokerError("primary broker failure"),
                ),
                mock.patch(
                    "zeus.audit.AuditContainerRuntime.cleanup",
                    autospec=True,
                    side_effect=AuditContainerError("cleanup raised"),
                ),
            ):
                try:
                    report = service.run()
                except AuditContainerError:
                    self.fail("container cleanup replaced the primary audit failure")

            self.assertEqual(AuditStatus.failed, report.status)
            execution = {check.name: check for check in report.checks}["execution"]
            self.assertIn("primary broker failure", execution.observation)
            self.assertIn("cleanup could not be verified", execution.observation)
            cleanup = {check.name: check for check in report.checks}["control_cleanup"]
            self.assertEqual("failed", cleanup.disposition.value)
            self.assertEqual(1, len(control_paths))
            self.assertTrue(control_paths[0].is_dir())
            self.assertTrue(
                (service.settings.state_dir / "audits" / report.run_id / "report.json").is_file()
            )

    def test_container_error_during_unidentified_setup_retains_control_and_reports_it(
        self,
    ) -> None:
        from zeus.audit import AuditService
        from zeus.audit_container import AuditContainerError
        from zeus.audit_models import AuditStatus

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._repository(root)
            tool = root / "audit-tool"
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            tool.chmod(0o700)
            service = AuditService.from_cwd(cwd=root, env={})

            with (
                self._configured_service(service),
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
                    side_effect=AuditContainerError("malformed Docker create response"),
                ),
            ):
                report = service.run()

            self.assertEqual(AuditStatus.failed, report.status)
            self.assertFalse(report.completeness.complete)
            cleanup = {check.name: check for check in report.checks}["control_cleanup"]
            self.assertEqual("failed", cleanup.disposition.value)
            self.assertIn("external resource cleanup", cleanup.observation)
            control = service.settings.state_dir / "audit" / "runs" / report.run_id
            self.assertTrue(control.is_dir())
            execution = {check.name: check for check in report.checks}["execution"]
            self.assertIn("cleanup could not be verified", execution.observation)
            self.assertTrue(
                (service.settings.state_dir / "audits" / report.run_id / "report.json").is_file()
            )


if __name__ == "__main__":
    unittest.main()
