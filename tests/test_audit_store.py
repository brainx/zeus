from __future__ import annotations

import os
import stat
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from zeus import audit_store
from zeus.audit_models import (
    AuditCompleteness,
    AuditMetadata,
    AuditReport,
    AuditStatus,
    SeverityCounts,
)
from zeus.audit_report import REPORT_SCHEMA_VERSION, render_audit_markdown
from zeus.audit_store import AuditStore, AuditStoreError
from zeus.private_io import UnsafeFileError, write_private_bytes_atomic


def _report(
    run_id: str,
    *,
    started_at: str = "2026-07-23T10:00:00Z",
    summary: str = "Audit complete",
) -> AuditReport:
    return AuditReport(
        schema_version=REPORT_SCHEMA_VERSION,
        run_id=run_id,
        repository_id="repository-opaque-id",
        status=AuditStatus.completed,
        metadata=AuditMetadata(
            zeus_version="0.4.0",
            hermes_version="0.20.0",
            skill_version="1",
            image_digest="sha256:" + "a" * 64,
            target_commit="b" * 40,
            started_at=started_at,
            finished_at=started_at,
            termination_reason=None,
            provider="provider",
            model="model",
            worktree_changes_excluded=True,
        ),
        summary=summary,
        checks=(),
        skipped_content=(),
        findings=(),
        severity_counts=SeverityCounts(),
        completeness=AuditCompleteness(complete=True),
    )


class AuditStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()
        self.state_dir = self.root / "state"
        self.store = AuditStore(self.state_dir)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _artifact_path(self, run_id: str, name: str) -> Path:
        return self.state_dir / "audits" / run_id / name

    def test_install_publishes_complete_private_pair(self) -> None:
        report = _report("0123456789abcdef0123456789abcdef")

        artifacts = self.store.install(report)

        self.assertEqual(report.run_id, artifacts.run_id)
        self.assertEqual(self._artifact_path(report.run_id, "report.json"), artifacts.json_path)
        self.assertEqual(
            self._artifact_path(report.run_id, "report.md"),
            artifacts.markdown_path,
        )
        self.assertEqual(report, self.store.read_report(report.run_id))
        self.assertEqual(render_audit_markdown(report), self.store.read_markdown(report.run_id))
        for directory in (
            self.state_dir,
            self.state_dir / "audits",
            self.state_dir / "audits" / report.run_id,
        ):
            self.assertEqual(0o700, stat.S_IMODE(directory.stat().st_mode))
        for name in ("report.json", "report.md"):
            self.assertEqual(
                0o600,
                stat.S_IMODE(self._artifact_path(report.run_id, name).stat().st_mode),
            )

    def test_install_never_replaces_an_existing_run(self) -> None:
        run_id = "11111111111111111111111111111111"
        original = _report(run_id, summary="original")
        self.store.install(original)

        with self.assertRaises(AuditStoreError):
            self.store.install(replace(original, summary="replacement"))

        self.assertEqual(original, self.store.read_report(run_id))
        self.assertEqual(render_audit_markdown(original), self.store.read_markdown(run_id))

    def test_install_does_not_replace_an_ambiguous_empty_destination(self) -> None:
        run_id = "22222222222222222222222222222222"
        destination = self.state_dir / "audits" / run_id

        def create_destination(_source: int, _name: str, _destination: int) -> None:
            destination.mkdir(mode=0o700)
            raise FileExistsError("destination exists")

        with (
            patch.object(audit_store, "_rename_directory_noreplace", create_destination),
            self.assertRaises(AuditStoreError),
        ):
            self.store.install(_report(run_id))

        self.assertTrue(destination.is_dir())
        self.assertEqual([], list(destination.iterdir()))

    def test_failure_before_publish_leaves_no_visible_run_and_cleans_owned_staging(self) -> None:
        run_id = "33333333333333333333333333333333"
        real_write = write_private_bytes_atomic
        calls = 0

        def fail_second_write(path: Path, data: bytes, max_bytes: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected write failure")
            real_write(path, data, max_bytes)

        with (
            patch.object(
                audit_store,
                "_write_private_bytes_atomic",
                side_effect=fail_second_write,
            ),
            self.assertRaises(OSError),
        ):
            self.store.install(_report(run_id))

        audits = self.state_dir / "audits"
        self.assertFalse((audits / run_id).exists())
        self.assertEqual([], list(audits.iterdir()))

    def test_failure_cleanup_preserves_replaced_ambiguous_staging_path(self) -> None:
        run_id = "44444444444444444444444444444444"
        replacement_seen: Path | None = None
        real_write = write_private_bytes_atomic
        calls = 0

        def replace_staging_then_fail(path: Path, data: bytes, max_bytes: int) -> None:
            nonlocal calls, replacement_seen
            calls += 1
            if calls == 2:
                staging = path.parent
                displaced = staging.with_name(staging.name + ".owned")
                staging.rename(displaced)
                staging.mkdir(mode=0o700)
                marker = staging / "unowned"
                marker.write_text("preserve", encoding="utf-8")
                replacement_seen = staging
                raise OSError("injected replacement")
            real_write(path, data, max_bytes)

        with (
            patch.object(
                audit_store,
                "_write_private_bytes_atomic",
                side_effect=replace_staging_then_fail,
            ),
            self.assertRaises(OSError),
        ):
            self.store.install(_report(run_id))

        self.assertIsNotNone(replacement_seen)
        assert replacement_seen is not None
        self.assertEqual("preserve", (replacement_seen / "unowned").read_text(encoding="utf-8"))
        self.assertFalse((self.state_dir / "audits" / run_id).exists())

    def test_new_install_preserves_older_runs(self) -> None:
        older = _report(
            "55555555555555555555555555555555",
            started_at="2026-07-23T09:00:00Z",
        )
        newer = _report(
            "66666666666666666666666666666666",
            started_at="2026-07-23T10:00:00Z",
        )

        self.store.install(older)
        self.store.install(newer)

        self.assertEqual(older, self.store.read_report(older.run_id))
        self.assertEqual(newer, self.store.read_report(newer.run_id))

    def test_rejects_non_lowercase_uuid_hex_run_ids_before_path_access(self) -> None:
        invalid = (
            "",
            "run-123",
            "../report",
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef0",
            "01234567-89ab-cdef-0123-456789abcdef",
            "0123456789ABCDEF0123456789ABCDEF",
            "g123456789abcdef0123456789abcdef",
        )
        for run_id in invalid:
            with self.subTest(run_id=run_id):
                with self.assertRaises((AuditStoreError, ValueError)):
                    self.store.install(_report(run_id))
                with self.assertRaises((AuditStoreError, ValueError)):
                    self.store.read_report(run_id)
                with self.assertRaises((AuditStoreError, ValueError)):
                    self.store.read_markdown(run_id)

        self.assertFalse(self.state_dir.exists())

    def test_read_rejects_corrupt_json_and_run_id_mismatch(self) -> None:
        run_id = "77777777777777777777777777777777"
        self.store.install(_report(run_id))
        json_path = self._artifact_path(run_id, "report.json")
        json_path.write_bytes(b"{corrupt")
        json_path.chmod(0o600)

        with self.assertRaises((AuditStoreError, ValueError)):
            self.store.read_report(run_id)

        other_id = "88888888888888888888888888888888"
        other = _report(other_id)
        from zeus.audit_report import serialize_audit_report

        json_path.write_bytes(serialize_audit_report(other))
        json_path.chmod(0o600)
        with self.assertRaises(AuditStoreError):
            self.store.read_report(run_id)

    def test_reads_reject_unsafe_leaf_types_and_oversize(self) -> None:
        run_id = "99999999999999999999999999999999"
        run_dir = self.state_dir / "audits" / run_id
        run_dir.mkdir(parents=True, mode=0o700)
        (self.state_dir / "audits").chmod(0o700)
        self.state_dir.chmod(0o700)
        target = run_dir / "target"
        target.write_bytes(b"target")
        target.chmod(0o600)

        for kind in ("symlink", "hardlink", "fifo", "oversize"):
            with self.subTest(kind=kind):
                json_path = run_dir / "report.json"
                if os.path.lexists(json_path):
                    json_path.unlink()
                if kind == "symlink":
                    json_path.symlink_to(target)
                elif kind == "hardlink":
                    os.link(target, json_path)
                elif kind == "fifo":
                    if not hasattr(os, "mkfifo"):
                        continue
                    os.mkfifo(json_path, mode=0o600)
                else:
                    json_path.write_bytes(b"x" * 33)
                    json_path.chmod(0o600)
                store = AuditStore(self.state_dir, max_artifact_bytes=32)
                with self.assertRaises((AuditStoreError, UnsafeFileError, ValueError)):
                    store.read_report(run_id)

    def test_list_is_newest_first_with_a_stable_run_id_tiebreaker(self) -> None:
        reports = (
            _report(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                started_at="2026-07-23T09:00:00Z",
            ),
            _report(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                started_at="2026-07-23T10:00:00Z",
            ),
            _report(
                "cccccccccccccccccccccccccccccccc",
                started_at="2026-07-23T10:00:00Z",
            ),
        )
        for report in reports:
            self.store.install(report)

        self.assertEqual(
            (
                "cccccccccccccccccccccccccccccccc",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            tuple(report.run_id for report in self.store.list_reports()),
        )

    def test_list_of_missing_store_is_empty(self) -> None:
        self.assertEqual((), self.store.list_reports())
        self.assertFalse(self.state_dir.exists())

    def test_read_markdown_rejects_non_utf8_and_deterministic_mismatch(self) -> None:
        run_id = "dddddddddddddddddddddddddddddddd"
        report = _report(run_id)
        self.store.install(report)
        markdown_path = self._artifact_path(run_id, "report.md")

        markdown_path.write_bytes(b"\xff")
        markdown_path.chmod(0o600)
        with self.assertRaises(AuditStoreError):
            self.store.read_markdown(run_id)

        markdown_path.write_text(render_audit_markdown(report) + "tampered\n", encoding="utf-8")
        markdown_path.chmod(0o600)
        with self.assertRaises(AuditStoreError):
            self.store.read_markdown(run_id)

    def test_concurrent_installs_have_one_winner_and_one_loser(self) -> None:
        run_id = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        report = _report(run_id)
        barrier = threading.Barrier(2)
        successes: list[object] = []
        failures: list[BaseException] = []

        def install() -> None:
            barrier.wait()
            try:
                successes.append(AuditStore(self.state_dir).install(report))
            except BaseException as exc:
                failures.append(exc)

        threads = [threading.Thread(target=install) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(1, len(successes))
        self.assertEqual(1, len(failures))
        self.assertIsInstance(failures[0], AuditStoreError)
        self.assertEqual(report, self.store.read_report(run_id))
        self.assertEqual(
            [run_id],
            [
                entry.name
                for entry in (self.state_dir / "audits").iterdir()
                if not entry.name.startswith(".")
            ],
        )
