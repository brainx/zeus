from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import os
import select
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from typing import ClassVar
from unittest.mock import patch

from zeus import models
from zeus.models import BotRecord, BotStatus, DesiredState, RestartPolicy
from zeus.state import StateStore
from zeus.supervisor import Supervisor

V4_BOTS_SCHEMA = """
CREATE TABLE bots (
    bot_id TEXT PRIMARY KEY,
    template_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    profile_path TEXT NOT NULL,
    status TEXT NOT NULL,
    pid INTEGER,
    restart_policy TEXT NOT NULL DEFAULT 'manual',
    restart_backoff_seconds REAL NOT NULL DEFAULT 5.0,
    restart_max_attempts INTEGER NOT NULL DEFAULT 5,
    restart_attempts INTEGER NOT NULL DEFAULT 0,
    next_restart_at TEXT,
    started_at TEXT,
    ready_at TEXT,
    stopped_at TEXT,
    last_exit_code INTEGER,
    last_error TEXT,
    last_transition_reason TEXT,
    last_event_id INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
)
"""


V4_LIFECYCLE_SCHEMA = """
CREATE TABLE lifecycle_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    bot_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    request_id TEXT,
    occurred_at TEXT NOT NULL,
    source TEXT NOT NULL,
    action TEXT NOT NULL,
    outcome TEXT NOT NULL,
    status_before TEXT,
    status_after TEXT,
    pid_before INTEGER,
    pid_after INTEGER,
    reason TEXT NOT NULL DEFAULT '',
    error_code TEXT,
    error_message TEXT,
    details_json TEXT NOT NULL DEFAULT '{}'
)
"""


def _command_fingerprint(argv: list[str]) -> str:
    encoded = json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class _RecoveryPopen:
    pid = 4321
    launches: ClassVar[list[dict[str, object]]] = []
    marker_start_fingerprint: ClassVar[str | None] = "test-start:4321"

    def __init__(self, argv, env, stdout, stderr, **kwargs):
        self.returncode: int | None = None
        payload_fd = os.dup(int(argv[-2]))
        ack_fd = os.dup(int(argv[-1]))

        def publish() -> None:
            try:
                chunks: list[bytes] = []
                while chunk := os.read(payload_fd, 65536):
                    chunks.append(chunk)
                payload = json.loads(b"".join(chunks))
                self.__class__.launches.append(payload)
                marker = dict(payload["marker"])
                marker.update({"pid": self.pid, "started_at": time.time()})
                if self.marker_start_fingerprint is not None:
                    marker["proc_start_fingerprint"] = self.marker_start_fingerprint
                marker_path = Path(payload["marker_path"])
                marker_path.parent.mkdir(parents=True, exist_ok=True)
                marker_path.write_text(json.dumps(marker), encoding="utf-8")
                os.write(ack_fd, b"1")
            finally:
                os.close(payload_fd)
                os.close(ack_fd)

        threading.Thread(target=publish, daemon=True).start()

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is None:
            raise subprocess.TimeoutExpired("hermes", timeout)
        return self.returncode


class _MissingFingerprintRecoveryPopen(_RecoveryPopen):
    marker_start_fingerprint = None


class _PostAckLockPopen:
    pid = 4321
    publication_locked = threading.Event()
    release_exec = threading.Event()
    exec_visible = threading.Event()
    errors: ClassVar[list[BaseException]] = []
    instances: ClassVar[list[_PostAckLockPopen]] = []

    def __init__(self, argv, env, stdout, stderr, **kwargs):
        self.returncode: int | None = None
        self.__class__.instances.append(self)
        payload_fd = os.dup(int(argv[-2]))
        ack_fd = os.dup(int(argv[-1]))

        def publish_then_wait_for_exec() -> None:
            from zeus import gateway_launcher

            try:
                chunks: list[bytes] = []
                while chunk := os.read(payload_fd, 65536):
                    chunks.append(chunk)
                payload = json.loads(b"".join(chunks))
                profile_path = Path(payload["profile_path"])
                marker = dict(payload["marker"])
                marker.update(
                    {
                        "pid": self.pid,
                        "started_at": time.time(),
                        "proc_start_fingerprint": "test-start:4321",
                    }
                )
                with gateway_launcher.marker_publication_lock(
                    profile_path,
                    timeout_seconds=1,
                ):
                    gateway_launcher._publish_marker(profile_path, marker)
                    os.write(ack_fd, b"1")
                    os.close(ack_fd)
                    self.__class__.publication_locked.set()
                    if not self.__class__.release_exec.wait(timeout=2):
                        raise RuntimeError("test exec release timed out")
                    if self.returncode is None:
                        self.__class__.exec_visible.set()
            except BaseException as exc:
                self.__class__.errors.append(exc)
            finally:
                os.close(payload_fd)
                with contextlib.suppress(OSError):
                    os.close(ack_fd)

        self.publisher = threading.Thread(target=publish_then_wait_for_exec, daemon=True)
        self.publisher.start()

    @classmethod
    def reset(cls) -> None:
        cls.publication_locked.clear()
        cls.release_exec.clear()
        cls.exec_visible.clear()
        cls.errors.clear()
        cls.instances.clear()

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.returncode = -15
        self.__class__.release_exec.set()

    def kill(self) -> None:
        self.returncode = -9
        self.__class__.release_exec.set()

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is None:
            raise subprocess.TimeoutExpired("hermes", timeout)
        return self.returncode


class GatewayLauncherTests(unittest.TestCase):
    def _fake_hermes(self, root: Path) -> tuple[Path, Path, Path]:
        started = root / "hermes-started.json"
        gate = root / "ack-observed"
        hermes = root / "bin" / "hermes"
        hermes.parent.mkdir(parents=True)
        hermes.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys, time\n"
            "from pathlib import Path\n"
            "gate = Path(os.environ['HERMES_ACK_GATE'])\n"
            "deadline = time.monotonic() + 5\n"
            "while not gate.exists() and time.monotonic() < deadline:\n"
            "    time.sleep(0.01)\n"
            "if not gate.exists():\n"
            "    raise SystemExit(9)\n"
            "Path(os.environ['HERMES_STARTED']).write_text(\n"
            "    json.dumps({'pid': os.getpid(), 'argv': sys.argv}), encoding='utf-8'\n"
            ")\n",
            encoding="utf-8",
        )
        hermes.chmod(0o755)
        return hermes.resolve(), started, gate

    def _payload(self, root: Path) -> tuple[dict[str, object], Path, Path, Path]:
        profile = root / "hermes" / "profiles" / "coder"
        profile.mkdir(parents=True)
        profile = profile.resolve()
        hermes, started, gate = self._fake_hermes(root)
        argv = [str(hermes), "-p", "coder", "gateway", "run"]
        marker_path = profile / "logs" / "zeus-gateway.pid.json"
        payload: dict[str, object] = {
            "profile_path": str(profile),
            "marker_path": str(marker_path),
            "marker": {
                "schema": 3,
                "bot_id": "coder",
                "component": "gateway",
                "action": "run",
                "operation_id": "a" * 32,
                "desired_revision": 1,
                "argv": argv,
                "resolved_hermes_bin": str(hermes),
                "command_fingerprint": _command_fingerprint(argv),
                "readiness_probe": None,
            },
            "argv": argv,
            "env": {
                "HERMES_HOME": str(profile.parent.parent),
                "HERMES_ACK_GATE": str(gate),
                "HERMES_STARTED": str(started),
                "OPTIONAL_EMPTY": "",
                "OPENROUTER_API_KEY": "private-launch-secret",
                "PATH": os.environ.get("PATH", ""),
            },
        }
        return payload, marker_path, started, gate

    def _run_launcher(
        self,
        payload: dict[str, object] | bytes,
        *,
        acknowledge: bool = True,
    ) -> tuple[subprocess.CompletedProcess[bytes], bytes, int]:
        payload_bytes = (
            payload
            if isinstance(payload, bytes)
            else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )
        payload_read, payload_write = os.pipe()
        ack_read, ack_write = os.pipe()
        command = [
            sys.executable,
            "-m",
            "zeus.gateway_launcher",
            str(payload_read),
            str(ack_write),
        ]
        process = subprocess.Popen(  # nosec B603
            command,
            pass_fds=(payload_read, ack_write),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        os.close(payload_read)
        os.close(ack_write)
        try:
            try:
                os.write(payload_write, payload_bytes)
            except BrokenPipeError:
                pass
            finally:
                os.close(payload_write)
            ack = os.read(ack_read, 1)
            if acknowledge and ack == b"1" and isinstance(payload, dict):
                Path(str(payload["env"]["HERMES_ACK_GATE"])).touch()  # type: ignore[index]
            _stdout, stderr = process.communicate(timeout=8)
            return (
                subprocess.CompletedProcess(command, process.returncode, b"", stderr),
                ack,
                process.pid,
            )
        finally:
            os.close(ack_read)
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)

    def test_marker_failure_prevents_hermes_exec(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload, marker_path, started, _gate = self._payload(Path(tmp))
            marker_path.parent.write_text("not a directory\n", encoding="utf-8")

            result, ack, _pid = self._run_launcher(payload)

            self.assertNotEqual(0, result.returncode)
            self.assertEqual(b"", ack)
            self.assertFalse(started.exists())

    def test_successful_launcher_acknowledges_then_execs_same_pid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload, marker_path, started, _gate = self._payload(Path(tmp))

            result, ack, launched_pid = self._run_launcher(payload)

            self.assertEqual(0, result.returncode, result.stderr.decode("utf-8", errors="replace"))
            self.assertEqual(b"1", ack)
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
            observed = json.loads(started.read_text(encoding="utf-8"))
            self.assertEqual(launched_pid, marker["pid"])
            self.assertEqual(launched_pid, observed["pid"])
            self.assertEqual(3, marker["schema"])
            self.assertEqual("a" * 32, marker["operation_id"])
            self.assertEqual(1, marker["desired_revision"])
            self.assertEqual(_command_fingerprint(marker["argv"]), marker["command_fingerprint"])
            self.assertIn("started_at", marker)
            self.assertIn("readiness_probe", marker)
            self.assertEqual(0o600, marker_path.stat().st_mode & 0o777)
            self.assertNotIn("private-launch-secret", marker_path.read_text(encoding="utf-8"))
            self.assertNotIn("private-launch-secret", "\0".join(observed["argv"]))

    def test_launcher_waits_for_publication_lock_before_marker_and_ack(self) -> None:
        from zeus import gateway_launcher

        self.assertTrue(
            hasattr(gateway_launcher, "marker_publication_lock"),
            "shared marker publication lock is unavailable",
        )
        marker_publication_lock = gateway_launcher.marker_publication_lock

        with tempfile.TemporaryDirectory() as tmp:
            payload, marker_path, started, gate = self._payload(Path(tmp))
            profile_path = Path(str(payload["profile_path"]))
            payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            payload_read, payload_write = os.pipe()
            ack_read, ack_write = os.pipe()
            process: subprocess.Popen[bytes] | None = None

            try:
                with marker_publication_lock(profile_path, timeout_seconds=1):
                    process = subprocess.Popen(  # nosec B603
                        [
                            sys.executable,
                            "-m",
                            "zeus.gateway_launcher",
                            str(payload_read),
                            str(ack_write),
                        ],
                        pass_fds=(payload_read, ack_write),
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE,
                    )
                    os.close(payload_read)
                    payload_read = -1
                    os.close(ack_write)
                    ack_write = -1
                    os.write(payload_write, payload_bytes)
                    os.close(payload_write)
                    payload_write = -1

                    readable, _writable, _errors = select.select([ack_read], [], [], 0.2)
                    self.assertEqual([], readable)
                    self.assertFalse(marker_path.exists())

                self.assertEqual(b"1", os.read(ack_read, 1))
                gate.touch()
                assert process is not None
                _stdout, stderr = process.communicate(timeout=8)
                self.assertEqual(0, process.returncode, stderr.decode(errors="replace"))
                self.assertTrue(marker_path.exists())
                self.assertTrue(started.exists())
            finally:
                for fd in (payload_read, payload_write, ack_read, ack_write):
                    if fd >= 0:
                        with contextlib.suppress(OSError):
                            os.close(fd)
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)

    def test_publication_lock_rejects_unsafe_files_and_times_out(self) -> None:
        from zeus import gateway_launcher

        self.assertTrue(
            hasattr(gateway_launcher, "marker_publication_lock"),
            "shared marker publication lock is unavailable",
        )
        marker_publication_lock = gateway_launcher.marker_publication_lock
        lock_name = gateway_launcher.MARKER_PUBLICATION_LOCK_NAME

        with tempfile.TemporaryDirectory() as tmp:
            payload, _marker_path, _started, _gate = self._payload(Path(tmp))
            profile_path = Path(str(payload["profile_path"]))
            lock_path = profile_path / lock_name
            target = profile_path / "lock-target"
            target.write_text("", encoding="utf-8")

            lock_path.symlink_to(target)
            with (
                self.assertRaisesRegex(
                    gateway_launcher.LaunchPayloadError, "lock.*safely|lock.*regular"
                ),
                marker_publication_lock(profile_path, timeout_seconds=0.05),
            ):
                self.fail("unsafe publication lock was acquired")
            lock_path.unlink()

            target.chmod(0o640)
            target_mode = target.stat().st_mode & 0o777
            os.link(target, lock_path)
            with (
                self.assertRaisesRegex(gateway_launcher.LaunchPayloadError, "link"),
                marker_publication_lock(profile_path, timeout_seconds=0.05),
            ):
                self.fail("hard-linked publication lock was acquired")
            self.assertEqual(target_mode, target.stat().st_mode & 0o777)
            lock_path.unlink()
            target.unlink()

            with marker_publication_lock(profile_path, timeout_seconds=0.5):
                started_at = time.monotonic()
                with (
                    self.assertRaisesRegex(gateway_launcher.LaunchPayloadError, "timed out"),
                    marker_publication_lock(profile_path, timeout_seconds=0.05),
                ):
                    self.fail("contended publication lock was acquired")
                self.assertLess(time.monotonic() - started_at, 0.5)

    def test_publication_lock_closes_profile_fd_when_unlock_fails(self) -> None:
        from zeus import gateway_launcher

        if os.name != "posix":
            self.skipTest("POSIX descriptor locking is required")
        with tempfile.TemporaryDirectory() as tmp:
            payload, _marker_path, _started, _gate = self._payload(Path(tmp))
            profile_path = Path(str(payload["profile_path"]))
            lock = gateway_launcher.marker_publication_lock(
                profile_path,
                timeout_seconds=0.5,
            )
            held = lock.__enter__()
            profile_fd = held._profile_fd
            lock_fd = held._lock_fd
            real_flock = gateway_launcher.fcntl.flock

            def fail_unlock(fd: int, operation: int) -> None:
                if operation == gateway_launcher.fcntl.LOCK_UN:
                    raise OSError("injected unlock failure")
                real_flock(fd, operation)

            try:
                with (
                    patch.object(gateway_launcher.fcntl, "flock", side_effect=fail_unlock),
                    self.assertRaisesRegex(OSError, "injected unlock failure"),
                ):
                    lock.__exit__(None, None, None)

                closed: list[bool] = []
                for fd in (lock_fd, profile_fd):
                    try:
                        os.fstat(fd)
                    except OSError:
                        closed.append(True)
                    else:
                        closed.append(False)
                self.assertEqual([True, True], closed)
            finally:
                for fd in (lock_fd, profile_fd):
                    with contextlib.suppress(OSError):
                        os.close(fd)

    def test_concurrent_launchers_publish_one_marker_and_exec_one_gateway(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload, marker_path, started, gate = self._payload(Path(tmp))
            payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            processes: list[subprocess.Popen[bytes]] = []
            ack_reads: list[int] = []

            try:
                for _index in range(2):
                    payload_read, payload_write = os.pipe()
                    ack_read, ack_write = os.pipe()
                    process = subprocess.Popen(  # nosec B603
                        [
                            sys.executable,
                            "-m",
                            "zeus.gateway_launcher",
                            str(payload_read),
                            str(ack_write),
                        ],
                        pass_fds=(payload_read, ack_write),
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE,
                    )
                    os.close(payload_read)
                    os.close(ack_write)
                    os.write(payload_write, payload_bytes)
                    os.close(payload_write)
                    processes.append(process)
                    ack_reads.append(ack_read)

                acknowledgments = [os.read(fd, 1) for fd in ack_reads]
                if b"1" in acknowledgments:
                    gate.touch()
                results = [process.communicate(timeout=8) for process in processes]

                self.assertEqual(1, acknowledgments.count(b"1"))
                successful = [
                    process
                    for process, (_stdout, stderr) in zip(processes, results, strict=True)
                    if process.returncode == 0
                ]
                self.assertEqual(
                    1,
                    len(successful),
                    [stderr.decode("utf-8", errors="replace") for _stdout, stderr in results],
                )
                marker = json.loads(marker_path.read_text(encoding="utf-8"))
                observed = json.loads(started.read_text(encoding="utf-8"))
                self.assertEqual(successful[0].pid, marker["pid"])
                self.assertEqual(successful[0].pid, observed["pid"])
                self.assertEqual([], list(marker_path.parent.glob(".zeus-gateway.pid.json.*.tmp")))
            finally:
                for fd in ack_reads:
                    with contextlib.suppress(OSError):
                        os.close(fd)
                for process in processes:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=2)

    def test_launcher_preserves_an_existing_marker_without_acknowledging(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload, marker_path, started, _gate = self._payload(Path(tmp))
            marker_path.parent.mkdir(mode=0o700)
            existing = b"existing marker must remain byte-for-byte\n"
            marker_path.write_bytes(existing)

            result, ack, _pid = self._run_launcher(payload)

            self.assertNotEqual(0, result.returncode)
            self.assertEqual(b"", ack)
            self.assertEqual(existing, marker_path.read_bytes())
            self.assertFalse(started.exists())
            self.assertEqual([], list(marker_path.parent.glob(".zeus-gateway.pid.json.*.tmp")))

    def test_launcher_rejects_malformed_and_oversize_payloads(self) -> None:
        for name, payload in (
            ("malformed", b"{not-json"),
            ("oversize", b"{" + b" " * (1024 * 1024) + b"}"),
        ):
            with self.subTest(name=name):
                result, ack, _pid = self._run_launcher(payload)
                self.assertNotEqual(0, result.returncode)
                self.assertEqual(b"", ack)

    def test_launcher_rejects_invalid_fd_arguments(self) -> None:
        commands = (
            [sys.executable, "-m", "zeus.gateway_launcher"],
            [sys.executable, "-m", "zeus.gateway_launcher", "-1", "4"],
            [sys.executable, "-m", "zeus.gateway_launcher", "3", "3"],
            [sys.executable, "-m", "zeus.gateway_launcher", "payload", "4"],
            [sys.executable, "-m", "zeus.gateway_launcher", "999999", "999998"],
            [sys.executable, "-m", "zeus.gateway_launcher", "3", "4", "extra"],
        )
        for command in commands:
            with self.subTest(command=command):
                result = subprocess.run(  # nosec B603
                    command,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=5,
                )
                self.assertNotEqual(0, result.returncode)

    def test_launcher_rejects_invalid_command_environment_and_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, _marker_path, started, _gate = self._payload(root)
            cases: list[tuple[str, object]] = []

            invalid_argv = json.loads(json.dumps(base))
            invalid_argv["argv"] = "not-a-list"
            cases.append(("argv-type", invalid_argv))

            nul_argv = json.loads(json.dumps(base))
            nul_argv["argv"][0] += "\0"
            cases.append(("argv-nul", nul_argv))

            invalid_env = json.loads(json.dumps(base))
            invalid_env["env"] = ["PATH=/bin"]
            cases.append(("env-type", invalid_env))

            missing_hermes_home = json.loads(json.dumps(base))
            del missing_hermes_home["env"]["HERMES_HOME"]
            cases.append(("missing-hermes-home", missing_hermes_home))

            mismatched_hermes_home = json.loads(json.dumps(base))
            mismatched_hermes_home["env"]["HERMES_HOME"] = str(root / "different-hermes")
            cases.append(("mismatched-hermes-home", mismatched_hermes_home))

            nul_env = json.loads(json.dumps(base))
            nul_env["env"]["PATH"] = "/bin\0/tmp"
            cases.append(("env-nul", nul_env))

            outside_marker = json.loads(json.dumps(base))
            outside_marker["marker_path"] = str(root / "outside.json")
            cases.append(("marker-boundary", outside_marker))

            traversal = json.loads(json.dumps(base))
            profile = Path(str(base["profile_path"]))
            traversal_profile = profile.parent / ".." / "profiles" / profile.name
            traversal["profile_path"] = str(traversal_profile)
            traversal["marker_path"] = str(traversal_profile / "logs/zeus-gateway.pid.json")
            cases.append(("profile-traversal", traversal))

            for name, payload in cases:
                with self.subTest(name=name):
                    started.unlink(missing_ok=True)
                    result, ack, _pid = self._run_launcher(payload)
                    self.assertNotEqual(0, result.returncode)
                    self.assertEqual(b"", ack)
                    self.assertFalse(started.exists())

    def test_launcher_rejects_symlinked_profile_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            payload, _marker_path, started, _gate = self._payload(root)
            real_hermes = root / "hermes"
            linked_hermes = root / "linked-hermes"
            linked_hermes.symlink_to(real_hermes, target_is_directory=True)
            linked_profile = linked_hermes / "profiles" / "coder"
            payload["profile_path"] = str(linked_profile)
            payload["marker_path"] = str(linked_profile / "logs" / "zeus-gateway.pid.json")
            payload["env"]["HERMES_HOME"] = str(linked_hermes)  # type: ignore[index]

            result, ack, _pid = self._run_launcher(payload)

            self.assertNotEqual(0, result.returncode)
            self.assertEqual(b"", ack)
            self.assertFalse(started.exists())

    def test_profile_open_rejects_leaf_replacement_between_validation_and_open(self) -> None:
        from zeus.gateway_launcher import LaunchPayloadError, _open_profile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile = root / "hermes" / "profiles" / "coder"
            profile.mkdir(parents=True)
            profile = profile.resolve()
            replacement = root / "replacement"
            replacement.mkdir()
            displaced = root / "displaced"
            real_open = os.open
            swapped = False

            def racing_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
                nonlocal swapped
                if not swapped and (Path(str(path)) == profile or path == "coder"):
                    profile.rename(displaced)
                    replacement.rename(profile)
                    swapped = True
                return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

            with (
                patch("zeus.gateway_launcher.os.open", side_effect=racing_open),
                self.assertRaises(LaunchPayloadError),
            ):
                fd = _open_profile(profile)
                os.close(fd)

            self.assertTrue(swapped)

    def test_profile_chain_rejects_final_symlink_appearing_during_missing_lookup(self) -> None:
        from zeus.gateway_launcher import LaunchPayloadError, _open_profile_chain

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            profile = root / "hermes" / "profiles" / "coder"
            profile.parent.mkdir(parents=True)
            external = root / "external-profile"
            external.mkdir()
            real_stat = os.stat
            appeared = False

            def racing_stat(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                *,
                dir_fd: int | None = None,
                follow_symlinks: bool = True,
            ) -> os.stat_result:
                nonlocal appeared
                if path == profile.name and dir_fd is not None and not appeared:
                    try:
                        return real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
                    except FileNotFoundError:
                        profile.symlink_to(external, target_is_directory=True)
                        appeared = True
                        raise
                return real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

            with (
                patch("zeus.gateway_launcher.os.stat", side_effect=racing_stat),
                self.assertRaisesRegex(LaunchPayloadError, "appeared"),
            ):
                _open_profile_chain(profile)

            self.assertTrue(appeared)
            self.assertTrue(profile.is_symlink())

    def test_profile_chain_rejects_intermediate_symlink_appearing_during_missing_lookup(
        self,
    ) -> None:
        from zeus.gateway_launcher import LaunchPayloadError, _open_profile_chain

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            hermes = root / "hermes"
            hermes.mkdir()
            profiles = hermes / "profiles"
            profile = profiles / "coder"
            external = root / "external-profiles"
            (external / "coder").mkdir(parents=True)
            real_stat = os.stat
            appeared = False

            def racing_stat(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                *,
                dir_fd: int | None = None,
                follow_symlinks: bool = True,
            ) -> os.stat_result:
                nonlocal appeared
                if path == profiles.name and dir_fd is not None and not appeared:
                    try:
                        return real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
                    except FileNotFoundError:
                        profiles.symlink_to(external, target_is_directory=True)
                        appeared = True
                        raise
                return real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

            with (
                patch("zeus.gateway_launcher.os.stat", side_effect=racing_stat),
                self.assertRaisesRegex(LaunchPayloadError, "appeared"),
            ):
                _open_profile_chain(profile)

            self.assertTrue(appeared)
            self.assertTrue(profiles.is_symlink())

    def test_directory_open_closes_new_descriptor_when_post_open_fstat_fails(self) -> None:
        from zeus.gateway_launcher import LaunchPayloadError, _open_directory_at

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            child = root / "child"
            child.mkdir()
            parent_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            real_open = os.open
            real_fstat = os.fstat
            opened_fd: int | None = None

            def tracking_open(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal opened_fd
                descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                if path == child.name and dir_fd == parent_fd:
                    opened_fd = descriptor
                return descriptor

            def failing_fstat(fd: int) -> os.stat_result:
                if fd == opened_fd:
                    raise OSError(errno.EIO, "injected directory fstat failure")
                return real_fstat(fd)

            try:
                with (
                    patch("zeus.gateway_launcher.os.open", side_effect=tracking_open),
                    patch("zeus.gateway_launcher.os.fstat", side_effect=failing_fstat),
                    self.assertRaises(LaunchPayloadError),
                ):
                    _open_directory_at(parent_fd, child.name)
            finally:
                os.close(parent_fd)

            self.assertIsNotNone(opened_fd)
            with self.assertRaises(OSError):
                os.fstat(opened_fd)  # type: ignore[arg-type]

    def test_marker_open_closes_new_descriptor_when_post_open_fstat_fails(self) -> None:
        from zeus.gateway_launcher import LaunchPayloadError, _open_regular_marker

        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp) / "logs"
            logs.mkdir()
            marker = logs / "zeus-gateway.pid.json"
            marker.write_text("{}", encoding="utf-8")
            logs_fd = os.open(logs, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            real_open = os.open
            real_fstat = os.fstat
            opened_fd: int | None = None

            def tracking_open(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal opened_fd
                descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                if path == marker.name and dir_fd == logs_fd:
                    opened_fd = descriptor
                return descriptor

            def failing_fstat(fd: int) -> os.stat_result:
                if fd == opened_fd:
                    raise OSError(errno.EIO, "injected marker fstat failure")
                return real_fstat(fd)

            try:
                with (
                    patch("zeus.gateway_launcher.os.open", side_effect=tracking_open),
                    patch("zeus.gateway_launcher.os.fstat", side_effect=failing_fstat),
                    self.assertRaises(LaunchPayloadError),
                ):
                    _open_regular_marker(logs_fd)
            finally:
                os.close(logs_fd)

            self.assertIsNotNone(opened_fd)
            with self.assertRaises(OSError):
                os.fstat(opened_fd)  # type: ignore[arg-type]

    def test_ack_failure_removes_only_the_owned_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload, marker_path, started, _gate = self._payload(root)
            payload_read, payload_write = os.pipe()
            read_only_ack = os.open(root / "read-only-ack", os.O_RDONLY | os.O_CREAT, 0o600)
            command = [
                sys.executable,
                "-m",
                "zeus.gateway_launcher",
                str(payload_read),
                str(read_only_ack),
            ]
            process = subprocess.Popen(  # nosec B603
                command,
                pass_fds=(payload_read, read_only_ack),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            os.close(payload_read)
            os.close(read_only_ack)
            os.write(payload_write, json.dumps(payload).encode("utf-8"))
            os.close(payload_write)
            _stdout, stderr = process.communicate(timeout=8)

            self.assertNotEqual(0, process.returncode, stderr.decode("utf-8", errors="replace"))
            self.assertFalse(marker_path.exists())
            self.assertFalse(started.exists())

    def test_cleanup_preserves_a_marker_owned_by_another_operation(self) -> None:
        from zeus.gateway_launcher import remove_marker_if_owned

        with tempfile.TemporaryDirectory() as tmp:
            payload, marker_path, _started, _gate = self._payload(Path(tmp))
            marker_path.parent.mkdir(mode=0o700)
            other = dict(payload["marker"])  # type: ignore[arg-type]
            other.update({"pid": os.getpid(), "operation_id": "b" * 32, "started_at": time.time()})
            marker_path.write_text(json.dumps(other), encoding="utf-8")

            removed = remove_marker_if_owned(
                Path(str(payload["profile_path"])),
                operation_id="a" * 32,
                desired_revision=1,
                pid=os.getpid(),
                command_fingerprint=str(other["command_fingerprint"]),
            )

            self.assertFalse(removed)
            self.assertEqual("b" * 32, json.loads(marker_path.read_text())["operation_id"])

    def test_cleanup_preserves_marker_without_exact_launcher_ownership_schema(self) -> None:
        from zeus.gateway_launcher import remove_marker_if_owned

        with tempfile.TemporaryDirectory() as tmp:
            payload, marker_path, _started, _gate = self._payload(Path(tmp))
            marker_path.parent.mkdir(mode=0o700)
            unproven = dict(payload["marker"])  # type: ignore[arg-type]
            unproven.update({"schema": 2, "pid": os.getpid(), "started_at": time.time()})
            marker_path.write_text(json.dumps(unproven), encoding="utf-8")

            removed = remove_marker_if_owned(
                Path(str(payload["profile_path"])),
                operation_id="a" * 32,
                desired_revision=1,
                pid=os.getpid(),
                command_fingerprint=str(unproven["command_fingerprint"]),
            )

            self.assertFalse(removed)
            self.assertEqual(2, json.loads(marker_path.read_text())["schema"])

    def test_cleanup_preserves_duplicate_key_and_extra_field_markers(self) -> None:
        from zeus.gateway_launcher import remove_marker_if_owned

        with tempfile.TemporaryDirectory() as tmp:
            payload, marker_path, _started, _gate = self._payload(Path(tmp))
            marker_path.parent.mkdir(mode=0o700)
            marker = dict(payload["marker"])  # type: ignore[arg-type]
            marker.update({"pid": os.getpid(), "started_at": time.time()})
            encoded = json.dumps(marker, separators=(",", ":"))
            duplicate = encoded.replace(
                '"operation_id":"' + "a" * 32 + '"',
                '"operation_id":"' + "b" * 32 + '","operation_id":"' + "a" * 32 + '"',
            )
            extra = dict(marker)
            extra["unexpected"] = True

            for name, contents in (
                ("duplicate", duplicate),
                ("extra", json.dumps(extra, separators=(",", ":"))),
            ):
                with self.subTest(name=name):
                    marker_path.write_text(contents, encoding="utf-8")

                    removed = remove_marker_if_owned(
                        Path(str(payload["profile_path"])),
                        operation_id="a" * 32,
                        desired_revision=1,
                        pid=os.getpid(),
                        command_fingerprint=str(marker["command_fingerprint"]),
                    )

                    self.assertFalse(removed)
                    self.assertEqual(contents, marker_path.read_text(encoding="utf-8"))

    def test_cleanup_preserves_nonregular_and_malformed_marker_entries_in_place(self) -> None:
        from zeus.gateway_launcher import remove_marker_if_owned

        with tempfile.TemporaryDirectory() as tmp:
            payload, marker_path, _started, _gate = self._payload(Path(tmp))
            marker_path.parent.mkdir(mode=0o700)
            profile_path = Path(str(payload["profile_path"]))
            fingerprint = str(payload["marker"]["command_fingerprint"])  # type: ignore[index]

            marker_path.mkdir()
            removed = remove_marker_if_owned(
                profile_path,
                operation_id="a" * 32,
                desired_revision=1,
                pid=os.getpid(),
                command_fingerprint=fingerprint,
            )
            self.assertFalse(removed)
            self.assertTrue(marker_path.is_dir())

            marker_path.rmdir()
            malformed = b'{"schema":3,"operation_id":'
            marker_path.write_bytes(malformed)
            removed = remove_marker_if_owned(
                profile_path,
                operation_id="a" * 32,
                desired_revision=1,
                pid=os.getpid(),
                command_fingerprint=fingerprint,
            )
            self.assertFalse(removed)
            self.assertEqual(malformed, marker_path.read_bytes())

    def test_cleanup_preserves_replacement_directory_during_owned_marker_race(self) -> None:
        from zeus.gateway_launcher import MARKER_NAME, remove_marker_if_owned

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload, marker_path, _started, _gate = self._payload(root)
            marker_path.parent.mkdir(mode=0o700)
            marker = dict(payload["marker"])  # type: ignore[arg-type]
            marker.update({"pid": os.getpid(), "started_at": time.time()})
            marker_path.write_text(json.dumps(marker), encoding="utf-8")
            displaced = root / "displaced-owned-marker"
            replacement = root / "replacement-directory"
            replacement.mkdir()
            from zeus.gateway_launcher import _open_regular_marker

            swapped = False

            def racing_open(logs_fd: int) -> tuple[int, os.stat_result]:
                nonlocal swapped
                result = _open_regular_marker(logs_fd)
                if not swapped:
                    marker_path.rename(displaced)
                    replacement.rename(marker_path)
                    swapped = True
                return result

            with patch("zeus.gateway_launcher._open_regular_marker", side_effect=racing_open):
                removed = remove_marker_if_owned(
                    Path(str(payload["profile_path"])),
                    operation_id="a" * 32,
                    desired_revision=1,
                    pid=os.getpid(),
                    command_fingerprint=str(marker["command_fingerprint"]),
                )

            self.assertTrue(swapped)
            self.assertFalse(removed)
            self.assertTrue(marker_path.is_dir())
            self.assertEqual([], list(marker_path.parent.glob(f".{MARKER_NAME}.cleanup.*")))


def create_v4_database(database: Path, rows: list[tuple[str, str, str]]) -> None:
    with closing(sqlite3.connect(database)) as conn:
        conn.execute(V4_BOTS_SCHEMA)
        conn.execute(V4_LIFECYCLE_SCHEMA)
        conn.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
        conn.execute("INSERT INTO schema_version VALUES (4)")
        conn.execute(
            """
            CREATE TABLE idempotency_records (
                key_hash TEXT PRIMARY KEY,
                request_hash TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('in_progress', 'completed')),
                owner_instance_id TEXT NOT NULL,
                response_status INTEGER NULL,
                response_json TEXT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )
        updated_at = "2026-07-12T10:00:00+00:00"
        for index, (bot_id, status, policy) in enumerate(rows, start=1):
            conn.execute(
                """
                INSERT INTO bots (
                    bot_id, template_id, display_name, profile_path, status,
                    restart_policy, created_at, updated_at
                ) VALUES (?, 'coding-bot', ?, ?, ?, ?, ?, ?)
                """,
                (
                    bot_id,
                    bot_id.title(),
                    f"profiles/{bot_id}",
                    status,
                    policy,
                    updated_at,
                    updated_at,
                ),
            )
            cursor = conn.execute(
                """
                INSERT INTO lifecycle_events (
                    bot_id, operation_id, occurred_at, source, action, outcome,
                    status_before, status_after, reason
                ) VALUES (?, ?, ?, 'migration', 'migration.snapshot', 'success', ?, ?, 'v4')
                """,
                (bot_id, f"{index:032x}", updated_at, status, status),
            )
            conn.execute(
                "UPDATE bots SET last_event_id = ? WHERE bot_id = ?",
                (cursor.lastrowid, bot_id),
            )
        conn.commit()


class CrashRecoveryStateTests(unittest.TestCase):
    def test_v4_statuses_map_to_expected_desired_state(self) -> None:
        statuses = ("running", "starting", "failed", "unknown", "stopped")
        policies = ("manual", "on-failure")
        rows = [
            (
                f"{status.replace('unknown', 'unclear')}-{policy.replace('-failure', '')}",
                status,
                policy,
            )
            for status in statuses
            for policy in policies
        ]
        expected = {
            bot_id: (
                "running"
                if status in {"running", "starting"}
                or (status in {"failed", "unknown"} and policy == "on-failure")
                else "stopped"
            )
            for bot_id, status, policy in rows
        }

        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "zeus.db"
            create_v4_database(database, rows)

            StateStore(database).migrate()

            with closing(sqlite3.connect(database)) as conn:
                conn.row_factory = sqlite3.Row
                migrated = conn.execute(
                    """
                    SELECT bot_id, desired_state, desired_revision, desired_updated_at,
                           pending_operation_id, pending_action, pending_since, last_event_id
                    FROM bots ORDER BY bot_id
                    """
                ).fetchall()
                events = conn.execute(
                    """
                    SELECT event_id, bot_id, operation_id, occurred_at, source, action, outcome,
                           details_json
                    FROM lifecycle_events WHERE operation_id = 'migration-v5' ORDER BY event_id
                    """
                ).fetchall()

            self.assertEqual(expected, {row["bot_id"]: row["desired_state"] for row in migrated})
            self.assertTrue(all(row["desired_revision"] == 0 for row in migrated))
            self.assertTrue(
                all(row["desired_updated_at"] == "2026-07-12T10:00:00+00:00" for row in migrated)
            )
            self.assertTrue(
                all(
                    row["pending_operation_id"] is None
                    and row["pending_action"] is None
                    and row["pending_since"] is None
                    for row in migrated
                )
            )
            self.assertEqual(len(rows), len(events))
            self.assertTrue(all(row["source"] == "migration" for row in events))
            self.assertTrue(
                all(row["action"] == "migration.desired_state_snapshot" for row in events)
            )
            self.assertTrue(all(row["outcome"] == "success" for row in events))
            self.assertTrue(
                all(row["occurred_at"] == "2026-07-12T10:00:00+00:00" for row in events)
            )
            event_ids = {row["bot_id"]: row["event_id"] for row in events}
            self.assertEqual(event_ids, {row["bot_id"]: row["last_event_id"] for row in migrated})

    def test_v5_constraints_enforce_desired_and_pending_invariants(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord("coder", "coding-bot", "Coder", str(Path(tmp) / "profiles/coder"))
            )
            invalid_updates = (
                "UPDATE bots SET desired_state = 'paused' WHERE bot_id = 'coder'",
                "UPDATE bots SET desired_revision = -1 WHERE bot_id = 'coder'",
                "UPDATE bots SET pending_action = 'delete', pending_operation_id = 'a', "
                "pending_since = 'now' WHERE bot_id = 'coder'",
                "UPDATE bots SET pending_action = 'start' WHERE bot_id = 'coder'",
            )
            with closing(store.connect()) as conn:
                for statement in invalid_updates:
                    with (
                        self.subTest(statement=statement),
                        self.assertRaises(sqlite3.IntegrityError),
                    ):
                        conn.execute(statement)

    def test_v4_to_v5_migration_failure_rolls_back_version_columns_and_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "zeus.db"
            create_v4_database(database, [("coder", "running", "manual")])
            with closing(sqlite3.connect(database)) as conn:
                conn.execute(
                    """
                    CREATE TRIGGER bots_desired_intent_reject_partial_update
                    BEFORE UPDATE ON bots
                    BEGIN
                        SELECT 1;
                    END
                    """
                )
                conn.commit()

            with self.assertRaises(sqlite3.DatabaseError):
                StateStore(database).migrate()

            with closing(sqlite3.connect(database)) as conn:
                version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
                columns = {row[1] for row in conn.execute("PRAGMA table_info(bots)")}
                events = conn.execute("SELECT COUNT(*) FROM lifecycle_events").fetchone()[0]
            self.assertEqual(4, version)
            self.assertNotIn("desired_state", columns)
            self.assertEqual(1, events)

    def test_fresh_v6_database_is_idempotent_and_serializes_only_public_desired_fields(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "zeus.db")
            store.init()
            store.init()
            store.migrate()
            record = BotRecord(
                "coder",
                "coding-bot",
                "Coder",
                str(Path(tmp) / "profiles/coder"),
                status=BotStatus.running,
                desired_state=models.DesiredState.running,
            )
            store.upsert_bot(record)

            loaded = store.get_bot("coder")
            assert loaded is not None
            payload = loaded.to_dict()
            with closing(store.connect()) as conn:
                version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
                triggers = {
                    row[0]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type = 'trigger' AND name LIKE 'bots_desired_%'"
                    )
                }

            self.assertEqual(6, version)
            self.assertEqual("running", payload["desired_state"])
            self.assertIs(payload["converged"], True)
            self.assertNotIn("desired_revision", payload)
            self.assertNotIn("pending_operation_id", payload)
            self.assertGreaterEqual(len(triggers), 2)
            self.assertFalse(
                BotRecord(
                    "coder",
                    "coding-bot",
                    "Coder",
                    "profiles/coder",
                    status=BotStatus.starting,
                    desired_state=models.DesiredState.running,
                ).converged
            )

    def test_intent_methods_are_atomic_correlated_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord("coder", "coding-bot", "Coder", str(Path(tmp) / "profiles/coder"))
            )

            begun = store.begin_lifecycle_intent(
                "coder", action="start", operation_id="a" * 32, source="cli"
            )
            self.assertEqual(models.DesiredState.running, begun.desired_state)
            self.assertEqual(1, begun.desired_revision)
            self.assertEqual("a" * 32, begun.pending_operation_id)
            self.assertEqual("start", begun.pending_action)

            with self.assertRaisesRegex(RuntimeError, "does not match"):
                store.complete_lifecycle_intent(
                    "coder",
                    action="start",
                    operation_id="b" * 32,
                    desired_revision=1,
                    status=BotStatus.running,
                    pid=1234,
                    source="cli",
                )
            still_pending = store.get_bot("coder")
            assert still_pending is not None
            self.assertEqual("a" * 32, still_pending.pending_operation_id)
            self.assertEqual(BotStatus.stopped, still_pending.status)

            completed = store.complete_lifecycle_intent(
                "coder",
                action="start",
                operation_id="a" * 32,
                desired_revision=1,
                status=BotStatus.running,
                pid=1234,
                source="cli",
            )
            self.assertTrue(completed.converged)
            self.assertIsNone(completed.pending_operation_id)
            self.assertEqual(1234, completed.pid)

            restarted = store.begin_lifecycle_intent(
                "coder", action="restart", operation_id="c" * 32, source="api", request_id="d" * 32
            )
            self.assertEqual(models.DesiredState.running, restarted.desired_state)
            self.assertEqual(2, restarted.desired_revision)
            cleared = store.clear_stale_intent(
                "coder",
                action="restart",
                operation_id="c" * 32,
                desired_revision=2,
                source="recovery",
                reason="no owned process marker",
            )
            self.assertEqual(models.DesiredState.running, cleared.desired_state)
            self.assertIsNone(cleared.pending_action)

            actions = [
                event.action
                for event in reversed(store.list_lifecycle_events("coder", limit=20, before=None))
            ]
            self.assertEqual(
                [
                    "bot.start.intent",
                    "bot.start.complete",
                    "bot.restart.intent",
                    "bot.restart.intent.clear",
                ],
                actions,
            )

    def test_intent_action_mismatch_preserves_projection_event_and_pending_state(self) -> None:
        for operation in ("complete", "clear"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as tmp:
                store = StateStore(Path(tmp) / "zeus.db")
                store.init()
                store.upsert_bot(
                    BotRecord("coder", "coding-bot", "Coder", str(Path(tmp) / "profiles/coder"))
                )
                store.begin_lifecycle_intent(
                    "coder", action="start", operation_id="a" * 32, source="cli"
                )
                before = store.get_bot("coder")
                before_events = store.list_lifecycle_events("coder", limit=10, before=None)

                with self.assertRaisesRegex(RuntimeError, "does not match"):
                    if operation == "complete":
                        store.complete_lifecycle_intent(
                            "coder",
                            action="stop",
                            operation_id="a" * 32,
                            desired_revision=1,
                            status=BotStatus.stopped,
                            pid=None,
                            source="cli",
                        )
                    else:
                        store.clear_stale_intent(
                            "coder",
                            action="stop",
                            operation_id="a" * 32,
                            desired_revision=1,
                            source="recovery",
                            reason="injected action mismatch",
                        )

                after = store.get_bot("coder")
                self.assertEqual(before, after)
                self.assertEqual(
                    before_events,
                    store.list_lifecycle_events("coder", limit=10, before=None),
                )
                assert after is not None
                self.assertEqual("a" * 32, after.pending_operation_id)
                self.assertEqual("start", after.pending_action)

    def test_successful_intent_completion_rejects_incompatible_terminal_state(self) -> None:
        invalid_completions = (
            ("stop", BotStatus.running, 1234),
            ("stop", BotStatus.stopped, 1234),
            ("start", BotStatus.stopped, None),
            ("start", BotStatus.running, 0),
            ("restart", BotStatus.failed, None),
        )
        for action, status, pid in invalid_completions:
            with (
                self.subTest(action=action, status=status, pid=pid),
                tempfile.TemporaryDirectory() as tmp,
            ):
                store = StateStore(Path(tmp) / "zeus.db")
                store.init()
                store.upsert_bot(
                    BotRecord("coder", "coding-bot", "Coder", str(Path(tmp) / "profiles/coder"))
                )
                store.begin_lifecycle_intent(
                    "coder", action=action, operation_id="a" * 32, source="cli"
                )

                with self.assertRaisesRegex(ValueError, "terminal state"):
                    store.complete_lifecycle_intent(
                        "coder",
                        action=action,
                        operation_id="a" * 32,
                        desired_revision=1,
                        status=status,
                        pid=pid,
                        source="cli",
                    )

                loaded = store.get_bot("coder")
                assert loaded is not None
                self.assertEqual("a" * 32, loaded.pending_operation_id)
                self.assertEqual(action, loaded.pending_action)
                self.assertEqual(
                    [f"bot.{action}.intent"],
                    [
                        event.action
                        for event in store.list_lifecycle_events("coder", limit=10, before=None)
                    ],
                )

    def test_failed_intent_completion_records_safe_failure_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord("coder", "coding-bot", "Coder", str(Path(tmp) / "profiles/coder"))
            )
            store.begin_lifecycle_intent(
                "coder", action="start", operation_id="a" * 32, source="cli"
            )

            completed = store.complete_lifecycle_intent(
                "coder",
                action="start",
                operation_id="a" * 32,
                desired_revision=1,
                status=BotStatus.failed,
                pid=None,
                source="cli",
                outcome="failure",
                error_code="registration_failed",
                error_message="marker publication failed API_KEY=not-a-real-secret",
            )

            self.assertEqual(BotStatus.failed, completed.status)
            self.assertIsNone(completed.pending_operation_id)
            event = store.list_lifecycle_events("coder", limit=1, before=None)[0]
            self.assertEqual("bot.start.complete", event.action)
            self.assertEqual("failure", event.outcome)
            self.assertEqual("registration_failed", event.error_code)
            self.assertEqual("marker publication failed API_KEY=[redacted]", event.error_message)

    def test_intent_event_failure_rolls_back_projection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord("coder", "coding-bot", "Coder", str(Path(tmp) / "profiles/coder"))
            )

            with (
                patch.object(
                    store, "_insert_lifecycle_event", side_effect=sqlite3.DatabaseError("boom")
                ),
                self.assertRaisesRegex(sqlite3.DatabaseError, "boom"),
            ):
                store.begin_lifecycle_intent(
                    "coder", action="stop", operation_id="a" * 32, source="cli"
                )

            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertEqual(0, loaded.desired_revision)
            self.assertIsNone(loaded.pending_operation_id)
            self.assertEqual([], store.list_lifecycle_events("coder", limit=10, before=None))

    def test_intent_completion_and_clear_failures_roll_back_projection(self) -> None:
        for operation in ("complete", "clear"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as tmp:
                store = StateStore(Path(tmp) / "zeus.db")
                store.init()
                store.upsert_bot(
                    BotRecord("coder", "coding-bot", "Coder", str(Path(tmp) / "profiles/coder"))
                )
                store.begin_lifecycle_intent(
                    "coder", action="start", operation_id="a" * 32, source="cli"
                )

                with (
                    patch.object(
                        store, "_insert_lifecycle_event", side_effect=sqlite3.DatabaseError("boom")
                    ),
                    self.assertRaisesRegex(sqlite3.DatabaseError, "boom"),
                ):
                    if operation == "complete":
                        store.complete_lifecycle_intent(
                            "coder",
                            action="start",
                            operation_id="a" * 32,
                            desired_revision=1,
                            status=BotStatus.running,
                            pid=1234,
                            source="cli",
                        )
                    else:
                        store.clear_stale_intent(
                            "coder",
                            action="start",
                            operation_id="a" * 32,
                            desired_revision=1,
                            source="recovery",
                            reason="injected rollback",
                        )

                loaded = store.get_bot("coder")
                assert loaded is not None
                self.assertEqual(BotStatus.stopped, loaded.status)
                self.assertEqual("a" * 32, loaded.pending_operation_id)
                self.assertEqual("start", loaded.pending_action)
                self.assertEqual(1, loaded.desired_revision)
                self.assertEqual(
                    ["bot.start.intent"],
                    [
                        event.action
                        for event in store.list_lifecycle_events("coder", limit=10, before=None)
                    ],
                )

    def test_intent_validation_rejects_untrusted_correlation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "zeus.db")
            store.init()
            store.upsert_bot(BotRecord("coder", "coding-bot", "Coder", "profiles/coder"))

            invalid = (
                {"action": "delete", "operation_id": "a" * 32, "source": "cli"},
                {"action": "start", "operation_id": "operator-picked", "source": "cli"},
                {"action": "start", "operation_id": "a" * 32, "source": "api"},
                {
                    "action": "start",
                    "operation_id": "a" * 32,
                    "source": "cli",
                    "request_id": "b" * 32,
                },
            )
            for values in invalid:
                with self.subTest(values=values), self.assertRaises(ValueError):
                    store.begin_lifecycle_intent("coder", **values)


class SupervisorIntentRecoveryTests(unittest.TestCase):
    def _fixture(
        self,
        root: Path,
        *,
        desired: DesiredState = DesiredState.stopped,
        pid_alive_fn=None,
        proc_start_fingerprint_reader=None,
    ) -> tuple[StateStore, Supervisor]:
        hermes_root = root / "hermes"
        profile = hermes_root / "profiles" / "coder"
        profile.mkdir(parents=True)
        (profile / ".env").write_text("", encoding="utf-8")
        hermes = root / "bin" / "hermes"
        hermes.parent.mkdir(parents=True)
        hermes.write_text("#!/bin/sh\n", encoding="utf-8")
        hermes.chmod(0o755)
        store = StateStore(root / "zeus.db")
        store.init()
        store.upsert_bot(
            BotRecord(
                "coder",
                "coding-bot",
                "Coder",
                str(profile),
                desired_state=desired,
            )
        )
        return store, Supervisor(
            store,
            str(hermes),
            hermes_root,
            popen_factory=_RecoveryPopen,
            pid_alive_fn=pid_alive_fn or (lambda pid: True),
            cmdline_reader=lambda pid: [
                str(hermes.resolve()),
                "-p",
                "coder",
                "gateway",
                "run",
            ],
            proc_start_fingerprint_reader=(
                proc_start_fingerprint_reader or (lambda pid: "test-start:4321")
            ),
            startup_grace_seconds=0,
        )

    def _runtime_marker(
        self,
        supervisor: Supervisor,
        *,
        operation_id: str = "a" * 32,
        desired_revision: int = 1,
        pid: int = 4321,
        proc_start_fingerprint: str | None = "test-start:4321",
    ) -> dict[str, object]:
        payload = supervisor.adapter.launcher_payload(
            "coder",
            operation_id=operation_id,
            desired_revision=desired_revision,
            readiness_probe=None,
        )
        marker = dict(payload["marker"])
        marker.update({"pid": pid, "started_at": time.time()})
        if proc_start_fingerprint is not None:
            marker["proc_start_fingerprint"] = proc_start_fingerprint
        return marker

    def _write_runtime_marker(
        self,
        supervisor: Supervisor,
        profile_path: str,
        marker: dict[str, object],
    ) -> Path:
        marker_path = supervisor.pid_marker_path(profile_path)
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        marker_path.write_text(json.dumps(marker), encoding="utf-8")
        return marker_path

    def _compat_marker(
        self,
        supervisor: Supervisor,
        *,
        schema: int | None,
        pid: int = 4321,
    ) -> dict[str, object]:
        resolved_hermes = supervisor._resolved_hermes_bin()
        assert resolved_hermes is not None
        marker: dict[str, object] = {
            "pid": pid,
            "argv": [resolved_hermes, "-p", "coder", "gateway", "run"],
            "started_at": time.time(),
            "proc_start_fingerprint": f"test-start:{pid}",
        }
        if schema == 2:
            marker.update(
                {
                    "schema": 2,
                    "bot_id": "coder",
                    "component": "gateway",
                    "action": "run",
                    "resolved_hermes_bin": resolved_hermes,
                }
            )
        return marker

    def _begin_restart_over_compat_gateway(
        self,
        store: StateStore,
        supervisor: Supervisor,
        *,
        schema: int | None,
    ) -> tuple[BotRecord, Path]:
        record = store.get_bot("coder")
        assert record is not None
        store.upsert_bot(
            replace(
                record,
                status=BotStatus.running,
                pid=4321,
                desired_state=DesiredState.running,
                desired_revision=1,
            )
        )
        marker_path = self._write_runtime_marker(
            supervisor,
            record.profile_path,
            self._compat_marker(supervisor, schema=schema),
        )
        pending = store.begin_lifecycle_intent(
            "coder",
            action="restart",
            operation_id="b" * 32,
            source="cli",
        )
        return pending, marker_path

    def _begin_restart_over_running_gateway(
        self,
        store: StateStore,
        supervisor: Supervisor,
        *,
        marker_revision: int = 1,
        marker_operation_id: str = "a" * 32,
    ) -> tuple[BotRecord, Path]:
        record = store.get_bot("coder")
        assert record is not None
        store.upsert_bot(
            replace(
                record,
                status=BotStatus.running,
                pid=4321,
                desired_state=DesiredState.running,
                desired_revision=1,
            )
        )
        marker = self._runtime_marker(
            supervisor,
            operation_id=marker_operation_id,
            desired_revision=marker_revision,
        )
        marker_path = self._write_runtime_marker(supervisor, record.profile_path, marker)
        pending = store.begin_lifecycle_intent(
            "coder",
            action="restart",
            operation_id="b" * 32,
            source="cli",
        )
        return pending, marker_path

    def test_start_and_stop_effects_observe_committed_lifecycle_intents(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(Path(tmp))
            observed: list[tuple[str | None, int, str]] = []

            def spawn_after_intent(*args: object, **kwargs: object) -> _RecoveryPopen:
                pending = store.get_bot("coder")
                assert pending is not None
                event = store.list_lifecycle_events("coder", limit=1, before=None)[0]
                observed.append((pending.pending_action, pending.desired_revision, event.action))
                return _RecoveryPopen(*args, **kwargs)

            supervisor.popen_factory = spawn_after_intent
            _RecoveryPopen.launches.clear()

            started = supervisor.start("coder")

            self.assertEqual(BotStatus.running, started.status)
            self.assertEqual([("start", 1, "bot.start.intent")], observed)

        with tempfile.TemporaryDirectory() as tmp:
            alive = True
            store, supervisor = self._fixture(
                Path(tmp),
                desired=DesiredState.running,
                pid_alive_fn=lambda pid: alive,
            )
            record = store.get_bot("coder")
            assert record is not None
            running = replace(
                record,
                status=BotStatus.running,
                pid=4321,
                desired_revision=1,
            )
            store.upsert_bot(running)
            self._write_runtime_marker(
                supervisor,
                running.profile_path,
                self._runtime_marker(supervisor, desired_revision=1),
            )
            observed = []

            def signal_after_intent(pid: int, sent_signal: object) -> None:
                nonlocal alive
                pending = store.get_bot("coder")
                assert pending is not None
                event = store.list_lifecycle_events("coder", limit=1, before=None)[0]
                observed.append((pending.pending_action, pending.desired_revision, event.action))
                alive = False

            supervisor.kill_fn = signal_after_intent
            supervisor.stop_grace_seconds = 0

            stopped = supervisor.stop("coder")

            self.assertEqual(BotStatus.stopped, stopped.status)
            self.assertEqual([("stop", 2, "bot.stop.intent")], observed)

    def test_pending_compat_restart_fails_closed_without_side_effects(self) -> None:
        for schema in (2, None):
            for alive in (True, False):
                with (
                    self.subTest(schema=schema, alive=alive),
                    tempfile.TemporaryDirectory() as tmp,
                ):
                    store, supervisor = self._fixture(
                        Path(tmp),
                        pid_alive_fn=lambda pid, alive=alive: alive,
                    )
                    _pending, marker_path = self._begin_restart_over_compat_gateway(
                        store,
                        supervisor,
                        schema=schema,
                    )
                    before = store.get_bot("coder")
                    assert before is not None
                    marker_before = marker_path.read_bytes()
                    _RecoveryPopen.launches.clear()

                    with (
                        patch.object(supervisor, "kill_fn") as kill,
                        patch.object(supervisor, "popen_factory") as popen,
                        patch.object(supervisor, "_update_lifecycle") as update,
                    ):
                        result = supervisor.reconcile("coder")[0]

                    kill.assert_not_called()
                    popen.assert_not_called()
                    update.assert_not_called()
                    self.assertEqual(BotStatus.failed, result.status)
                    self.assertIn("manual process resolution", result.message)
                    self.assertEqual(marker_before, marker_path.read_bytes())
                    self.assertEqual(before, store.get_bot("coder"))
                    self.assertEqual([], _RecoveryPopen.launches)

    def test_pending_compat_restart_late_uncorrelated_publication_preserves_db(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(Path(tmp), pid_alive_fn=lambda pid: False)
            _pending, marker_path = self._begin_restart_over_compat_gateway(
                store,
                supervisor,
                schema=2,
            )
            before = store.get_bot("coder")
            assert before is not None
            replacement = self._runtime_marker(
                supervisor,
                operation_id="c" * 32,
                desired_revision=before.desired_revision,
                pid=9999,
                proc_start_fingerprint="test-start:9999",
            )
            original_read = supervisor._read_strict_runtime_marker

            def publish_after_detection(bot_id: str, profile_path: str) -> object:
                observed = original_read(bot_id, profile_path)
                marker_path.write_text(json.dumps(replacement), encoding="utf-8")
                return observed

            with (
                patch.object(
                    supervisor,
                    "_read_strict_runtime_marker",
                    side_effect=publish_after_detection,
                ),
                patch.object(supervisor, "kill_fn") as kill,
                patch.object(supervisor, "popen_factory") as popen,
                patch.object(supervisor, "_update_lifecycle") as update,
            ):
                result = supervisor.reconcile("coder")[0]

            kill.assert_not_called()
            popen.assert_not_called()
            update.assert_not_called()
            self.assertEqual(BotStatus.failed, result.status)
            self.assertEqual(9999, json.loads(marker_path.read_text())["pid"])
            self.assertEqual(before, store.get_bot("coder"))

    def test_pending_compat_restart_never_adopts_replaced_correlated_publication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(Path(tmp), pid_alive_fn=lambda pid: pid == 9876)
            _pending, marker_path = self._begin_restart_over_compat_gateway(
                store,
                supervisor,
                schema=None,
            )
            before = store.get_bot("coder")
            assert before is not None
            correlated = self._runtime_marker(
                supervisor,
                operation_id="b" * 32,
                desired_revision=before.desired_revision,
                pid=9876,
                proc_start_fingerprint="test-start:9876",
            )
            unrelated = self._runtime_marker(
                supervisor,
                operation_id="c" * 32,
                desired_revision=before.desired_revision,
                pid=9999,
                proc_start_fingerprint="test-start:9999",
            )
            original_read = supervisor._read_strict_runtime_marker

            def replace_before_automatic_action(bot_id: str, profile_path: str) -> object:
                observed = original_read(bot_id, profile_path)
                marker_path.write_text(json.dumps(correlated), encoding="utf-8")
                marker_path.write_text(json.dumps(unrelated), encoding="utf-8")
                return observed

            with (
                patch.object(
                    supervisor,
                    "_read_strict_runtime_marker",
                    side_effect=replace_before_automatic_action,
                ),
                patch.object(supervisor, "_complete_started_intent") as adopt,
                patch.object(supervisor, "kill_fn") as kill,
                patch.object(supervisor, "popen_factory") as popen,
                patch.object(supervisor, "_update_lifecycle") as update,
            ):
                result = supervisor.reconcile("coder")[0]

            adopt.assert_not_called()
            kill.assert_not_called()
            popen.assert_not_called()
            update.assert_not_called()
            self.assertEqual(BotStatus.failed, result.status)
            self.assertEqual(9999, json.loads(marker_path.read_text())["pid"])
            self.assertEqual(before, store.get_bot("coder"))

    def test_intent_failure_happens_before_spawn(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(Path(tmp))
            calls = 0

            def unexpected_spawn(*args: object, **kwargs: object) -> object:
                nonlocal calls
                calls += 1
                raise AssertionError("spawn must follow the committed intent")

            supervisor.popen_factory = unexpected_spawn
            with (
                patch.object(
                    store,
                    "begin_lifecycle_intent",
                    side_effect=sqlite3.DatabaseError("intent unavailable"),
                ),
                self.assertRaisesRegex(sqlite3.DatabaseError, "intent unavailable"),
            ):
                supervisor.start("coder")

            self.assertEqual(0, calls)

    def test_restart_keeps_desired_running_before_any_spawn(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(Path(tmp))
            observed: list[tuple[DesiredState, str | None]] = []

            def inspect_spawn(*args: object, **kwargs: object) -> object:
                record = store.get_bot("coder")
                assert record is not None
                observed.append((record.desired_state, record.pending_action))
                raise FileNotFoundError("injected launch failure")

            supervisor.popen_factory = inspect_spawn
            supervisor.restart("coder")

            self.assertEqual([(DesiredState.running, "restart")], observed)
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertIs(DesiredState.running, loaded.desired_state)

    def test_status_never_spawns_to_enforce_desired_running(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _store, supervisor = self._fixture(Path(tmp), desired=DesiredState.running)
            with patch.object(supervisor, "popen_factory") as popen:
                result = supervisor.status("coder")
            popen.assert_not_called()
            self.assertEqual(BotStatus.failed, result.status)
            self.assertIn("action required", result.message)

    def test_reconcile_crash_before_spawn_reuses_pending_correlation_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _interrupted_supervisor = self._fixture(root)
            _RecoveryPopen.launches.clear()
            pending = store.begin_lifecycle_intent(
                "coder",
                action="start",
                operation_id="a" * 32,
                source="cli",
            )

            hermes = root / "bin" / "hermes"
            hermes_root = root / "hermes"
            recovered_store = StateStore(root / "zeus.db")
            recovered_store.init()
            supervisor = Supervisor(
                recovered_store,
                str(hermes),
                hermes_root,
                popen_factory=_RecoveryPopen,
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: [
                    str(hermes.resolve()),
                    "-p",
                    "coder",
                    "gateway",
                    "run",
                ],
                proc_start_fingerprint_reader=lambda pid: "test-start:4321",
                startup_grace_seconds=0,
            )

            result = supervisor.reconcile("coder")[0]

            self.assertEqual(BotStatus.running, result.status)
            self.assertEqual(1, len(_RecoveryPopen.launches))
            marker = _RecoveryPopen.launches[0]["marker"]
            self.assertEqual("a" * 32, marker["operation_id"])
            self.assertEqual(pending.desired_revision, marker["desired_revision"])
            loaded = recovered_store.get_bot("coder")
            assert loaded is not None
            self.assertIsNone(loaded.pending_operation_id)

    def test_pending_start_recovery_waits_for_original_publication_and_adopts_once(self) -> None:
        from zeus import gateway_launcher

        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(Path(tmp), desired=DesiredState.running)
            pending = store.begin_lifecycle_intent(
                "coder",
                action="start",
                operation_id="a" * 32,
                source="cli",
            )
            marker = self._runtime_marker(
                supervisor,
                operation_id="a" * 32,
                desired_revision=pending.desired_revision,
            )
            profile_path = Path(pending.profile_path).resolve()
            marker_path = supervisor.pid_marker_path(pending.profile_path)
            publication_locked = threading.Event()
            publish_original = threading.Event()
            recovery_done = threading.Event()
            publication_errors: list[BaseException] = []
            recovery_errors: list[BaseException] = []
            recovery_results: list[object] = []

            def original_launcher() -> None:
                try:
                    with gateway_launcher.marker_publication_lock(
                        profile_path,
                        timeout_seconds=1,
                    ):
                        publication_locked.set()
                        if not publish_original.wait(timeout=2):
                            raise RuntimeError("test publication release timed out")
                        gateway_launcher._publish_marker(profile_path, marker)
                except BaseException as exc:
                    publication_errors.append(exc)

            def recover() -> None:
                try:
                    recovery_results.append(supervisor.reconcile("coder")[0])
                except BaseException as exc:
                    recovery_errors.append(exc)
                finally:
                    recovery_done.set()

            _RecoveryPopen.launches.clear()
            publisher = threading.Thread(target=original_launcher)
            publisher.start()
            self.assertTrue(publication_locked.wait(timeout=1), publication_errors)
            recovery = threading.Thread(target=recover)
            recovery.start()
            recovery_waited = not recovery_done.wait(timeout=0.15)
            launches_while_waiting = list(_RecoveryPopen.launches)
            publish_original.set()
            publisher.join(timeout=2)
            recovery.join(timeout=2)

            self.assertTrue(recovery_waited, recovery_errors)
            self.assertEqual([], launches_while_waiting)
            self.assertFalse(publisher.is_alive())
            self.assertFalse(recovery.is_alive())
            self.assertEqual([], publication_errors)
            self.assertEqual([], recovery_errors)
            self.assertEqual([], _RecoveryPopen.launches)
            self.assertEqual(1, len(recovery_results))
            self.assertEqual(BotStatus.running, recovery_results[0].status)
            self.assertEqual(marker, json.loads(marker_path.read_text()))
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertEqual(4321, loaded.pid)
            self.assertIsNone(loaded.pending_operation_id)

    def test_pending_restart_stops_then_launches_on_next_reconcile_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            alive = True

            def is_alive(pid: int) -> bool:
                return alive

            store, supervisor = self._fixture(Path(tmp), pid_alive_fn=is_alive)
            pending, marker_path = self._begin_restart_over_running_gateway(store, supervisor)
            supervisor.stop_grace_seconds = 0
            sent: list[tuple[int, object]] = []

            def stop_gateway(pid: int, sig: object) -> None:
                nonlocal alive
                sent.append((pid, sig))
                alive = False

            supervisor.kill_fn = stop_gateway
            _RecoveryPopen.launches.clear()

            stopped = supervisor.reconcile("coder")[0]

            self.assertEqual([(4321, signal.SIGTERM)], sent)
            self.assertEqual(BotStatus.starting, stopped.status)
            self.assertIn("restart", stopped.message)
            self.assertEqual([], _RecoveryPopen.launches)
            self.assertFalse(marker_path.exists())
            after_stop = store.get_bot("coder")
            assert after_stop is not None
            self.assertEqual(BotStatus.stopped, after_stop.status)
            self.assertIsNone(after_stop.pid)
            self.assertEqual("restart", after_stop.pending_action)
            self.assertEqual("b" * 32, after_stop.pending_operation_id)
            self.assertEqual(pending.desired_revision, after_stop.desired_revision)
            self.assertIs(DesiredState.running, after_stop.desired_state)

            alive = True
            launched = supervisor.reconcile("coder")[0]
            stable = supervisor.reconcile("coder")[0]

            self.assertEqual(BotStatus.running, launched.status)
            self.assertEqual(BotStatus.running, stable.status)
            self.assertEqual(1, len(_RecoveryPopen.launches))
            launched_marker = _RecoveryPopen.launches[0]["marker"]
            self.assertEqual("b" * 32, launched_marker["operation_id"])
            self.assertEqual(pending.desired_revision, launched_marker["desired_revision"])

    def test_pending_restart_timeout_preserves_old_process_then_retries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            alive = True
            store, supervisor = self._fixture(Path(tmp), pid_alive_fn=lambda pid: alive)
            pending, marker_path = self._begin_restart_over_running_gateway(store, supervisor)
            supervisor.stop_grace_seconds = 0
            sent: list[tuple[int, object]] = []
            supervisor.kill_fn = lambda pid, sig: sent.append((pid, sig))
            _RecoveryPopen.launches.clear()

            timed_out = supervisor.reconcile("coder")[0]

            self.assertEqual(BotStatus.failed, timed_out.status)
            self.assertIn("did not stop", timed_out.message)
            self.assertEqual([(4321, signal.SIGTERM)], sent)
            self.assertTrue(marker_path.exists())
            after_timeout = store.get_bot("coder")
            assert after_timeout is not None
            self.assertEqual(4321, after_timeout.pid)
            self.assertEqual("restart", after_timeout.pending_action)
            self.assertEqual("b" * 32, after_timeout.pending_operation_id)
            self.assertEqual([], _RecoveryPopen.launches)

            def stop_on_retry(pid: int, sig: object) -> None:
                nonlocal alive
                sent.append((pid, sig))
                alive = False

            supervisor.kill_fn = stop_on_retry
            retried = supervisor.reconcile("coder")[0]

            self.assertEqual(BotStatus.starting, retried.status)
            self.assertEqual(2, len(sent))
            self.assertFalse(marker_path.exists())
            after_retry = store.get_bot("coder")
            assert after_retry is not None
            self.assertIsNone(after_retry.pid)
            self.assertEqual("restart", after_retry.pending_action)
            self.assertEqual(pending.desired_revision, after_retry.desired_revision)
            self.assertEqual([], _RecoveryPopen.launches)

    def test_pending_restart_replacement_before_term_is_never_signaled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(Path(tmp), pid_alive_fn=lambda pid: True)
            pending, marker_path = self._begin_restart_over_running_gateway(store, supervisor)
            replacement = self._runtime_marker(
                supervisor,
                operation_id="b" * 32,
                desired_revision=pending.desired_revision,
            )
            original_read = supervisor._read_strict_runtime_marker
            reads = 0

            def replace_before_authorization(bot_id: str, profile_path: str) -> object:
                nonlocal reads
                reads += 1
                if reads == 2:
                    marker_path.write_text(json.dumps(replacement), encoding="utf-8")
                return original_read(bot_id, profile_path)

            _RecoveryPopen.launches.clear()
            with (
                patch.object(
                    supervisor,
                    "_read_strict_runtime_marker",
                    side_effect=replace_before_authorization,
                ),
                patch.object(supervisor, "kill_fn") as kill,
            ):
                result = supervisor.reconcile("coder")[0]

            kill.assert_not_called()
            self.assertEqual(BotStatus.failed, result.status)
            self.assertIn("action required", result.message)
            self.assertEqual("b" * 32, json.loads(marker_path.read_text())["operation_id"])
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertEqual(4321, loaded.pid)
            self.assertEqual("b" * 32, loaded.pending_operation_id)
            self.assertEqual([], _RecoveryPopen.launches)

    def test_stop_compat_replacement_before_term_is_never_signaled(self) -> None:
        for schema in (2, None):
            with self.subTest(schema=schema), tempfile.TemporaryDirectory() as tmp:
                store, supervisor = self._fixture(
                    Path(tmp),
                    desired=DesiredState.running,
                    pid_alive_fn=lambda pid: True,
                )
                record = store.get_bot("coder")
                assert record is not None
                store.upsert_bot(
                    replace(
                        record,
                        status=BotStatus.running,
                        pid=4321,
                        desired_state=DesiredState.running,
                    )
                )
                marker_path = self._write_runtime_marker(
                    supervisor,
                    record.profile_path,
                    self._runtime_marker(supervisor),
                )
                replacement = self._compat_marker(supervisor, schema=schema)
                original_read = supervisor._read_strict_runtime_marker
                reads = 0

                def replace_after_precheck(
                    bot_id: str,
                    profile_path: str,
                    *,
                    marker_path: Path = marker_path,
                    replacement: dict[str, object] = replacement,
                    original_read: object = original_read,
                ) -> object:
                    nonlocal reads
                    reads += 1
                    if reads == 2:
                        marker_path.write_text(json.dumps(replacement), encoding="utf-8")
                    assert callable(original_read)
                    return original_read(bot_id, profile_path)

                supervisor.stop_grace_seconds = 0
                with (
                    patch.object(
                        supervisor,
                        "_read_strict_runtime_marker",
                        side_effect=replace_after_precheck,
                    ),
                    patch.object(supervisor, "kill_fn") as kill,
                ):
                    result = supervisor.stop("coder")

                kill.assert_not_called()
                self.assertEqual(BotStatus.failed, result.status)
                self.assertIn("action required", result.message)
                self.assertEqual(replacement, json.loads(marker_path.read_text()))
                loaded = store.get_bot("coder")
                assert loaded is not None
                self.assertEqual(4321, loaded.pid)
                self.assertEqual("stop", loaded.pending_action)

    def test_pending_restart_replacement_before_kill_is_never_killed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(Path(tmp), pid_alive_fn=lambda pid: True)
            pending, marker_path = self._begin_restart_over_running_gateway(store, supervisor)
            replacement = self._runtime_marker(
                supervisor,
                operation_id="b" * 32,
                desired_revision=pending.desired_revision,
            )
            supervisor.stop_grace_seconds = 0
            supervisor.kill_after_timeout = True
            sent: list[tuple[int, object]] = []

            def replace_after_term(pid: int, sig: object) -> None:
                sent.append((pid, sig))
                if sig == signal.SIGTERM:
                    marker_path.write_text(json.dumps(replacement), encoding="utf-8")

            supervisor.kill_fn = replace_after_term
            _RecoveryPopen.launches.clear()

            result = supervisor.reconcile("coder")[0]

            self.assertEqual([(4321, signal.SIGTERM)], sent)
            self.assertEqual(BotStatus.failed, result.status)
            self.assertIn("action required", result.message)
            self.assertEqual("b" * 32, json.loads(marker_path.read_text())["operation_id"])
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertEqual(4321, loaded.pid)
            self.assertEqual("b" * 32, loaded.pending_operation_id)
            self.assertEqual([], _RecoveryPopen.launches)

    def test_stop_compat_replacement_before_kill_is_never_killed(self) -> None:
        for schema in (2, None):
            with self.subTest(schema=schema), tempfile.TemporaryDirectory() as tmp:
                store, supervisor = self._fixture(
                    Path(tmp),
                    desired=DesiredState.running,
                    pid_alive_fn=lambda pid: True,
                )
                record = store.get_bot("coder")
                assert record is not None
                store.upsert_bot(
                    replace(
                        record,
                        status=BotStatus.running,
                        pid=4321,
                        desired_state=DesiredState.running,
                    )
                )
                marker_path = self._write_runtime_marker(
                    supervisor,
                    record.profile_path,
                    self._runtime_marker(supervisor),
                )
                replacement = self._compat_marker(supervisor, schema=schema)
                supervisor.stop_grace_seconds = 0
                supervisor.kill_after_timeout = True
                sent: list[tuple[int, object]] = []

                def replace_after_term(
                    pid: int,
                    sig: object,
                    *,
                    sent: list[tuple[int, object]] = sent,
                    marker_path: Path = marker_path,
                    replacement: dict[str, object] = replacement,
                ) -> None:
                    sent.append((pid, sig))
                    if sig == signal.SIGTERM:
                        marker_path.write_text(json.dumps(replacement), encoding="utf-8")

                supervisor.kill_fn = replace_after_term
                result = supervisor.stop("coder", kill_after_timeout=True)

                self.assertEqual([(4321, signal.SIGTERM)], sent)
                self.assertEqual(BotStatus.failed, result.status)
                self.assertIn("action required", result.message)
                self.assertEqual(replacement, json.loads(marker_path.read_text()))
                loaded = store.get_bot("coder")
                assert loaded is not None
                self.assertEqual(4321, loaded.pid)
                self.assertEqual("stop", loaded.pending_action)

    def test_pending_restart_replacement_before_cleanup_is_preserved(self) -> None:
        from zeus.gateway_launcher import _remove_marker_if_owned_locked as real_remove_marker

        with tempfile.TemporaryDirectory() as tmp:
            alive = True
            store, supervisor = self._fixture(Path(tmp), pid_alive_fn=lambda pid: alive)
            _pending, marker_path = self._begin_restart_over_running_gateway(store, supervisor)
            replacement = self._runtime_marker(
                supervisor,
                operation_id="b" * 32,
                desired_revision=2,
            )
            supervisor.stop_grace_seconds = 0
            sent: list[tuple[int, object]] = []

            def stop_after_term(pid: int, sig: object) -> None:
                nonlocal alive
                sent.append((pid, sig))
                alive = False

            def replace_before_cleanup(
                profile_path: Path,
                *,
                operation_id: str,
                desired_revision: int,
                pid: int,
                command_fingerprint: str,
                expected_proc_start_fingerprint: object,
            ) -> bool:
                marker_path.write_text(json.dumps(replacement), encoding="utf-8")
                return real_remove_marker(
                    profile_path,
                    operation_id=operation_id,
                    desired_revision=desired_revision,
                    pid=pid,
                    command_fingerprint=command_fingerprint,
                    expected_proc_start_fingerprint=expected_proc_start_fingerprint,
                )

            supervisor.kill_fn = stop_after_term
            _RecoveryPopen.launches.clear()
            with patch(
                "zeus.supervisor._remove_marker_if_owned_locked",
                side_effect=replace_before_cleanup,
            ):
                result = supervisor.reconcile("coder")[0]

            self.assertEqual([(4321, signal.SIGTERM)], sent)
            self.assertEqual(BotStatus.failed, result.status)
            self.assertIn("action required", result.message)
            self.assertEqual(replacement, json.loads(marker_path.read_text()))
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertEqual(4321, loaded.pid)
            self.assertEqual("b" * 32, loaded.pending_operation_id)
            self.assertEqual([], _RecoveryPopen.launches)

    def _assert_cleanup_serializes_cooperative_publication(self, effect: str) -> None:
        from zeus import gateway_launcher

        self.assertTrue(
            hasattr(gateway_launcher, "marker_publication_lock"),
            "shared marker publication lock is unavailable",
        )
        marker_publication_lock = gateway_launcher.marker_publication_lock
        publish_marker = gateway_launcher._publish_marker

        with tempfile.TemporaryDirectory() as tmp:
            alive = effect not in {
                "dead",
                "pending_stop",
                "pending_restart",
                "reconcile",
                "status",
            }

            def is_alive(pid: int) -> bool:
                return alive

            store, supervisor = self._fixture(
                Path(tmp),
                desired=(
                    DesiredState.stopped
                    if effect in {"reconcile", "status"}
                    else DesiredState.running
                ),
                pid_alive_fn=is_alive,
            )
            record = store.get_bot("coder")
            assert record is not None
            running = replace(
                record,
                status=BotStatus.running,
                pid=4321,
                desired_state=(
                    DesiredState.stopped
                    if effect in {"reconcile", "status"}
                    else DesiredState.running
                ),
                desired_revision=1,
            )
            store.upsert_bot(running)
            marker_path = self._write_runtime_marker(
                supervisor,
                running.profile_path,
                self._runtime_marker(supervisor),
            )
            replacement = self._runtime_marker(
                supervisor,
                operation_id="d" * 32,
                desired_revision=1 if effect in {"reconcile", "status"} else 2,
            )
            supervisor.stop_grace_seconds = 0
            sent: list[tuple[int, object]] = []

            def stop_after_signal(pid: int, sig: object) -> None:
                nonlocal alive
                sent.append((pid, sig))
                if (effect in {"term", "restart"} and sig == signal.SIGTERM) or (
                    effect == "kill" and sig == signal.SIGKILL
                ):
                    alive = False

            supervisor.kill_fn = stop_after_signal
            _RecoveryPopen.launches.clear()

            transition_entered = threading.Event()
            release_transition = threading.Event()
            transition_completed = threading.Event()
            publication_started = threading.Event()
            publication_completed = threading.Event()
            operation_results: list[object] = []
            operation_errors: list[BaseException] = []
            publication_errors: list[BaseException] = []

            if effect in {"term", "kill", "dead", "pending_stop"}:
                transition_target = store
                transition_name = "complete_lifecycle_intent"
            else:
                transition_target = supervisor
                transition_name = "_update_lifecycle"
            original_transition = getattr(transition_target, transition_name)

            def blocked_transition(*args: object, **kwargs: object) -> object:
                transition_entered.set()
                if not release_transition.wait(timeout=2):
                    raise RuntimeError("test transition release timed out")
                result = original_transition(*args, **kwargs)
                transition_completed.set()
                return result

            def run_operation() -> None:
                try:
                    if effect == "restart":
                        context = supervisor._lifecycle_context("cli", None)
                        with supervisor.bot_lock("coder"), supervisor._bot_process_lock("coder"):
                            pending = store.begin_lifecycle_intent(
                                "coder",
                                action="restart",
                                operation_id=context.operation_id,
                                source=context.source,
                                reason="gateway restart requested",
                            )
                            operation_results.append(
                                supervisor._stop_record_effect(
                                    pending,
                                    context=context,
                                    complete_stop=False,
                                )
                            )
                    elif effect in {"pending_stop", "pending_restart"}:
                        pending_context = supervisor._lifecycle_context("cli", None)
                        with supervisor.bot_lock("coder"), supervisor._bot_process_lock("coder"):
                            store.begin_lifecycle_intent(
                                "coder",
                                action="stop" if effect == "pending_stop" else "restart",
                                operation_id=pending_context.operation_id,
                                source=pending_context.source,
                                reason="interrupted lifecycle operation",
                            )
                        operation_results.append(supervisor.reconcile("coder")[0])
                    elif effect == "reconcile":
                        operation_results.append(supervisor.reconcile("coder")[0])
                    elif effect == "status":
                        operation_results.append(supervisor.status("coder"))
                    else:
                        operation_results.append(
                            supervisor.stop("coder", kill_after_timeout=effect == "kill")
                        )
                except BaseException as exc:
                    operation_errors.append(exc)

            def publish_replacement() -> None:
                try:
                    profile_path = Path(running.profile_path).resolve()
                    publication_started.set()
                    with marker_publication_lock(profile_path, timeout_seconds=5):
                        publish_marker(profile_path, replacement)
                    publication_completed.set()
                except BaseException as exc:
                    publication_errors.append(exc)

            with patch.object(transition_target, transition_name, side_effect=blocked_transition):
                operation = threading.Thread(target=run_operation)
                operation.start()
                entered = transition_entered.wait(timeout=1)
                publisher: threading.Thread | None = None
                publisher_entered = False
                publication_blocked = False
                if entered:
                    publisher = threading.Thread(target=publish_replacement)
                    publisher.start()
                    publisher_entered = publication_started.wait(timeout=1)
                    if publisher_entered:
                        publication_blocked = not publication_completed.wait(timeout=0.15)
                release_transition.set()
                operation.join(timeout=2)
                if publisher is not None:
                    publisher.join(timeout=5)

            self.assertTrue(entered, operation_errors)
            self.assertTrue(publisher_entered, publication_errors)
            self.assertTrue(publication_blocked, publication_errors)
            self.assertFalse(operation.is_alive())
            self.assertEqual([], operation_errors)
            marker_after = json.loads(marker_path.read_text()) if marker_path.exists() else None
            self.assertEqual(
                [],
                publication_errors,
                (publication_errors, marker_after, operation_results),
            )
            self.assertTrue(transition_completed.is_set())
            self.assertTrue(publication_completed.is_set())

            expected_signals = (
                [signal.SIGTERM, signal.SIGKILL]
                if effect == "kill"
                else (
                    []
                    if effect in {"dead", "pending_stop", "pending_restart", "reconcile", "status"}
                    else [signal.SIGTERM]
                )
            )
            self.assertEqual(expected_signals, [sig for _pid, sig in sent])
            self.assertEqual(1, len(operation_results))
            result = operation_results[0]
            self.assertEqual(
                (
                    BotStatus.failed
                    if effect == "status"
                    else (BotStatus.starting if effect == "pending_restart" else BotStatus.stopped)
                ),
                result.status,
            )
            self.assertEqual(replacement, json.loads(marker_path.read_text()))
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertIsNone(loaded.pid)
            self.assertEqual(
                "restart" if effect in {"restart", "pending_restart"} else None,
                loaded.pending_action,
            )
            self.assertEqual(
                effect in {"restart", "pending_restart"},
                loaded.pending_operation_id is not None,
            )
            self.assertEqual([], _RecoveryPopen.launches)

    def test_live_term_cleanup_serializes_cooperative_publication(self) -> None:
        self._assert_cleanup_serializes_cooperative_publication("term")

    def test_live_kill_cleanup_serializes_cooperative_publication(self) -> None:
        self._assert_cleanup_serializes_cooperative_publication("kill")

    def test_dead_stop_cleanup_serializes_cooperative_publication(self) -> None:
        self._assert_cleanup_serializes_cooperative_publication("dead")

    def test_restart_cleanup_serializes_cooperative_publication(self) -> None:
        self._assert_cleanup_serializes_cooperative_publication("restart")

    def test_status_cleanup_serializes_cooperative_publication(self) -> None:
        self._assert_cleanup_serializes_cooperative_publication("status")

    def test_pending_stop_cleanup_serializes_cooperative_publication(self) -> None:
        self._assert_cleanup_serializes_cooperative_publication("pending_stop")

    def test_pending_restart_cleanup_serializes_cooperative_publication(self) -> None:
        self._assert_cleanup_serializes_cooperative_publication("pending_restart")

    def test_reconcile_cleanup_serializes_cooperative_publication(self) -> None:
        self._assert_cleanup_serializes_cooperative_publication("reconcile")

    def _assert_uncooperative_generation_replacement_preserved(self, effect: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            alive = effect != "dead"
            marker_path: Path
            replacement: dict[str, object]

            def is_alive(pid: int) -> bool:
                nonlocal alive
                if effect == "dead":
                    marker_path.write_text(json.dumps(replacement), encoding="utf-8")
                    alive = False
                return alive

            store, supervisor = self._fixture(
                Path(tmp),
                desired=DesiredState.running,
                pid_alive_fn=is_alive,
            )
            record = store.get_bot("coder")
            assert record is not None
            running = replace(
                record,
                status=BotStatus.running,
                pid=4321,
                desired_state=DesiredState.running,
                desired_revision=1,
            )
            store.upsert_bot(running)
            marker_path = self._write_runtime_marker(
                supervisor,
                running.profile_path,
                self._runtime_marker(supervisor),
            )
            replacement = self._runtime_marker(
                supervisor,
                operation_id="d" * 32,
                desired_revision=2,
            )
            supervisor.stop_grace_seconds = 0
            sent: list[tuple[int, object]] = []

            def replace_after_signal(pid: int, sig: object) -> None:
                nonlocal alive
                sent.append((pid, sig))
                if (effect in {"term", "restart"} and sig == signal.SIGTERM) or (
                    effect == "kill" and sig == signal.SIGKILL
                ):
                    marker_path.write_text(json.dumps(replacement), encoding="utf-8")
                    alive = False

            supervisor.kill_fn = replace_after_signal
            _RecoveryPopen.launches.clear()

            if effect == "restart":
                result = supervisor.restart("coder")
                expected_action = "restart"
            else:
                result = supervisor.stop("coder", kill_after_timeout=effect == "kill")
                expected_action = "stop"

            expected_signals = (
                [signal.SIGTERM, signal.SIGKILL]
                if effect == "kill"
                else ([] if effect == "dead" else [signal.SIGTERM])
            )
            self.assertEqual(expected_signals, [sig for _pid, sig in sent])
            self.assertEqual(BotStatus.failed, result.status)
            self.assertIn("action required", result.message)
            self.assertEqual(replacement, json.loads(marker_path.read_text()))
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertEqual(4321, loaded.pid)
            self.assertEqual(expected_action, loaded.pending_action)
            self.assertIsNotNone(loaded.pending_operation_id)
            self.assertEqual(2, loaded.desired_revision)
            self.assertEqual([], _RecoveryPopen.launches)

    def test_live_term_cleanup_preserves_uncooperative_replacement(self) -> None:
        self._assert_uncooperative_generation_replacement_preserved("term")

    def test_live_kill_cleanup_preserves_uncooperative_replacement(self) -> None:
        self._assert_uncooperative_generation_replacement_preserved("kill")

    def test_dead_stop_cleanup_preserves_uncooperative_replacement(self) -> None:
        self._assert_uncooperative_generation_replacement_preserved("dead")

    def test_restart_cleanup_preserves_uncooperative_replacement(self) -> None:
        self._assert_uncooperative_generation_replacement_preserved("restart")

    def test_status_missing_marker_clears_dead_nonpending_pid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(
                Path(tmp),
                desired=DesiredState.stopped,
                pid_alive_fn=lambda pid: False,
            )
            record = store.get_bot("coder")
            assert record is not None
            store.upsert_bot(
                replace(
                    record,
                    status=BotStatus.running,
                    pid=4321,
                    desired_revision=1,
                )
            )

            result = supervisor.status("coder")

            self.assertEqual(BotStatus.failed, result.status)
            self.assertNotIn("action required", result.message)
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertIsNone(loaded.pid)

    def test_status_dead_cleanup_rejects_compat_and_uncorrelated_schema3_markers(self) -> None:
        for name in ("compat", "uncorrelated"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                store, supervisor = self._fixture(
                    Path(tmp),
                    desired=DesiredState.stopped,
                    pid_alive_fn=lambda pid: False,
                )
                record = store.get_bot("coder")
                assert record is not None
                running = replace(
                    record,
                    status=BotStatus.running,
                    pid=4321,
                    desired_revision=1,
                )
                store.upsert_bot(running)
                marker = (
                    self._compat_marker(supervisor, schema=2)
                    if name == "compat"
                    else self._runtime_marker(supervisor, desired_revision=2)
                )
                marker_path = self._write_runtime_marker(
                    supervisor,
                    running.profile_path,
                    marker,
                )

                result = supervisor.status("coder")

                self.assertEqual(BotStatus.failed, result.status)
                self.assertIn("action required", result.message)
                self.assertEqual(marker, json.loads(marker_path.read_text()))
                loaded = store.get_bot("coder")
                assert loaded is not None
                self.assertEqual(4321, loaded.pid)

    def test_status_publication_lock_timeout_fails_closed(self) -> None:
        from zeus import gateway_launcher

        self.assertTrue(
            hasattr(gateway_launcher, "marker_publication_lock"),
            "shared marker publication lock is unavailable",
        )
        marker_publication_lock = gateway_launcher.marker_publication_lock

        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(
                Path(tmp),
                desired=DesiredState.stopped,
                pid_alive_fn=lambda pid: False,
            )
            record = store.get_bot("coder")
            assert record is not None
            running = replace(
                record,
                status=BotStatus.running,
                pid=4321,
                desired_revision=1,
            )
            store.upsert_bot(running)
            marker = self._runtime_marker(supervisor)
            marker_path = self._write_runtime_marker(supervisor, running.profile_path, marker)
            supervisor.lock_timeout_seconds = 0.05
            lock_acquired = threading.Event()
            release_lock = threading.Event()
            holder_errors: list[BaseException] = []

            def hold_lock() -> None:
                try:
                    with marker_publication_lock(
                        Path(running.profile_path).resolve(), timeout_seconds=1
                    ):
                        lock_acquired.set()
                        if not release_lock.wait(timeout=2):
                            raise RuntimeError("test lock release timed out")
                except BaseException as exc:
                    holder_errors.append(exc)

            holder = threading.Thread(target=hold_lock)
            holder.start()
            self.assertTrue(lock_acquired.wait(timeout=1), holder_errors)
            try:
                result = supervisor.status("coder")
            finally:
                release_lock.set()
                holder.join(timeout=2)

            self.assertEqual([], holder_errors)
            self.assertFalse(holder.is_alive())
            self.assertEqual(BotStatus.failed, result.status)
            self.assertIn("publication lock timed out", result.message)
            self.assertEqual(marker, json.loads(marker_path.read_text()))
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertEqual(4321, loaded.pid)

    def test_pending_restart_cleanup_pins_process_start_fingerprint(self) -> None:
        from zeus.gateway_launcher import _remove_marker_if_owned_locked as real_remove_marker

        with tempfile.TemporaryDirectory() as tmp:
            alive = True
            store, supervisor = self._fixture(Path(tmp), pid_alive_fn=lambda pid: alive)
            pending, marker_path = self._begin_restart_over_running_gateway(store, supervisor)
            replacement = self._runtime_marker(
                supervisor,
                operation_id="a" * 32,
                desired_revision=pending.desired_revision - 1,
                proc_start_fingerprint="replacement-start:4321",
            )
            supervisor.stop_grace_seconds = 0

            def stop_after_term(pid: int, sig: object) -> None:
                nonlocal alive
                alive = False

            def replace_start_identity_before_cleanup(
                profile_path: Path,
                *,
                operation_id: str,
                desired_revision: int,
                pid: int,
                command_fingerprint: str,
                expected_proc_start_fingerprint: object,
            ) -> bool:
                marker_path.write_text(json.dumps(replacement), encoding="utf-8")
                return real_remove_marker(
                    profile_path,
                    operation_id=operation_id,
                    desired_revision=desired_revision,
                    pid=pid,
                    command_fingerprint=command_fingerprint,
                    expected_proc_start_fingerprint=expected_proc_start_fingerprint,
                )

            supervisor.kill_fn = stop_after_term
            _RecoveryPopen.launches.clear()
            with patch(
                "zeus.supervisor._remove_marker_if_owned_locked",
                side_effect=replace_start_identity_before_cleanup,
            ):
                result = supervisor.reconcile("coder")[0]

            self.assertEqual(BotStatus.failed, result.status)
            self.assertIn("action required", result.message)
            stored_marker = json.loads(marker_path.read_text())
            self.assertEqual("replacement-start:4321", stored_marker["proc_start_fingerprint"])
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertEqual(4321, loaded.pid)
            self.assertEqual("b" * 32, loaded.pending_operation_id)
            self.assertEqual([], _RecoveryPopen.launches)

    def test_pending_restart_recovers_dead_old_process_before_launching(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            alive = False
            store, supervisor = self._fixture(Path(tmp), pid_alive_fn=lambda pid: alive)
            pending, marker_path = self._begin_restart_over_running_gateway(store, supervisor)
            _RecoveryPopen.launches.clear()

            with patch.object(supervisor, "kill_fn") as kill:
                recovered = supervisor.reconcile("coder")[0]

            kill.assert_not_called()
            self.assertEqual(BotStatus.starting, recovered.status)
            self.assertEqual([], _RecoveryPopen.launches)
            self.assertFalse(marker_path.exists())
            after_recovery = store.get_bot("coder")
            assert after_recovery is not None
            self.assertEqual(BotStatus.stopped, after_recovery.status)
            self.assertIsNone(after_recovery.pid)
            self.assertEqual("restart", after_recovery.pending_action)
            self.assertEqual("b" * 32, after_recovery.pending_operation_id)

            alive = True
            launched = supervisor.reconcile("coder")[0]

            self.assertEqual(BotStatus.running, launched.status)
            self.assertEqual(1, len(_RecoveryPopen.launches))
            launched_marker = _RecoveryPopen.launches[0]["marker"]
            self.assertEqual("b" * 32, launched_marker["operation_id"])
            self.assertEqual(pending.desired_revision, launched_marker["desired_revision"])

    def test_pending_restart_old_marker_mismatch_never_signals_or_launches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(Path(tmp), pid_alive_fn=lambda pid: True)
            self._begin_restart_over_running_gateway(
                store,
                supervisor,
                marker_revision=2,
                marker_operation_id="a" * 32,
            )
            _RecoveryPopen.launches.clear()

            with (
                patch.object(supervisor, "kill_fn") as kill,
                patch.object(supervisor, "popen_factory") as popen,
            ):
                result = supervisor.reconcile("coder")[0]

            kill.assert_not_called()
            popen.assert_not_called()
            self.assertEqual(BotStatus.failed, result.status)
            self.assertIn("action required", result.message)
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertEqual(4321, loaded.pid)
            self.assertEqual("restart", loaded.pending_action)
            self.assertEqual("b" * 32, loaded.pending_operation_id)

    def test_pending_restart_missing_old_marker_never_launches_past_live_pid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(Path(tmp), pid_alive_fn=lambda pid: True)
            _pending, marker_path = self._begin_restart_over_running_gateway(store, supervisor)
            marker_path.unlink()
            _RecoveryPopen.launches.clear()

            with (
                patch.object(supervisor, "kill_fn") as kill,
                patch.object(supervisor, "popen_factory") as popen,
            ):
                result = supervisor.reconcile("coder")[0]

            kill.assert_not_called()
            popen.assert_not_called()
            self.assertEqual(BotStatus.failed, result.status)
            self.assertIn("marker is missing", result.message)
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertEqual(4321, loaded.pid)
            self.assertEqual("restart", loaded.pending_action)

    def test_status_reports_pending_restart_without_signaling_or_launching(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(Path(tmp), pid_alive_fn=lambda pid: True)
            self._begin_restart_over_running_gateway(store, supervisor)

            with (
                patch.object(supervisor, "kill_fn") as kill,
                patch.object(supervisor, "popen_factory") as popen,
            ):
                result = supervisor.status("coder")

            kill.assert_not_called()
            popen.assert_not_called()
            self.assertEqual(BotStatus.failed, result.status)
            self.assertIn("action required", result.message)
            self.assertIn("restart", result.message)

    def test_start_registers_matching_process_start_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(Path(tmp))
            _RecoveryPopen.launches.clear()

            result = supervisor.start("coder")

            self.assertEqual(BotStatus.running, result.status)
            self.assertEqual(1, len(_RecoveryPopen.launches))
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertEqual(4321, loaded.pid)
            self.assertIsNone(loaded.pending_operation_id)

    def test_start_waits_for_post_ack_launcher_exec_before_registration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(Path(tmp))
            supervisor.popen_factory = _PostAckLockPopen
            supervisor.lock_timeout_seconds = 1
            supervisor.cmdline_reader = lambda pid: (
                [
                    str(supervisor._resolved_hermes_bin()),
                    "-p",
                    "coder",
                    "gateway",
                    "run",
                ]
                if _PostAckLockPopen.exec_visible.is_set()
                else [sys.executable, "-m", "zeus.gateway_launcher"]
            )
            _PostAckLockPopen.reset()
            results: list[models.BotStatusResponse] = []
            errors: list[BaseException] = []
            completed = threading.Event()

            def start() -> None:
                try:
                    results.append(supervisor.start("coder"))
                except BaseException as exc:
                    errors.append(exc)
                finally:
                    completed.set()

            start_thread = threading.Thread(target=start)
            start_thread.start()
            self.assertTrue(_PostAckLockPopen.publication_locked.wait(timeout=1))
            registration_waited = not completed.wait(timeout=0.15)
            during_wait = store.get_bot("coder")
            _PostAckLockPopen.release_exec.set()
            start_thread.join(timeout=2)

            self.assertTrue(registration_waited, errors)
            self.assertIsNotNone(during_wait)
            assert during_wait is not None
            self.assertEqual("start", during_wait.pending_action)
            self.assertIsNone(during_wait.pid)
            self.assertFalse(start_thread.is_alive())
            self.assertEqual([], errors)
            self.assertEqual([], _PostAckLockPopen.errors)
            self.assertEqual(1, len(results))
            self.assertEqual(BotStatus.running, results[0].status)
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertEqual(4321, loaded.pid)
            self.assertIsNone(loaded.pending_operation_id)

    def test_start_post_ack_publication_timeout_never_registers_running(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(Path(tmp))
            supervisor.popen_factory = _PostAckLockPopen
            supervisor.lock_timeout_seconds = 0.05
            _PostAckLockPopen.reset()

            result = supervisor.start("coder")
            publisher = _PostAckLockPopen.instances[0].publisher
            publisher.join(timeout=1)

            self.assertTrue(_PostAckLockPopen.publication_locked.is_set())
            self.assertFalse(publisher.is_alive())
            self.assertEqual([], _PostAckLockPopen.errors)
            self.assertEqual(BotStatus.failed, result.status)
            self.assertIsNone(result.pid)
            self.assertIn("registration failed", result.message)
            self.assertFalse(supervisor.pid_marker_path(result.profile_path).exists())
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertNotEqual(BotStatus.running, loaded.status)
            self.assertIsNone(loaded.pid)
            self.assertEqual("start", loaded.pending_action)

    def test_start_rejects_post_ack_marker_without_process_start_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(Path(tmp))
            supervisor.popen_factory = _MissingFingerprintRecoveryPopen
            _MissingFingerprintRecoveryPopen.launches.clear()

            result = supervisor.start("coder")

            self.assertEqual(BotStatus.failed, result.status)
            self.assertIn("registration failed", result.message)
            self.assertFalse(
                supervisor.pid_marker_path(str(Path(tmp) / "hermes/profiles/coder")).exists()
            )
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertEqual("start", loaded.pending_action)
            self.assertIsNone(loaded.pid)

    def test_reconcile_adopts_exact_live_marker_without_spawning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(
                Path(tmp),
                proc_start_fingerprint_reader=lambda pid: "test-start:4321",
            )
            pending = store.begin_lifecycle_intent(
                "coder",
                action="start",
                operation_id="a" * 32,
                source="cli",
            )
            payload = supervisor.adapter.launcher_payload(
                "coder",
                operation_id="a" * 32,
                desired_revision=pending.desired_revision,
                readiness_probe=None,
            )
            marker = dict(payload["marker"])
            marker.update(
                {
                    "pid": 4321,
                    "started_at": time.time(),
                    "proc_start_fingerprint": "test-start:4321",
                }
            )
            marker_path = supervisor.pid_marker_path(pending.profile_path)
            marker_path.parent.mkdir(parents=True)
            marker_path.write_text(json.dumps(marker), encoding="utf-8")

            with patch.object(supervisor, "popen_factory") as popen:
                result = supervisor.reconcile("coder")[0]

            popen.assert_not_called()
            self.assertEqual(BotStatus.running, result.status)
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertEqual(4321, loaded.pid)
            self.assertIsNone(loaded.pending_operation_id)

    def test_reconcile_refuses_adoption_without_process_start_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(
                Path(tmp),
                proc_start_fingerprint_reader=lambda pid: None,
            )
            pending = store.begin_lifecycle_intent(
                "coder",
                action="start",
                operation_id="a" * 32,
                source="cli",
            )
            marker = self._runtime_marker(
                supervisor,
                desired_revision=pending.desired_revision,
                proc_start_fingerprint=None,
            )
            self._write_runtime_marker(supervisor, pending.profile_path, marker)

            with patch.object(supervisor, "popen_factory") as popen:
                result = supervisor.reconcile("coder")[0]

            popen.assert_not_called()
            self.assertEqual(BotStatus.failed, result.status)
            self.assertIn("action required", result.message)
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertIsNone(loaded.pid)
            self.assertEqual("a" * 32, loaded.pending_operation_id)

    def test_stop_schema_v3_marker_reader_fails_closed_before_signal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for case in ("symlink", "directory", "oversized", "duplicate", "mismatch"):
                with self.subTest(case=case):
                    case_root = root / case
                    store, supervisor = self._fixture(
                        case_root,
                        desired=DesiredState.running,
                        proc_start_fingerprint_reader=lambda pid: "test-start:4321",
                    )
                    record = store.get_bot("coder")
                    assert record is not None
                    running = replace(record, status=BotStatus.running, pid=4321)
                    store.upsert_bot(running)
                    marker = self._runtime_marker(supervisor)
                    marker_path = supervisor.pid_marker_path(running.profile_path)
                    marker_path.parent.mkdir(parents=True, exist_ok=True)
                    if case == "symlink":
                        target = case_root / "outside-marker.json"
                        target.write_text(json.dumps(marker), encoding="utf-8")
                        marker_path.symlink_to(target)
                    elif case == "directory":
                        marker_path.mkdir()
                    elif case == "oversized":
                        marker_path.write_text(
                            json.dumps(marker) + " " * (64 * 1024), encoding="utf-8"
                        )
                    elif case == "duplicate":
                        encoded = json.dumps(marker, separators=(",", ":"))
                        marker_path.write_text(
                            encoded.replace('"pid":4321', '"pid":4321,"pid":4321'),
                            encoding="utf-8",
                        )
                    else:
                        marker["bot_id"] = "other"
                        marker_path.write_text(json.dumps(marker), encoding="utf-8")

                    with patch.object(
                        supervisor,
                        "kill_fn",
                        side_effect=ProcessLookupError,
                    ) as kill:
                        result = supervisor.stop("coder")

                    kill.assert_not_called()
                    self.assertEqual(BotStatus.failed, result.status)
                    self.assertIn("action required", result.message)

    def test_stop_rejects_symlinked_profile_path_components_without_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for case in ("profile", "ancestor"):
                with self.subTest(case=case):
                    case_root = root / case
                    store, supervisor = self._fixture(
                        case_root,
                        desired=DesiredState.running,
                    )
                    record = store.get_bot("coder")
                    assert record is not None
                    running = replace(record, status=BotStatus.running, pid=4321)
                    store.upsert_bot(running)
                    marker = self._runtime_marker(
                        supervisor,
                        proc_start_fingerprint="test-start:4321",
                    )
                    marker_path = self._write_runtime_marker(
                        supervisor,
                        running.profile_path,
                        marker,
                    )
                    supervisor.stop_grace_seconds = 0
                    if case == "profile":
                        target = case_root / "real-profile"
                        Path(running.profile_path).rename(target)
                        Path(running.profile_path).symlink_to(target, target_is_directory=True)
                        preserved_marker = target / "logs" / marker_path.name
                    else:
                        hermes_root = case_root / "hermes"
                        target = case_root / "real-hermes"
                        hermes_root.rename(target)
                        hermes_root.symlink_to(target, target_is_directory=True)
                        preserved_marker = target / "profiles/coder/logs" / marker_path.name

                    with (
                        patch.object(supervisor, "kill_fn") as kill,
                        patch.object(supervisor, "popen_factory") as popen,
                    ):
                        result = supervisor.stop("coder")

                    kill.assert_not_called()
                    popen.assert_not_called()
                    self.assertEqual(BotStatus.failed, result.status)
                    self.assertIn("action required", result.message)
                    self.assertTrue(preserved_marker.exists())
                    loaded = store.get_bot("coder")
                    assert loaded is not None
                    self.assertEqual("stop", loaded.pending_action)

    def test_stop_reauthorizes_process_identity_before_sigkill(self) -> None:
        class NeverExits:
            pid = 4321

            def poll(self) -> int | None:
                return None

            def wait(self, timeout: float) -> None:
                raise subprocess.TimeoutExpired("hermes", timeout)

        with tempfile.TemporaryDirectory() as tmp:
            fingerprints = iter(["test-start:4321", "test-start:4321", "test-start:reused"])
            store, supervisor = self._fixture(
                Path(tmp),
                desired=DesiredState.running,
                proc_start_fingerprint_reader=lambda pid: next(fingerprints, "test-start:reused"),
            )
            record = store.get_bot("coder")
            assert record is not None
            running = replace(record, status=BotStatus.running, pid=4321)
            store.upsert_bot(running)
            marker = self._runtime_marker(
                supervisor,
                proc_start_fingerprint="test-start:4321",
            )
            marker_path = self._write_runtime_marker(
                supervisor,
                running.profile_path,
                marker,
            )
            supervisor._processes["coder"] = NeverExits()
            supervisor.stop_grace_seconds = 0
            sent: list[tuple[int, object]] = []
            supervisor.kill_fn = lambda pid, sig: sent.append((pid, sig))

            result = supervisor.stop("coder", kill_after_timeout=True)

            self.assertEqual([(4321, signal.SIGTERM)], sent)
            self.assertEqual(BotStatus.failed, result.status)
            self.assertIn("action required", result.message)
            self.assertTrue(marker_path.exists())
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertEqual("stop", loaded.pending_action)

    def test_start_refuses_existing_live_marker_before_persisting_intent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(
                Path(tmp),
                proc_start_fingerprint_reader=lambda pid: "test-start:4321",
            )
            record = store.get_bot("coder")
            assert record is not None
            marker = self._runtime_marker(supervisor)
            marker_path = self._write_runtime_marker(supervisor, record.profile_path, marker)

            with patch.object(supervisor, "popen_factory") as popen:
                result = supervisor.start("coder")

            popen.assert_not_called()
            self.assertEqual(BotStatus.failed, result.status)
            self.assertIn("action required", result.message)
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertIsNone(loaded.pending_operation_id)
            self.assertIs(DesiredState.stopped, loaded.desired_state)
            self.assertTrue(marker_path.exists())

    def test_start_refuses_dangling_marker_symlink_as_ambiguous(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(Path(tmp))
            record = store.get_bot("coder")
            assert record is not None
            marker_path = supervisor.pid_marker_path(record.profile_path)
            marker_path.parent.mkdir(parents=True, exist_ok=True)
            marker_path.symlink_to(Path(tmp) / "missing-target.json")

            with patch.object(supervisor, "popen_factory") as popen:
                result = supervisor.start("coder")

            popen.assert_not_called()
            self.assertEqual(BotStatus.failed, result.status)
            self.assertIn("action required", result.message)
            self.assertTrue(marker_path.is_symlink())

    def test_start_removes_only_exact_dead_marker_before_spawning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _RecoveryPopen.launches.clear()
            store, supervisor = self._fixture(
                Path(tmp),
                pid_alive_fn=lambda pid: bool(_RecoveryPopen.launches),
                proc_start_fingerprint_reader=lambda pid: "test-start:4321",
            )
            record = store.get_bot("coder")
            assert record is not None
            marker = self._runtime_marker(supervisor)
            self._write_runtime_marker(supervisor, record.profile_path, marker)

            result = supervisor.start("coder")

            self.assertEqual(BotStatus.running, result.status)
            self.assertEqual(1, len(_RecoveryPopen.launches))
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertIsNone(loaded.pending_operation_id)

    def test_reconcile_removes_exact_dead_marker_for_recorded_pid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(
                Path(tmp),
                pid_alive_fn=lambda pid: False,
                proc_start_fingerprint_reader=lambda pid: "test-start:4321",
            )
            record = store.get_bot("coder")
            assert record is not None
            running = replace(record, status=BotStatus.running, pid=4321)
            store.upsert_bot(running)
            marker = self._runtime_marker(supervisor)
            marker_path = self._write_runtime_marker(supervisor, record.profile_path, marker)

            result = supervisor.reconcile("coder")[0]

            self.assertEqual(BotStatus.stopped, result.status)
            self.assertFalse(marker_path.exists())

    def test_reconcile_preserves_mismatched_live_marker_for_dead_recorded_pid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(
                Path(tmp),
                desired=DesiredState.running,
                pid_alive_fn=lambda pid: pid == 9876,
                proc_start_fingerprint_reader=lambda pid: "test-start:9876",
            )
            record = store.get_bot("coder")
            assert record is not None
            store.upsert_bot(replace(record, status=BotStatus.running, pid=4321))
            marker = self._runtime_marker(
                supervisor,
                pid=9876,
                proc_start_fingerprint="test-start:9876",
            )
            marker_path = self._write_runtime_marker(supervisor, record.profile_path, marker)

            with patch.object(supervisor, "popen_factory") as popen:
                result = supervisor.reconcile("coder")[0]

            popen.assert_not_called()
            self.assertEqual(BotStatus.failed, result.status)
            self.assertIn("action required", result.message)
            self.assertTrue(marker_path.exists())
            self.assertEqual(9876, json.loads(marker_path.read_text())["pid"])

    def test_reconcile_does_not_launch_through_live_marker_when_pid_is_unrecorded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(
                Path(tmp),
                desired=DesiredState.running,
                proc_start_fingerprint_reader=lambda pid: "test-start:4321",
            )
            record = store.get_bot("coder")
            assert record is not None
            store.upsert_bot(
                replace(
                    record,
                    status=BotStatus.failed,
                    restart_policy=RestartPolicy.on_failure,
                )
            )
            marker = self._runtime_marker(supervisor)
            marker_path = self._write_runtime_marker(supervisor, record.profile_path, marker)

            with patch.object(supervisor, "popen_factory") as popen:
                result = supervisor.reconcile("coder")[0]

            popen.assert_not_called()
            self.assertEqual(BotStatus.failed, result.status)
            self.assertIn("action required", result.message)
            self.assertTrue(marker_path.exists())

    def test_pending_marker_correlation_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(Path(tmp))
            pending = store.begin_lifecycle_intent(
                "coder",
                action="start",
                operation_id="a" * 32,
                source="cli",
            )
            payload = supervisor.adapter.launcher_payload(
                "coder",
                operation_id="b" * 32,
                desired_revision=pending.desired_revision,
                readiness_probe=None,
            )
            marker = dict(payload["marker"])
            marker.update({"pid": 4321, "started_at": time.time()})
            marker_path = supervisor.pid_marker_path(pending.profile_path)
            marker_path.parent.mkdir(parents=True)
            marker_path.write_text(json.dumps(marker), encoding="utf-8")

            with patch.object(supervisor, "popen_factory") as popen:
                result = supervisor.reconcile("coder")[0]

            popen.assert_not_called()
            self.assertEqual(BotStatus.failed, result.status)
            self.assertIn("action required", result.message)
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertEqual("a" * 32, loaded.pending_operation_id)

    def test_pending_stop_with_dead_process_finalizes_without_signal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(Path(tmp), desired=DesiredState.running)
            record = store.get_bot("coder")
            assert record is not None
            store.upsert_bot(replace(record, status=BotStatus.running, pid=4321))
            store.begin_lifecycle_intent(
                "coder",
                action="stop",
                operation_id="c" * 32,
                source="cli",
            )
            supervisor.pid_alive_fn = lambda pid: False
            with patch.object(supervisor, "kill_fn") as kill:
                result = supervisor.reconcile("coder")[0]

            kill.assert_not_called()
            self.assertEqual(BotStatus.stopped, result.status)
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertIsNone(loaded.pending_operation_id)
            self.assertIs(DesiredState.stopped, loaded.desired_state)

    def test_hardlinked_schema3_marker_never_authorizes_stop_signal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(Path(tmp), desired=DesiredState.running)
            record = store.get_bot("coder")
            assert record is not None
            store.upsert_bot(
                replace(
                    record,
                    status=BotStatus.running,
                    pid=4321,
                    desired_state=DesiredState.running,
                )
            )
            marker = self._runtime_marker(supervisor)
            marker_path = self._write_runtime_marker(supervisor, record.profile_path, marker)
            os.link(marker_path, marker_path.with_name("marker-alias.json"))
            supervisor.stop_grace_seconds = 0

            with patch.object(supervisor, "kill_fn") as kill:
                result = supervisor.stop("coder")

            kill.assert_not_called()
            self.assertEqual(BotStatus.failed, result.status)
            self.assertIn("action required", result.message)
            self.assertTrue(marker_path.exists())
            self.assertEqual(2, marker_path.stat().st_nlink)

    def test_pending_stop_compat_marker_fails_closed_before_signal(self) -> None:
        for schema in (2, None):
            with self.subTest(schema=schema), tempfile.TemporaryDirectory() as tmp:
                store, supervisor = self._fixture(Path(tmp), desired=DesiredState.running)
                record = store.get_bot("coder")
                assert record is not None
                store.upsert_bot(
                    replace(
                        record,
                        status=BotStatus.running,
                        pid=4321,
                        desired_state=DesiredState.running,
                    )
                )
                marker_path = self._write_runtime_marker(
                    supervisor,
                    record.profile_path,
                    self._compat_marker(supervisor, schema=schema),
                )
                supervisor.stop_grace_seconds = 0
                pending = store.begin_lifecycle_intent(
                    "coder",
                    action="stop",
                    operation_id="c" * 32,
                    source="cli",
                )

                with (
                    patch.object(supervisor, "kill_fn") as kill,
                    patch.object(supervisor, "_remove_pid_marker") as remove,
                ):
                    result = supervisor.reconcile("coder")[0]

                kill.assert_not_called()
                remove.assert_not_called()
                self.assertEqual(BotStatus.failed, result.status)
                self.assertIn("manual process resolution", result.message)
                self.assertTrue(marker_path.exists())
                self.assertEqual(pending, store.get_bot("coder"))

    def test_pending_stop_compat_cleanup_preserves_schema3_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, supervisor = self._fixture(
                Path(tmp),
                desired=DesiredState.running,
                pid_alive_fn=lambda pid: False,
            )
            record = store.get_bot("coder")
            assert record is not None
            store.upsert_bot(
                replace(
                    record,
                    status=BotStatus.running,
                    pid=4321,
                    desired_state=DesiredState.running,
                )
            )
            marker_path = self._write_runtime_marker(
                supervisor,
                record.profile_path,
                self._compat_marker(supervisor, schema=2),
            )
            pending = store.begin_lifecycle_intent(
                "coder",
                action="stop",
                operation_id="c" * 32,
                source="cli",
            )
            replacement = self._runtime_marker(
                supervisor,
                operation_id="d" * 32,
                desired_revision=pending.desired_revision,
            )
            original_read = supervisor._read_strict_runtime_marker

            def replace_after_observation(bot_id: str, profile_path: str) -> object:
                observed = original_read(bot_id, profile_path)
                marker_path.write_text(json.dumps(replacement), encoding="utf-8")
                return observed

            with (
                patch.object(
                    supervisor,
                    "_read_strict_runtime_marker",
                    side_effect=replace_after_observation,
                ),
                patch.object(
                    supervisor,
                    "_remove_pid_marker",
                    wraps=supervisor._remove_pid_marker,
                ) as remove,
                patch.object(supervisor, "kill_fn") as kill,
            ):
                result = supervisor.reconcile("coder")[0]

            kill.assert_not_called()
            remove.assert_not_called()
            self.assertEqual(BotStatus.failed, result.status)
            self.assertIn("action required", result.message)
            self.assertTrue(marker_path.exists())
            self.assertEqual("d" * 32, json.loads(marker_path.read_text())["operation_id"])
            self.assertEqual(pending, store.get_bot("coder"))


if __name__ == "__main__":
    unittest.main()
