from __future__ import annotations

import fcntl
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import suppress
from dataclasses import replace
from pathlib import Path
from unittest import mock

import zeus.audit_docker_broker as audit_docker_broker
from zeus.audit_container import PreparedAuditContainer
from zeus.audit_docker_broker import (
    AuditDockerBrokerError,
    BrokerCommandResult,
    cleanup_audit_docker_broker,
    install_audit_docker_broker,
    invoke_audit_docker_broker,
    read_audit_docker_broker_state,
)
from zeus.audit_models import HARD_LIMITS, AuditCommandReceipt
from zeus.audit_receipts import expected_command_receipt_tag
from zeus.audit_trusted_snapshot_attest import TRUSTED_EXEC_ENV

RUN_ID = "1" * 32
PROFILE = f"audit-{RUN_ID}"
IMAGE_REF = "registry.example.invalid/audit@sha256:" + "a" * 64
IMAGE_ID = "sha256:" + "b" * 64
CONTAINER_ID = "c" * 64
TRUSTED_CONTAINER_ID = "9" * 64
OTHER_CONTAINER_ID = "d" * 64
TARGET_COMMIT = "e" * 40
SNAPSHOT_DIGEST = "f" * 64


def _bootstrap_script(session_id: str) -> str:
    snapshot = f"/tmp/hermes-snap-{session_id}.sh"
    temporary = f"{snapshot}.tmp.XXXXXXXXXX"
    marker = f"__HERMES_CWD_{session_id}__"
    return (
        "umask 077\n"
        f"__hermes_snap_tmp=$(mktemp {temporary}) || exit 1\n"
        "{ ( unset ${!HERMES_SESSION_*} ${!HERMES_CRON_AUTO_DELIVER_*} "
        'HERMES_UI_SESSION_ID 2>/dev/null; export -p; ) || true; } > "$__hermes_snap_tmp"\n'
        "__hermes_fns=$(declare -F | awk '{print $3}' | grep -vE '^_[^_]') || true\n"
        '[ -n "$__hermes_fns" ] && declare -f $__hermes_fns >> "$__hermes_snap_tmp" '
        "2>/dev/null || true\n"
        'alias -p >> "$__hermes_snap_tmp"\n'
        "echo 'shopt -s expand_aliases' >> \"$__hermes_snap_tmp\"\n"
        "echo 'set +e' >> \"$__hermes_snap_tmp\"\n"
        "echo 'set +u' >> \"$__hermes_snap_tmp\"\n"
        f'mv -f "$__hermes_snap_tmp" {snapshot} || rm -f "$__hermes_snap_tmp"\n'
        "builtin cd -- /workspace 2>/dev/null || true\n"
        f"""printf '\\n{marker}%s{marker}\\n' "$(pwd -P)"\n"""
    )


def _trusted_state_fields(snapshot_path: Path, *, running: bool) -> tuple[object, ...]:
    uid = os.geteuid()
    gid = os.getegid()
    tmpfs = f"rw,noexec,nosuid,nodev,size={HARD_LIMITS.temp_bytes},uid={uid},gid={gid},mode=0700"
    networks = {
        "none": {
            "Aliases": None,
            "DNSNames": None,
            "DriverOpts": None,
            "EndpointID": "endpoint-id",
            "Gateway": "",
            "GlobalIPv6Address": "",
            "GlobalIPv6PrefixLen": 0,
            "GwPriority": 0,
            "IPAMConfig": None,
            "IPAddress": "",
            "IPPrefixLen": 0,
            "IPv6Gateway": "",
            "Links": None,
            "MacAddress": "",
            "NetworkID": "network-id",
        }
    }
    requested_mount = {
        "Type": "bind",
        "Source": str(snapshot_path),
        "Target": "/workspace",
        "ReadOnly": True,
        "BindOptions": {},
    }
    effective_mounts = [
        {
            "Type": "bind",
            "Source": str(snapshot_path),
            "Destination": "/workspace",
            "RW": False,
        },
        {"Type": "tmpfs", "Destination": "/tmp", "RW": True},
    ]
    return (
        TRUSTED_CONTAINER_ID,
        f"/zeus-audit-trusted-{RUN_ID}",
        IMAGE_ID,
        RUN_ID,
        "true",
        running,
        123 if running else 0,
        "running" if running else "exited",
        f"{uid}:{gid}",
        "/workspace",
        ["/bin/sh"],
        ["-c", "trap : TERM INT; sleep infinity & wait"],
        list(TRUSTED_EXEC_ENV),
        None,
        {"Test": ["NONE"]},
        "none",
        True,
        None,
        ["ALL"],
        ["no-new-privileges:true"],
        "",
        "none",
        "",
        "",
        "private",
        [],
        [],
        [],
        [],
        {},
        HARD_LIMITS.pids,
        HARD_LIMITS.cpu_count * 1_000_000_000,
        HARD_LIMITS.memory_bytes,
        HARD_LIMITS.memory_bytes,
        False,
        [requested_mount],
        {"/tmp": tmpfs},
        {"Type": "none", "Config": {}},
        {"Name": "no", "MaximumRetryCount": 0},
        effective_mounts,
        {},
        networks,
        "",
        "",
        "",
    )


def _encode_trusted_fields(fields: tuple[object, ...]) -> bytes:
    return ("\t".join(json.dumps(field, separators=(",", ":")) for field in fields) + "\n").encode(
        "ascii"
    )


def _encoded_trusted_state(snapshot_path: Path, *, running: bool) -> bytes:
    return _encode_trusted_fields(_trusted_state_fields(snapshot_path, running=running))


class FakeDockerRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], float, int, dict[str, str]]] = []
        self.command_results: dict[str, BrokerCommandResult] = {}

    def run(
        self,
        argv: tuple[str, ...],
        *,
        deadline: float,
        output_limit: int,
        env: dict[str, str],
    ) -> BrokerCommandResult:
        self.calls.append((argv, deadline, output_limit, env))
        if argv[1:3] == ("image", "inspect"):
            return BrokerCommandResult(returncode=0, stdout=b'["/bin/sh"]\n', stderr=b"")
        if argv[1:3] == ("inspect", "--format"):
            return BrokerCommandResult(returncode=0, stdout=b"none\n", stderr=b"")
        if argv[1:3] == ("rm", "-f"):
            return BrokerCommandResult(
                returncode=0,
                stdout=f"{CONTAINER_ID}\n".encode("ascii"),
                stderr=b"",
            )
        if argv[1] == "exec":
            command = argv[-1]
            return self.command_results.get(
                command,
                BrokerCommandResult(returncode=0, stdout=b"ok\n", stderr=b""),
            )
        raise AssertionError(f"unexpected real Docker call: {argv!r}")


class MutatingWorkspaceDockerRunner(FakeDockerRunner):
    def __init__(self, snapshot_path: Path) -> None:
        super().__init__()
        self.snapshot_path = snapshot_path
        self.shared_workspace_content = b"committed\n"
        self.trusted_running = False
        self.trusted_temp_dirty = False
        self.trusted_background_alive = False
        self.attestor_returncode = 0

    def run(
        self,
        argv: tuple[str, ...],
        *,
        deadline: float,
        output_limit: int,
        env: dict[str, str],
    ) -> BrokerCommandResult:
        if argv[1:] == (
            "exec",
            CONTAINER_ID,
            "bash",
            "-c",
            "printf 'mutated\\n' > tracked.txt",
        ):
            self.calls.append((argv, deadline, output_limit, env))
            self.shared_workspace_content = b"mutated\n"
            return BrokerCommandResult(returncode=0, stdout=b"", stderr=b"")
        if argv[1:] == ("exec", CONTAINER_ID, "bash", "-c", "cat tracked.txt"):
            self.calls.append((argv, deadline, output_limit, env))
            return BrokerCommandResult(
                returncode=0,
                stdout=self.shared_workspace_content,
                stderr=b"",
            )
        if argv[1:3] == ("inspect", "--format") and argv[-1] == TRUSTED_CONTAINER_ID:
            self.calls.append((argv, deadline, output_limit, env))
            if argv[3] != audit_docker_broker._TRUSTED_STATE_FORMAT:
                fields = (
                    TRUSTED_CONTAINER_ID,
                    f"/zeus-audit-trusted-{RUN_ID}",
                    IMAGE_ID,
                    RUN_ID,
                    "true",
                )
                return BrokerCommandResult(
                    returncode=0,
                    stdout=(
                        "\t".join(json.dumps(field, separators=(",", ":")) for field in fields)
                        + "\n"
                    ).encode("ascii"),
                    stderr=b"",
                )
            return BrokerCommandResult(
                returncode=0,
                stdout=_encoded_trusted_state(
                    self.snapshot_path,
                    running=self.trusted_running,
                ),
                stderr=b"",
            )
        if argv[1:] == ("start", TRUSTED_CONTAINER_ID):
            self.calls.append((argv, deadline, output_limit, env))
            self.trusted_running = True
            return BrokerCommandResult(
                returncode=0,
                stdout=f"{TRUSTED_CONTAINER_ID}\n".encode("ascii"),
                stderr=b"",
            )
        if (
            argv[1] == "exec"
            and TRUSTED_CONTAINER_ID in argv
            and "python3" in argv
            and audit_docker_broker.ATTEST_SCRIPT in argv
        ):
            self.calls.append((argv, deadline, output_limit, env))
            return BrokerCommandResult(
                returncode=self.attestor_returncode,
                stdout=b"",
                stderr=b"attestation failed\n" if self.attestor_returncode else b"",
            )
        if argv[-3:] == ("bash", "-c", "cat tracked.txt") and TRUSTED_CONTAINER_ID in argv:
            self.calls.append((argv, deadline, output_limit, env))
            return BrokerCommandResult(
                returncode=0,
                stdout=b"committed\n",
                stderr=b"",
            )
        if (
            argv[-3:] == ("bash", "-c", "spawn background and dirty temp")
            and TRUSTED_CONTAINER_ID in argv
        ):
            self.calls.append((argv, deadline, output_limit, env))
            self.trusted_temp_dirty = True
            self.trusted_background_alive = True
            return BrokerCommandResult(returncode=0, stdout=b"spawned\n", stderr=b"")
        if (
            argv[-3:] == ("bash", "-c", "verify pristine trusted sandbox")
            and TRUSTED_CONTAINER_ID in argv
        ):
            self.calls.append((argv, deadline, output_limit, env))
            clean = not self.trusted_temp_dirty and not self.trusted_background_alive
            return BrokerCommandResult(
                returncode=0 if clean else 9,
                stdout=b"clean\n" if clean else b"contaminated\n",
                stderr=b"",
            )
        if argv[1:] == ("kill", "--signal=KILL", TRUSTED_CONTAINER_ID):
            self.calls.append((argv, deadline, output_limit, env))
            self.trusted_running = False
            self.trusted_temp_dirty = False
            self.trusted_background_alive = False
            return BrokerCommandResult(
                returncode=0,
                stdout=f"{TRUSTED_CONTAINER_ID}\n".encode("ascii"),
                stderr=b"",
            )
        if argv[1:3] == ("ps", "--all") and f"id={TRUSTED_CONTAINER_ID}" in argv:
            self.calls.append((argv, deadline, output_limit, env))
            return BrokerCommandResult(
                returncode=0,
                stdout=f"{TRUSTED_CONTAINER_ID}\n".encode("ascii"),
                stderr=b"",
            )
        if argv[1:] == ("rm", "-f", TRUSTED_CONTAINER_ID):
            self.calls.append((argv, deadline, output_limit, env))
            return BrokerCommandResult(
                returncode=0,
                stdout=f"{TRUSTED_CONTAINER_ID}\n".encode("ascii"),
                stderr=b"",
            )
        return super().run(argv, deadline=deadline, output_limit=output_limit, env=env)


class BlockingTrustedDockerRunner(MutatingWorkspaceDockerRunner):
    def __init__(self, snapshot_path: Path) -> None:
        super().__init__(snapshot_path)
        self.started = threading.Event()
        self.release = threading.Event()

    def run(
        self,
        argv: tuple[str, ...],
        *,
        deadline: float,
        output_limit: int,
        env: dict[str, str],
    ) -> BrokerCommandResult:
        if argv[-3:] == ("bash", "-c", "cat tracked.txt") and TRUSTED_CONTAINER_ID in argv:
            self.calls.append((argv, deadline, output_limit, env))
            self.started.set()
            if not self.release.wait(timeout=3):
                raise AssertionError("trusted terminal test runner was not released")
            return BrokerCommandResult(returncode=0, stdout=b"committed\n", stderr=b"")
        return super().run(argv, deadline=deadline, output_limit=output_limit, env=env)


class TimedOutTrustedContainerRunner(FakeDockerRunner):
    def __init__(self, snapshot_path: Path) -> None:
        super().__init__()
        self.snapshot_path = snapshot_path
        self.trusted_name = f"zeus-audit-trusted-{RUN_ID}"
        self.trusted_id = TRUSTED_CONTAINER_ID
        self.trusted_running = False

    def run(
        self,
        argv: tuple[str, ...],
        *,
        deadline: float,
        output_limit: int,
        env: dict[str, str],
    ) -> BrokerCommandResult:
        if argv[1:3] == ("inspect", "--format") and argv[-1] == self.trusted_id:
            self.calls.append((argv, deadline, output_limit, env))
            if argv[3] == audit_docker_broker._TRUSTED_STATE_FORMAT:
                return BrokerCommandResult(
                    returncode=0,
                    stdout=_encoded_trusted_state(
                        self.snapshot_path,
                        running=self.trusted_running,
                    ),
                    stderr=b"",
                )
            else:
                fields = (
                    f'"{self.trusted_id}"',
                    f'"/{self.trusted_name}"',
                    f'"{IMAGE_ID}"',
                    f'"{RUN_ID}"',
                    '"true"',
                )
            return BrokerCommandResult(
                returncode=0,
                stdout=("\t".join(fields) + "\n").encode("ascii"),
                stderr=b"",
            )
        if argv[1:] == ("start", self.trusted_id):
            self.calls.append((argv, deadline, output_limit, env))
            self.trusted_running = True
            return BrokerCommandResult(
                returncode=0,
                stdout=f"{self.trusted_id}\n".encode("ascii"),
                stderr=b"",
            )
        if (
            argv[1] == "exec"
            and self.trusted_id in argv
            and "python3" in argv
            and audit_docker_broker.ATTEST_SCRIPT in argv
        ):
            self.calls.append((argv, deadline, output_limit, env))
            return BrokerCommandResult(returncode=0, stdout=b"", stderr=b"")
        if argv[-3:] == ("bash", "-c", "cat tracked.txt") and self.trusted_id in argv:
            self.calls.append((argv, deadline, output_limit, env))
            raise AuditDockerBrokerError("simulated trusted command timeout")
        if argv[1:] == ("kill", "--signal=KILL", self.trusted_id):
            self.calls.append((argv, deadline, output_limit, env))
            self.trusted_running = False
            return BrokerCommandResult(
                returncode=0,
                stdout=f"{self.trusted_id}\n".encode("ascii"),
                stderr=b"",
            )
        if argv[1:] == ("rm", "-f", self.trusted_id):
            self.calls.append((argv, deadline, output_limit, env))
            return BrokerCommandResult(
                returncode=0,
                stdout=f"{self.trusted_id}\n".encode("ascii"),
                stderr=b"",
            )
        if argv[1:3] == ("ps", "--all") and f"id={self.trusted_id}" in argv:
            self.calls.append((argv, deadline, output_limit, env))
            return BrokerCommandResult(
                returncode=0,
                stdout=f"{self.trusted_id}\n".encode("ascii"),
                stderr=b"",
            )
        return super().run(argv, deadline=deadline, output_limit=output_limit, env=env)


class MissingTrustedContainerRunner(FakeDockerRunner):
    def run(
        self,
        argv: tuple[str, ...],
        *,
        deadline: float,
        output_limit: int,
        env: dict[str, str],
    ) -> BrokerCommandResult:
        if argv[1:3] == ("ps", "--all") and f"id={TRUSTED_CONTAINER_ID}" in argv:
            self.calls.append((argv, deadline, output_limit, env))
            return BrokerCommandResult(returncode=0, stdout=b"", stderr=b"")
        return super().run(argv, deadline=deadline, output_limit=output_limit, env=env)


class BlockingDockerRunner(FakeDockerRunner):
    def __init__(self) -> None:
        super().__init__()
        self.started = threading.Event()
        self.release = threading.Event()

    def run(
        self,
        argv: tuple[str, ...],
        *,
        deadline: float,
        output_limit: int,
        env: dict[str, str],
    ) -> BrokerCommandResult:
        if argv[1:] == ("exec", CONTAINER_ID, "bash", "-c", "first"):
            self.calls.append((argv, deadline, output_limit, env))
            self.started.set()
            if not self.release.wait(timeout=3):
                raise AssertionError("terminal test runner was not released")
            return BrokerCommandResult(returncode=0, stdout=b"x", stderr=b"")
        return super().run(argv, deadline=deadline, output_limit=output_limit, env=env)


class BlockingImageRunner(FakeDockerRunner):
    def __init__(self) -> None:
        super().__init__()
        self.started = threading.Event()
        self.release = threading.Event()

    def run(
        self,
        argv: tuple[str, ...],
        *,
        deadline: float,
        output_limit: int,
        env: dict[str, str],
    ) -> BrokerCommandResult:
        if argv[1:3] == ("image", "inspect"):
            self.calls.append((argv, deadline, output_limit, env))
            self.started.set()
            if not self.release.wait(timeout=3):
                raise AssertionError("image inspection test runner was not released")
            return BrokerCommandResult(returncode=0, stdout=b'["/bin/sh"]\n', stderr=b"")
        return super().run(argv, deadline=deadline, output_limit=output_limit, env=env)


class BlockingRemovalRunner(FakeDockerRunner):
    def __init__(self) -> None:
        super().__init__()
        self.started = threading.Event()
        self.release = threading.Event()

    def run(
        self,
        argv: tuple[str, ...],
        *,
        deadline: float,
        output_limit: int,
        env: dict[str, str],
    ) -> BrokerCommandResult:
        if argv[1:3] == ("rm", "-f") and not self.started.is_set():
            self.calls.append((argv, deadline, output_limit, env))
            self.started.set()
            if not self.release.wait(timeout=3):
                raise AssertionError("cleanup test runner was not released")
            return BrokerCommandResult(
                returncode=0,
                stdout=f"{CONTAINER_ID}\n".encode("ascii"),
                stderr=b"",
            )
        return super().run(argv, deadline=deadline, output_limit=output_limit, env=env)


class AuditDockerBrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name).resolve()
        self.trusted_executable = self.root / "trusted-executable"
        self.trusted_executable.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.trusted_executable.chmod(0o700)
        self.broker_dir = self.root / "broker"
        self.broker_dir.mkdir(mode=0o700)
        self.snapshot_dir = self.root / "snapshot"
        self.snapshot_dir.mkdir(mode=0o700)
        (self.snapshot_dir / "tracked.txt").write_bytes(b"committed\n")
        self.prepared = PreparedAuditContainer(
            container_id=CONTAINER_ID,
            container_name=f"zeus-audit-{RUN_ID}",
            profile_name=PROFILE,
            image_ref=IMAGE_REF,
            image_id=IMAGE_ID,
            broker_dir=self.broker_dir,
            state_path=self.broker_dir / "state.json",
        )
        self.runner = FakeDockerRunner()
        self.deadline = time.monotonic() + 300

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_trusted_snapshot_attestor_is_valid_isolated_python(self) -> None:
        compile(audit_docker_broker.ATTEST_SCRIPT, "<trusted-snapshot-attestor>", "exec")

    def _install(
        self,
        *,
        runner: FakeDockerRunner | None = None,
        limits=HARD_LIMITS,
        deadline: float | None = None,
        trusted_command_scripts: tuple[str, ...] = (),
    ) -> Path:
        prepared = (
            replace(
                self.prepared,
                trusted_container_id=TRUSTED_CONTAINER_ID,
                trusted_container_name=f"zeus-audit-trusted-{RUN_ID}",
                trusted_snapshot_path=str(self.snapshot_dir),
                trusted_snapshot_device=self.snapshot_dir.lstat().st_dev,
                trusted_snapshot_inode=self.snapshot_dir.lstat().st_ino,
                trusted_snapshot_owner=self.snapshot_dir.lstat().st_uid,
                trusted_snapshot_mode=stat.S_IMODE(self.snapshot_dir.lstat().st_mode),
                trusted_execution_uid=os.geteuid(),
                trusted_execution_gid=os.getegid(),
            )
            if trusted_command_scripts
            else self.prepared
        )
        return install_audit_docker_broker(
            prepared,
            docker_executable=self.trusted_executable,
            limits=limits,
            deadline=self.deadline if deadline is None else deadline,
            python_executable=self.trusted_executable,
            target_commit=TARGET_COMMIT,
            snapshot_digest=SNAPSHOT_DIGEST,
            trusted_command_scripts=trusted_command_scripts,
        )

    def _invoke(
        self,
        *arguments: str,
        runner: FakeDockerRunner | None = None,
        clock=time.monotonic,
    ) -> BrokerCommandResult:
        return invoke_audit_docker_broker(
            self.prepared.state_path,
            tuple(arguments),
            runner=self.runner if runner is None else runner,
            clock=clock,
        )

    def _advance_to_terminal(self, *, runner: FakeDockerRunner | None = None) -> None:
        active = self.runner if runner is None else runner
        self.assertEqual(0, self._invoke("version", runner=active).returncode)
        self.assertEqual(
            0,
            self._invoke(
                "run",
                "--rm",
                "--cpus",
                "0.5",
                "--memory",
                "64m",
                "--pids-limit",
                "32",
                IMAGE_REF,
                "sleep",
                "0",
                runner=active,
            ).returncode,
        )
        self.assertEqual(
            0,
            self._invoke(
                "info",
                "--format",
                "{{.Driver}}",
                runner=active,
            ).returncode,
        )
        self.assertEqual(
            0,
            self._invoke(
                "image",
                "inspect",
                IMAGE_REF,
                "--format",
                "{{json .Config.Entrypoint}}",
                runner=active,
            ).returncode,
        )
        self.assertEqual(
            0,
            self._invoke(
                "ps",
                "-a",
                "--filter",
                "label=hermes-agent=1",
                "--filter",
                "label=hermes-task-id=default",
                "--filter",
                f"label=hermes-profile={PROFILE}",
                "--format",
                '{{.ID}}\t{{.State}}\t{{.Label "hermes-egress"}}',
                runner=active,
            ).returncode,
        )
        self.assertEqual(
            0,
            self._invoke(
                "inspect",
                "--format",
                "{{.HostConfig.NetworkMode}}",
                CONTAINER_ID,
                runner=active,
            ).returncode,
        )
        self.assertEqual(
            0,
            self._invoke(
                "exec",
                CONTAINER_ID,
                "bash",
                "-l",
                "-c",
                _bootstrap_script("0123456789ab"),
                runner=active,
            ).returncode,
        )

    def test_exact_pinned_protocol_is_ordered_and_real_docker_surface_is_narrow(self) -> None:
        executable = self._install()
        self.assertEqual(self.broker_dir / "docker", executable)
        self.assertEqual(0o500, stat.S_IMODE(executable.lstat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(self.prepared.state_path.lstat().st_mode))

        self._advance_to_terminal()
        terminal = self._invoke("exec", CONTAINER_ID, "bash", "-c", "printf audited")
        self.assertEqual(0, terminal.returncode)
        self.assertEqual(b"ok\n", terminal.stdout)
        self.assertEqual(b"", terminal.stderr)

        cleanup = self._invoke("rm", "-f", CONTAINER_ID)
        self.assertEqual(0, cleanup.returncode)

        real_arguments = [call[0][1:] for call in self.runner.calls]
        self.assertEqual(
            [
                (
                    "image",
                    "inspect",
                    IMAGE_REF,
                    "--format",
                    "{{json .Config.Entrypoint}}",
                ),
                ("inspect", "--format", "{{.HostConfig.NetworkMode}}", CONTAINER_ID),
                (
                    "exec",
                    CONTAINER_ID,
                    "bash",
                    "-l",
                    "-c",
                    _bootstrap_script("0123456789ab"),
                ),
                ("exec", CONTAINER_ID, "bash", "-c", "printf audited"),
                ("rm", "-f", CONTAINER_ID),
            ],
            real_arguments,
        )
        for _argv, _deadline, _limit, env in self.runner.calls:
            self.assertEqual({"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}, env)

        state = read_audit_docker_broker_state(self.prepared.state_path)
        self.assertEqual("closed", state.phase)
        self.assertEqual(1, state.terminal_calls)
        self.assertEqual(3, state.terminal_output_bytes)
        self.assertEqual(0, state.aggregate_reserved_output_bytes)
        self.assertTrue(state.bootstrap_complete)
        self.assertFalse(state.limit_breach)
        self.assertEqual("complete", state.cleanup_state)
        self.assertEqual(CONTAINER_ID, state.container_id)
        self.assertEqual(IMAGE_ID, state.image_id)
        self.assertEqual(PROFILE, state.profile_name)
        self.assertEqual(
            {
                "hermes-agent": "1",
                "hermes-task-id": "default",
                "hermes-profile": PROFILE,
                "hermes-egress": "off",
            },
            state.hermes_labels,
        )
        self.assertEqual(TARGET_COMMIT, state.target_commit)
        self.assertEqual(SNAPSHOT_DIGEST, state.snapshot_digest)
        self.assertEqual(1, len(state.terminal_receipts))
        receipt = state.terminal_receipts[0]
        self.assertEqual("terminal-000001", receipt.receipt_id)
        self.assertEqual(1, receipt.sequence)
        self.assertEqual("exited", receipt.state)
        self.assertEqual(0, receipt.returncode)
        self.assertIsNotNone(receipt.duration_ms)
        self.assertEqual(3, receipt.stdout_bytes)
        self.assertEqual(0, receipt.stderr_bytes)
        self.assertRegex(receipt.command_tag, r"^hmac-sha256:[0-9a-f]{64}$")
        assert state.receipt_hmac_key is not None
        self.assertEqual(
            receipt.command_tag,
            expected_command_receipt_tag(
                key_hex=state.receipt_hmac_key,
                run_id=RUN_ID,
                target_commit=TARGET_COMMIT,
                snapshot_digest=SNAPSHOT_DIGEST,
                image_id=IMAGE_ID,
                command_script="printf audited",
                receipt=receipt,
            ),
        )
        self.assertNotEqual(
            receipt.command_tag,
            expected_command_receipt_tag(
                key_hex=state.receipt_hmac_key,
                run_id=RUN_ID,
                target_commit=TARGET_COMMIT,
                snapshot_digest=SNAPSHOT_DIGEST,
                image_id=IMAGE_ID,
                command_script="true",
                receipt=receipt,
            ),
        )
        state_bytes = self.prepared.state_path.read_bytes()
        self.assertNotIn(b"printf audited", state_bytes)
        self.assertNotIn(b"ok\\n", state_bytes)

    def test_coverage_command_uses_fresh_read_only_snapshot_after_ad_hoc_mutation(self) -> None:
        runner = MutatingWorkspaceDockerRunner(self.snapshot_dir)
        self._install(trusted_command_scripts=("cat tracked.txt",))
        self._advance_to_terminal(runner=runner)

        mutated = self._invoke(
            "exec",
            CONTAINER_ID,
            "bash",
            "-c",
            "printf 'mutated\\n' > tracked.txt",
            runner=runner,
        )
        trusted = self._invoke(
            "exec",
            CONTAINER_ID,
            "bash",
            "-c",
            "cat tracked.txt",
            runner=runner,
        )

        self.assertEqual(0, mutated.returncode)
        self.assertEqual(b"committed\n", trusted.stdout)
        trusted_calls = [
            call[0]
            for call in runner.calls
            if call[0][1] == "exec"
            and TRUSTED_CONTAINER_ID in call[0]
            and call[0][-3:] == ("bash", "-c", "cat tracked.txt")
        ]
        self.assertEqual(1, len(trusted_calls))
        trusted_argv = trusted_calls[0]
        self.assertNotIn(CONTAINER_ID, trusted_argv)
        trusted_index = trusted_argv.index(TRUSTED_CONTAINER_ID)
        self.assertEqual(
            ("/usr/bin/env", "-i", *TRUSTED_EXEC_ENV),
            trusted_argv[trusted_index + 1 : -3],
        )
        self.assertIn(("start", TRUSTED_CONTAINER_ID), [call[0][1:] for call in runner.calls])
        self.assertIn(
            ("kill", "--signal=KILL", TRUSTED_CONTAINER_ID),
            [call[0][1:] for call in runner.calls],
        )
        self.assertFalse(
            any(
                call[0][1:] == ("exec", CONTAINER_ID, "bash", "-c", "cat tracked.txt")
                for call in runner.calls
            )
        )

        state = read_audit_docker_broker_state(self.prepared.state_path)
        trusted_receipt = state.terminal_receipts[1]
        assert state.receipt_hmac_key is not None
        self.assertEqual(
            trusted_receipt.command_tag,
            expected_command_receipt_tag(
                key_hex=state.receipt_hmac_key,
                run_id=RUN_ID,
                target_commit=TARGET_COMMIT,
                snapshot_digest=SNAPSHOT_DIGEST,
                image_id=IMAGE_ID,
                command_script="cat tracked.txt",
                receipt=trusted_receipt,
                isolated_workspace=True,
            ),
        )
        self.assertNotEqual(
            trusted_receipt.command_tag,
            expected_command_receipt_tag(
                key_hex=state.receipt_hmac_key,
                run_id=RUN_ID,
                target_commit=TARGET_COMMIT,
                snapshot_digest=SNAPSHOT_DIGEST,
                image_id=IMAGE_ID,
                command_script="cat tracked.txt",
                receipt=trusted_receipt,
            ),
        )
        state_bytes = self.prepared.state_path.read_bytes()
        self.assertNotIn(b"cat tracked.txt", state_bytes)
        self.assertNotIn(b"mutated", state_bytes)
        self.assertNotIn(b"committed", state_bytes)

    def test_trusted_sandbox_reset_clears_background_processes_and_tmpfs(self) -> None:
        runner = MutatingWorkspaceDockerRunner(self.snapshot_dir)
        commands = (
            "spawn background and dirty temp",
            "verify pristine trusted sandbox",
        )
        self._install(trusted_command_scripts=commands)
        self._advance_to_terminal(runner=runner)

        first = self._invoke(
            "exec",
            CONTAINER_ID,
            "bash",
            "-c",
            commands[0],
            runner=runner,
        )
        second = self._invoke(
            "exec",
            CONTAINER_ID,
            "bash",
            "-c",
            commands[1],
            runner=runner,
        )

        self.assertEqual((0, b"spawned\n"), (first.returncode, first.stdout))
        self.assertEqual((0, b"clean\n"), (second.returncode, second.stdout))
        real_arguments = [call[0][1:] for call in runner.calls]
        self.assertEqual(2, real_arguments.count(("start", TRUSTED_CONTAINER_ID)))
        self.assertEqual(
            2,
            real_arguments.count(("kill", "--signal=KILL", TRUSTED_CONTAINER_ID)),
        )
        state = read_audit_docker_broker_state(self.prepared.state_path)
        self.assertEqual(("exited", "exited"), tuple(r.state for r in state.terminal_receipts))
        self.assertIsNone(state.active_trusted_receipt_id)

    def test_concurrent_trusted_call_is_refused_without_blocking_ordinary_terminal(self) -> None:
        runner = BlockingTrustedDockerRunner(self.snapshot_dir)
        self._install(trusted_command_scripts=("cat tracked.txt",))
        self._advance_to_terminal(runner=runner)
        result: list[BrokerCommandResult] = []

        thread = threading.Thread(
            target=lambda: result.append(
                self._invoke(
                    "exec",
                    CONTAINER_ID,
                    "bash",
                    "-c",
                    "cat tracked.txt",
                    runner=runner,
                )
            )
        )
        thread.start()
        self.assertTrue(runner.started.wait(timeout=2))
        refused = self._invoke(
            "exec",
            CONTAINER_ID,
            "bash",
            "-c",
            "cat tracked.txt",
            runner=runner,
        )
        ordinary = self._invoke(
            "exec",
            CONTAINER_ID,
            "bash",
            "-c",
            "printf ordinary",
            runner=runner,
        )
        runner.release.set()
        thread.join(timeout=3)

        self.assertFalse(thread.is_alive())
        self.assertEqual(126, refused.returncode)
        self.assertEqual((0, b"ok\n"), (ordinary.returncode, ordinary.stdout))
        self.assertEqual((0, b"committed\n"), (result[0].returncode, result[0].stdout))
        state = read_audit_docker_broker_state(self.prepared.state_path)
        self.assertEqual(2, state.terminal_calls)
        self.assertEqual(0, state.active_terminal_calls)
        self.assertIsNone(state.active_trusted_receipt_id)

    def test_failed_attestation_never_executes_trusted_command(self) -> None:
        runner = MutatingWorkspaceDockerRunner(self.snapshot_dir)
        runner.attestor_returncode = 9
        self._install(trusted_command_scripts=("cat tracked.txt",))
        self._advance_to_terminal(runner=runner)

        result = self._invoke(
            "exec",
            CONTAINER_ID,
            "bash",
            "-c",
            "cat tracked.txt",
            runner=runner,
        )

        self.assertEqual(126, result.returncode)
        self.assertFalse(
            any(
                call[0][-3:] == ("bash", "-c", "cat tracked.txt")
                and TRUSTED_CONTAINER_ID in call[0]
                for call in runner.calls
            )
        )
        state = read_audit_docker_broker_state(self.prepared.state_path)
        self.assertTrue(state.limit_breach)
        self.assertEqual("execution_failed", state.terminal_receipts[0].state)

    def test_snapshot_root_identity_drift_refuses_trusted_start(self) -> None:
        runner = MutatingWorkspaceDockerRunner(self.snapshot_dir)
        self._install(trusted_command_scripts=("cat tracked.txt",))
        self._advance_to_terminal(runner=runner)
        self.snapshot_dir.chmod(0o755)
        try:
            result = self._invoke(
                "exec",
                CONTAINER_ID,
                "bash",
                "-c",
                "cat tracked.txt",
                runner=runner,
            )
        finally:
            self.snapshot_dir.chmod(0o700)

        self.assertEqual(126, result.returncode)
        self.assertNotIn(
            ("start", TRUSTED_CONTAINER_ID),
            [call[0][1:] for call in runner.calls],
        )

    def test_broker_revalidates_full_trusted_isolation_before_each_start(self) -> None:
        self._install(trusted_command_scripts=("cat tracked.txt",))
        state = read_audit_docker_broker_state(self.prepared.state_path)
        mutations = {
            "environment": (12, ["HOME=/tmp"]),
            "pid namespace": (20, "host"),
            "uts namespace": (22, "host"),
            "user namespace": (23, "host"),
            "cgroup namespace": (24, "host"),
            "device": (25, [{"PathOnHost": "/dev/null"}]),
            "port": (29, {"80/tcp": [{"HostPort": "8080"}]}),
            "requested mount": (35, []),
            "log persistence": (37, {"Type": "json-file", "Config": {}}),
            "effective mount": (39, []),
            "effective network": (41, {"bridge": {}}),
        }
        for name, (index, replacement) in mutations.items():
            with self.subTest(name=name):
                fields = list(_trusted_state_fields(self.snapshot_dir, running=False))
                fields[index] = replacement
                result = BrokerCommandResult(
                    returncode=0,
                    stdout=_encode_trusted_fields(tuple(fields)),
                    stderr=b"",
                )
                self.assertFalse(
                    audit_docker_broker._trusted_state_matches(
                        state,
                        result,
                        running=False,
                    )
                )

    def test_trusted_container_timeout_is_validated_and_removed_without_orphan(self) -> None:
        runner = TimedOutTrustedContainerRunner(self.snapshot_dir)
        self._install(trusted_command_scripts=("cat tracked.txt",))
        self._advance_to_terminal(runner=runner)

        result = self._invoke(
            "exec",
            CONTAINER_ID,
            "bash",
            "-c",
            "cat tracked.txt",
            runner=runner,
        )

        self.assertEqual(126, result.returncode)
        real_arguments = [call[0][1:] for call in runner.calls]
        self.assertIn(("rm", "-f", runner.trusted_id), real_arguments)
        trusted_remove_index = real_arguments.index(("rm", "-f", runner.trusted_id))
        main_remove_index = real_arguments.index(("rm", "-f", CONTAINER_ID))
        self.assertLess(trusted_remove_index, main_remove_index)
        state = read_audit_docker_broker_state(self.prepared.state_path)
        self.assertTrue(state.limit_breach)
        self.assertEqual("terminal execution failure", state.breach_reason)
        self.assertEqual("execution_failed", state.terminal_receipts[0].state)

    def test_missing_trusted_container_cleanup_is_idempotent_and_removes_main(self) -> None:
        runner = MissingTrustedContainerRunner()
        self._install(trusted_command_scripts=("cat tracked.txt",))
        self._advance_to_terminal(runner=runner)

        result = self._invoke("rm", "-f", CONTAINER_ID, runner=runner)

        self.assertEqual(0, result.returncode)
        real_arguments = [call[0][1:] for call in runner.calls]
        self.assertIn(
            (
                "ps",
                "--all",
                "--no-trunc",
                "--filter",
                f"id={TRUSTED_CONTAINER_ID}",
                "--format",
                "{{.ID}}",
            ),
            real_arguments,
        )
        self.assertIn(("rm", "-f", CONTAINER_ID), real_arguments)
        self.assertNotIn(("rm", "-f", TRUSTED_CONTAINER_ID), real_arguments)
        state = read_audit_docker_broker_state(self.prepared.state_path)
        self.assertEqual("complete", state.cleanup_state)
        self.assertEqual("closed", state.phase)

    def test_nonzero_terminal_exit_is_recorded_without_changing_command_output(self) -> None:
        self._install()
        self._advance_to_terminal()
        self.runner.command_results["secret-bearing-command"] = BrokerCommandResult(
            returncode=7,
            stdout=b"public-output",
            stderr=b"public-error",
        )

        result = self._invoke(
            "exec",
            CONTAINER_ID,
            "bash",
            "-c",
            "secret-bearing-command",
        )

        self.assertEqual(7, result.returncode)
        self.assertEqual(b"public-output", result.stdout)
        self.assertEqual(b"public-error", result.stderr)
        state = read_audit_docker_broker_state(self.prepared.state_path)
        receipt = state.terminal_receipts[0]
        self.assertEqual("exited", receipt.state)
        self.assertEqual(7, receipt.returncode)
        self.assertEqual(len(result.stdout), receipt.stdout_bytes)
        self.assertEqual(len(result.stderr), receipt.stderr_bytes)
        state_bytes = self.prepared.state_path.read_bytes()
        self.assertNotIn(b"secret-bearing-command", state_bytes)
        self.assertNotIn(b"public-output", state_bytes)
        self.assertNotIn(b"public-error", state_bytes)

    def test_protocol_removal_refuses_each_outstanding_terminal_signal(self) -> None:
        self._install()
        state = read_audit_docker_broker_state(self.prepared.state_path)
        terminal = replace(
            state,
            phase="terminal",
            bootstrap_complete=True,
            session_id="0123456789ab",
        )
        inflight = AuditCommandReceipt(
            receipt_id="terminal-000001",
            sequence=1,
            command_tag="hmac-sha256:" + "a" * 64,
            state="inflight",
            returncode=None,
            duration_ms=None,
            stdout_bytes=None,
            stderr_bytes=None,
        )
        scenarios = {
            "active call": replace(terminal, active_terminal_calls=1),
            "output reservation": replace(
                terminal,
                aggregate_reserved_output_bytes=terminal.per_call_reserved_output_bytes,
            ),
            "inflight receipt": replace(
                terminal,
                terminal_calls=1,
                terminal_receipts=(inflight,),
            ),
        }

        for name, pending in scenarios.items():
            for timing, now in (
                ("within deadline", time.monotonic()),
                ("after deadline", pending.deadline + 1),
            ):
                with self.subTest(name=name, timing=timing):
                    decision = audit_docker_broker._decide(
                        pending,
                        ("rm", "-f", CONTAINER_ID),
                        now,
                    )
                    self.assertEqual("refuse", decision.kind)
                    self.assertEqual(pending, decision.state)

    def test_concurrent_removal_waits_for_terminal_reservation_release(self) -> None:
        runner = BlockingDockerRunner()
        self._install(runner=runner)
        self._advance_to_terminal(runner=runner)
        result: list[BrokerCommandResult] = []
        worker = threading.Thread(
            target=lambda: result.append(
                self._invoke(
                    "exec",
                    CONTAINER_ID,
                    "bash",
                    "-c",
                    "first",
                    runner=runner,
                )
            )
        )
        worker.start()
        self.assertTrue(runner.started.wait(timeout=2))
        try:
            refused = self._invoke("rm", "-f", CONTAINER_ID, runner=runner)
            self.assertEqual(126, refused.returncode)
            self.assertNotIn(
                ("rm", "-f", CONTAINER_ID),
                [call[0][1:] for call in runner.calls],
            )
            pending = read_audit_docker_broker_state(self.prepared.state_path)
            self.assertEqual(1, pending.active_terminal_calls)
            self.assertEqual(
                pending.per_call_reserved_output_bytes,
                pending.aggregate_reserved_output_bytes,
            )
        finally:
            runner.release.set()
            worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(0, result[0].returncode)

        removed = self._invoke("rm", "-f", CONTAINER_ID, runner=runner)
        self.assertEqual(0, removed.returncode)
        self.assertEqual(
            1,
            [call[0][1:] for call in runner.calls].count(("rm", "-f", CONTAINER_ID)),
        )

    def test_closed_state_rejects_outstanding_terminal_work(self) -> None:
        self._install()
        state = read_audit_docker_broker_state(self.prepared.state_path)
        inflight = AuditCommandReceipt(
            receipt_id="terminal-000001",
            sequence=1,
            command_tag="hmac-sha256:" + "a" * 64,
            state="inflight",
            returncode=None,
            duration_ms=None,
            stdout_bytes=None,
            stderr_bytes=None,
        )
        invalid = replace(
            state,
            phase="closed",
            cleanup_state="complete",
            terminal_calls=1,
            active_terminal_calls=1,
            aggregate_reserved_output_bytes=state.per_call_reserved_output_bytes,
            terminal_receipts=(inflight,),
        )

        with self.assertRaises(AuditDockerBrokerError):
            audit_docker_broker._decode_state(audit_docker_broker._state_bytes(invalid))

    def test_malformed_state_always_raises_broker_error(self) -> None:
        malformed_states = (
            b"",
            b"{}",
            b'{"schema_version":2}',
            b'{"schema_version":999,"unknown":true}',
        )

        for data in malformed_states:
            with self.subTest(data=data), self.assertRaises(AuditDockerBrokerError):
                audit_docker_broker._decode_state(data)

    def test_schema_v1_state_remains_readable(self) -> None:
        self._install()
        with audit_docker_broker._locked_state(self.prepared.state_path) as locked:
            current = audit_docker_broker._read_state_unlocked(locked)
            audit_docker_broker._write_state_unlocked(
                locked,
                replace(current, schema_version=1),
            )

        legacy = read_audit_docker_broker_state(self.prepared.state_path)

        self.assertEqual(1, legacy.schema_version)
        self.assertEqual("expect_version", legacy.phase)
        self.assertIsNone(legacy.target_commit)
        self.assertIsNone(legacy.snapshot_digest)
        self.assertIsNone(legacy.receipt_hmac_key)
        self.assertEqual((), legacy.terminal_receipts)

    def test_storage_probe_is_optional_and_emulated_without_create_or_run(self) -> None:
        self._install()
        self.assertEqual(0, self._invoke("version").returncode)
        self.assertEqual(
            0,
            self._invoke(
                "run",
                "--rm",
                "--cpus",
                "0.5",
                "--memory",
                "64m",
                "--pids-limit",
                "32",
                IMAGE_REF,
                "sleep",
                "0",
            ).returncode,
        )
        image = self._invoke(
            "image",
            "inspect",
            IMAGE_REF,
            "--format",
            "{{json .Config.Entrypoint}}",
        )
        self.assertEqual(0, image.returncode)
        self.assertEqual(
            [
                (
                    "image",
                    "inspect",
                    IMAGE_REF,
                    "--format",
                    "{{json .Config.Entrypoint}}",
                )
            ],
            [call[0][1:] for call in self.runner.calls],
        )

    def test_reordered_or_mutated_protocol_permanently_breaches_and_cleans_sealed_id(self) -> None:
        invalid_initial_calls = (
            ("exec", CONTAINER_ID, "bash", "-c", "true"),
            ("run", "-d", IMAGE_REF),
            ("create", IMAGE_REF),
            ("start", CONTAINER_ID),
            ("stop", CONTAINER_ID),
            ("version", "--format", "json"),
        )
        for arguments in invalid_initial_calls:
            with self.subTest(arguments=arguments):
                self.temporary_directory.cleanup()
                self.setUp()
                self._install()
                result = self._invoke(*arguments)
                self.assertEqual(126, result.returncode)
                self.assertNotIn(CONTAINER_ID.encode("ascii"), result.stderr)
                self.assertEqual(
                    [("rm", "-f", CONTAINER_ID)],
                    [call[0][1:] for call in self.runner.calls],
                )
                state = read_audit_docker_broker_state(self.prepared.state_path)
                self.assertTrue(state.limit_breach)
                self.assertEqual("breached", state.phase)
                self.assertEqual("complete", state.cleanup_state)
                refused = self._invoke("version")
                self.assertEqual(126, refused.returncode)
                self.assertEqual(1, len(self.runner.calls))

    def test_exact_labels_image_profile_and_network_identity_are_sealed(self) -> None:
        mutations = (
            (
                "image",
                "inspect",
                "registry.example.invalid/other@sha256:" + "e" * 64,
                "--format",
                "{{json .Config.Entrypoint}}",
            ),
            (
                "ps",
                "-a",
                "--filter",
                "label=hermes-agent=1",
                "--filter",
                "label=hermes-task-id=other",
                "--filter",
                f"label=hermes-profile={PROFILE}",
                "--format",
                '{{.ID}}\t{{.State}}\t{{.Label "hermes-egress"}}',
            ),
            (
                "inspect",
                "--format",
                "{{.HostConfig.NetworkMode}}",
                OTHER_CONTAINER_ID,
            ),
        )
        phases = (2, 3, 4)
        for arguments, phase in zip(mutations, phases, strict=True):
            with self.subTest(arguments=arguments):
                self.temporary_directory.cleanup()
                self.setUp()
                self._install()
                self.assertEqual(0, self._invoke("version").returncode)
                self.assertEqual(
                    0,
                    self._invoke(
                        "run",
                        "--rm",
                        "--cpus",
                        "0.5",
                        "--memory",
                        "64m",
                        "--pids-limit",
                        "32",
                        IMAGE_REF,
                        "sleep",
                        "0",
                    ).returncode,
                )
                if phase >= 3:
                    self.assertEqual(
                        0,
                        self._invoke(
                            "image",
                            "inspect",
                            IMAGE_REF,
                            "--format",
                            "{{json .Config.Entrypoint}}",
                        ).returncode,
                    )
                if phase >= 4:
                    self.assertEqual(
                        0,
                        self._invoke(
                            "ps",
                            "-a",
                            "--filter",
                            "label=hermes-agent=1",
                            "--filter",
                            "label=hermes-task-id=default",
                            "--filter",
                            f"label=hermes-profile={PROFILE}",
                            "--format",
                            '{{.ID}}\t{{.State}}\t{{.Label "hermes-egress"}}',
                        ).returncode,
                    )
                result = self._invoke(*arguments)
                self.assertEqual(126, result.returncode)
                self.assertEqual(
                    ("rm", "-f", CONTAINER_ID),
                    self.runner.calls[-1][0][1:],
                )

    def test_exec_rejects_other_ids_flags_duplicate_bootstrap_and_trailing_arguments(self) -> None:
        mutations = (
            ("exec", OTHER_CONTAINER_ID, "bash", "-c", "true"),
            ("exec", "--user", "root", CONTAINER_ID, "bash", "-c", "true"),
            ("exec", CONTAINER_ID, "bash", "-lc", "true"),
            ("exec", CONTAINER_ID, "bash", "-c", "true", "--privileged"),
            (
                "exec",
                CONTAINER_ID,
                "bash",
                "-l",
                "-c",
                _bootstrap_script("0123456789ab"),
            ),
            ("exec", CONTAINER_ID, "bash", "-c", "true", "--network=host"),
        )
        for arguments in mutations:
            with self.subTest(arguments=arguments):
                self.temporary_directory.cleanup()
                self.setUp()
                self._install()
                self._advance_to_terminal()
                before = len(self.runner.calls)
                result = self._invoke(*arguments)
                self.assertEqual(126, result.returncode)
                self.assertEqual(before + 1, len(self.runner.calls))
                self.assertEqual(
                    ("rm", "-f", CONTAINER_ID),
                    self.runner.calls[-1][0][1:],
                )

    def test_bootstrap_script_must_match_the_pinned_0200_shape(self) -> None:
        mutations = (
            _bootstrap_script("0123456789ab").replace("/workspace", "/root"),
            _bootstrap_script("0123456789ab").replace("umask 077", "umask 022"),
            _bootstrap_script("0123456789ab").replace(
                "hermes-snap-0123456789ab", "hermes-snap-fedcba987654", 1
            ),
            _bootstrap_script("0123456789ab") + "true\n",
        )
        for script in mutations:
            with self.subTest(script=script[-80:]):
                self.temporary_directory.cleanup()
                self.setUp()
                self._install()
                self.assertEqual(0, self._invoke("version").returncode)
                self.assertEqual(
                    0,
                    self._invoke(
                        "run",
                        "--rm",
                        "--cpus",
                        "0.5",
                        "--memory",
                        "64m",
                        "--pids-limit",
                        "32",
                        IMAGE_REF,
                        "sleep",
                        "0",
                    ).returncode,
                )
                self.assertEqual(
                    0,
                    self._invoke(
                        "image",
                        "inspect",
                        IMAGE_REF,
                        "--format",
                        "{{json .Config.Entrypoint}}",
                    ).returncode,
                )
                self.assertEqual(
                    0,
                    self._invoke(
                        "ps",
                        "-a",
                        "--filter",
                        "label=hermes-agent=1",
                        "--filter",
                        "label=hermes-task-id=default",
                        "--filter",
                        f"label=hermes-profile={PROFILE}",
                        "--format",
                        '{{.ID}}\t{{.State}}\t{{.Label "hermes-egress"}}',
                    ).returncode,
                )
                self.assertEqual(
                    0,
                    self._invoke(
                        "inspect",
                        "--format",
                        "{{.HostConfig.NetworkMode}}",
                        CONTAINER_ID,
                    ).returncode,
                )
                self.assertEqual(
                    126,
                    self._invoke(
                        "exec",
                        CONTAINER_ID,
                        "bash",
                        "-l",
                        "-c",
                        script,
                    ).returncode,
                )

    def test_terminal_output_call_argv_and_deadline_limits_fail_closed(self) -> None:
        cases = (
            (
                replace(
                    HARD_LIMITS,
                    terminal_output_per_call_bytes=4,
                    terminal_output_total_bytes=8,
                ),
                "oversized",
                BrokerCommandResult(returncode=0, stdout=b"12345", stderr=b""),
            ),
            (
                replace(HARD_LIMITS, terminal_calls=1),
                "second-call",
                BrokerCommandResult(returncode=0, stdout=b"", stderr=b""),
            ),
        )
        for limits, command, command_result in cases:
            with self.subTest(command=command):
                self.temporary_directory.cleanup()
                self.setUp()
                self._install(limits=limits)
                self._advance_to_terminal()
                if command == "second-call":
                    self.assertEqual(
                        0,
                        self._invoke("exec", CONTAINER_ID, "bash", "-c", "first").returncode,
                    )
                self.runner.command_results[command] = command_result
                self.assertEqual(
                    126,
                    self._invoke("exec", CONTAINER_ID, "bash", "-c", command).returncode,
                )
                state = read_audit_docker_broker_state(self.prepared.state_path)
                self.assertTrue(state.limit_breach)
                self.assertEqual(0, state.aggregate_reserved_output_bytes)

        self.temporary_directory.cleanup()
        self.setUp()
        self._install()
        self._advance_to_terminal()
        huge_command = "x" * (256 * 1024 + 1)
        self.assertEqual(
            126,
            self._invoke("exec", CONTAINER_ID, "bash", "-c", huge_command).returncode,
        )

        self.temporary_directory.cleanup()
        self.setUp()
        expired = time.monotonic() + 1
        self._install(deadline=expired)
        self.assertEqual(
            126,
            self._invoke("version", clock=lambda: expired + 1).returncode,
        )

    def test_concurrent_terminal_call_reserves_full_budget_before_launch(self) -> None:
        runner = BlockingDockerRunner()
        limits = replace(
            HARD_LIMITS,
            terminal_output_per_call_bytes=8,
            terminal_output_total_bytes=8,
        )
        self._install(runner=runner, limits=limits)
        self._advance_to_terminal(runner=runner)
        result: list[BrokerCommandResult] = []

        worker = threading.Thread(
            target=lambda: result.append(
                self._invoke(
                    "exec",
                    CONTAINER_ID,
                    "bash",
                    "-c",
                    "first",
                    runner=runner,
                )
            )
        )
        worker.start()
        self.assertTrue(runner.started.wait(timeout=2))
        state = read_audit_docker_broker_state(self.prepared.state_path)
        self.assertEqual(8, state.aggregate_reserved_output_bytes)
        self.assertEqual(1, state.active_terminal_calls)

        second = self._invoke(
            "exec",
            CONTAINER_ID,
            "bash",
            "-c",
            "second",
            runner=runner,
        )
        self.assertEqual(126, second.returncode)
        self.assertNotIn(
            ("exec", CONTAINER_ID, "bash", "-c", "second"),
            [call[0][1:] for call in runner.calls],
        )
        runner.release.set()
        worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(126, result[0].returncode)
        final = read_audit_docker_broker_state(self.prepared.state_path)
        self.assertTrue(final.limit_breach)
        self.assertEqual(0, final.aggregate_reserved_output_bytes)
        self.assertEqual(0, final.active_terminal_calls)

    def test_real_control_validation_does_not_advance_phase_while_in_flight(self) -> None:
        runner = BlockingImageRunner()
        self.runner = runner
        self._install()
        self.assertEqual(0, self._invoke("version").returncode)
        self.assertEqual(
            0,
            self._invoke(
                "run",
                "--rm",
                "--cpus",
                "0.5",
                "--memory",
                "64m",
                "--pids-limit",
                "32",
                IMAGE_REF,
                "sleep",
                "0",
            ).returncode,
        )
        result: list[BrokerCommandResult] = []
        worker = threading.Thread(
            target=lambda: result.append(
                self._invoke(
                    "image",
                    "inspect",
                    IMAGE_REF,
                    "--format",
                    "{{json .Config.Entrypoint}}",
                )
            )
        )
        worker.start()
        self.assertTrue(runner.started.wait(timeout=2))
        try:
            state = read_audit_docker_broker_state(self.prepared.state_path)
            self.assertEqual("image_inflight", state.phase)

            reordered = self._invoke(
                "ps",
                "-a",
                "--filter",
                "label=hermes-agent=1",
                "--filter",
                "label=hermes-task-id=default",
                "--filter",
                f"label=hermes-profile={PROFILE}",
                "--format",
                '{{.ID}}\t{{.State}}\t{{.Label "hermes-egress"}}',
            )
            self.assertEqual(126, reordered.returncode)
        finally:
            runner.release.set()
            worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(126, result[0].returncode)
        final = read_audit_docker_broker_state(self.prepared.state_path)
        self.assertEqual("breached", final.phase)
        self.assertEqual("complete", final.cleanup_state)

    def test_network_or_image_inspection_drift_breaches_before_exec(self) -> None:
        scenarios = (
            (
                (
                    "image",
                    "inspect",
                    IMAGE_REF,
                    "--format",
                    "{{json .Config.Entrypoint}}",
                ),
                BrokerCommandResult(returncode=0, stdout=b"not-json\n", stderr=b""),
            ),
            (
                ("inspect", "--format", "{{.HostConfig.NetworkMode}}", CONTAINER_ID),
                BrokerCommandResult(returncode=0, stdout=b"bridge\n", stderr=b""),
            ),
        )
        for target, bad_result in scenarios:
            with self.subTest(target=target):
                self.temporary_directory.cleanup()
                self.setUp()

                class DriftRunner(FakeDockerRunner):
                    def __init__(
                        nested_self,
                        expected_arguments: tuple[str, ...],
                        result: BrokerCommandResult,
                    ) -> None:
                        super().__init__()
                        nested_self.expected_arguments = expected_arguments
                        nested_self.result = result

                    def run(
                        nested_self,
                        argv: tuple[str, ...],
                        *,
                        deadline: float,
                        output_limit: int,
                        env: dict[str, str],
                    ) -> BrokerCommandResult:
                        if argv[1:] == nested_self.expected_arguments:
                            nested_self.calls.append((argv, deadline, output_limit, env))
                            return nested_self.result
                        return super().run(
                            argv,
                            deadline=deadline,
                            output_limit=output_limit,
                            env=env,
                        )

                runner = DriftRunner(target, bad_result)
                self.runner = runner
                self._install()
                self.assertEqual(0, self._invoke("version").returncode)
                self.assertEqual(
                    0,
                    self._invoke(
                        "run",
                        "--rm",
                        "--cpus",
                        "0.5",
                        "--memory",
                        "64m",
                        "--pids-limit",
                        "32",
                        IMAGE_REF,
                        "sleep",
                        "0",
                    ).returncode,
                )
                if target[0] == "inspect":
                    self.assertEqual(
                        0,
                        self._invoke(
                            "image",
                            "inspect",
                            IMAGE_REF,
                            "--format",
                            "{{json .Config.Entrypoint}}",
                        ).returncode,
                    )
                    self.assertEqual(
                        0,
                        self._invoke(
                            "ps",
                            "-a",
                            "--filter",
                            "label=hermes-agent=1",
                            "--filter",
                            "label=hermes-task-id=default",
                            "--filter",
                            f"label=hermes-profile={PROFILE}",
                            "--format",
                            '{{.ID}}\t{{.State}}\t{{.Label "hermes-egress"}}',
                        ).returncode,
                    )
                self.assertEqual(126, self._invoke(*target).returncode)
                self.assertEqual(
                    ("rm", "-f", CONTAINER_ID),
                    runner.calls[-1][0][1:],
                )

    def test_cleanup_helper_removes_only_the_sealed_container(self) -> None:
        self._install()
        result = cleanup_audit_docker_broker(
            self.prepared.state_path,
            runner=self.runner,
        )
        self.assertEqual(0, result.returncode)
        self.assertEqual(
            [("rm", "-f", CONTAINER_ID)],
            [call[0][1:] for call in self.runner.calls],
        )
        state = read_audit_docker_broker_state(self.prepared.state_path)
        self.assertEqual("closed", state.phase)
        self.assertEqual("complete", state.cleanup_state)

    def test_cleanup_has_one_owner_under_concurrent_callers(self) -> None:
        runner = BlockingRemovalRunner()
        self._install()
        result: list[BrokerCommandResult] = []
        worker = threading.Thread(
            target=lambda: result.append(
                cleanup_audit_docker_broker(
                    self.prepared.state_path,
                    runner=runner,
                )
            )
        )
        worker.start()
        self.assertTrue(runner.started.wait(timeout=2))
        try:
            second = cleanup_audit_docker_broker(
                self.prepared.state_path,
                runner=runner,
            )
            self.assertEqual(126, second.returncode)
            self.assertEqual(1, len(runner.calls))
        finally:
            runner.release.set()
            worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(0, result[0].returncode)
        state = read_audit_docker_broker_state(self.prepared.state_path)
        self.assertEqual("complete", state.cleanup_state)

    def test_protocol_breach_cannot_steal_an_active_cleanup_claim(self) -> None:
        runner = BlockingRemovalRunner()
        self._install()
        result: list[BrokerCommandResult] = []
        worker = threading.Thread(
            target=lambda: result.append(
                cleanup_audit_docker_broker(
                    self.prepared.state_path,
                    runner=runner,
                )
            )
        )
        worker.start()
        self.assertTrue(runner.started.wait(timeout=2))
        try:
            refused = self._invoke("unexpected", runner=runner)
            self.assertEqual(126, refused.returncode)
            self.assertEqual(1, len(runner.calls))
            running = read_audit_docker_broker_state(self.prepared.state_path)
            self.assertEqual("running", running.cleanup_state)
        finally:
            runner.release.set()
            worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(0, result[0].returncode)
        self.assertEqual(1, len(runner.calls))

    def test_expired_cleanup_claim_can_be_recovered(self) -> None:
        self._install()
        with audit_docker_broker._locked_state(self.prepared.state_path) as locked:
            state = audit_docker_broker._read_state_unlocked(locked)
            stale = replace(
                state,
                cleanup_state="running",
                cleanup_owner="e" * 32,
                cleanup_lease_deadline=100.0,
            )
            audit_docker_broker._write_state_unlocked(locked, stale)

        result = cleanup_audit_docker_broker(
            self.prepared.state_path,
            runner=self.runner,
            clock=lambda: 101.0,
        )
        self.assertEqual(0, result.returncode)
        self.assertEqual(
            [("rm", "-f", CONTAINER_ID)],
            [call[0][1:] for call in self.runner.calls],
        )
        recovered = read_audit_docker_broker_state(self.prepared.state_path)
        self.assertEqual("complete", recovered.cleanup_state)
        self.assertIsNone(recovered.cleanup_owner)
        self.assertIsNone(recovered.cleanup_lease_deadline)

    def test_overall_deadline_reclaims_orphaned_control_and_terminal_execution(self) -> None:
        cases = (
            ("image_inflight", 0),
            ("terminal", 1),
        )
        for index, (phase, active_calls) in enumerate(cases):
            with self.subTest(phase=phase):
                broker_dir = self.root / f"orphan-{index}"
                broker_dir.mkdir(mode=0o700)
                prepared = replace(
                    self.prepared,
                    broker_dir=broker_dir,
                    state_path=broker_dir / "state.json",
                )
                sealed_deadline = time.monotonic() + 1
                install_audit_docker_broker(
                    prepared,
                    docker_executable=self.trusted_executable,
                    limits=HARD_LIMITS,
                    deadline=sealed_deadline,
                    python_executable=self.trusted_executable,
                    target_commit=TARGET_COMMIT,
                    snapshot_digest=SNAPSHOT_DIGEST,
                )
                with audit_docker_broker._locked_state(prepared.state_path) as locked:
                    state = audit_docker_broker._read_state_unlocked(locked)
                    orphaned = replace(
                        state,
                        phase=phase,
                        terminal_calls=active_calls,
                        active_terminal_calls=active_calls,
                        aggregate_reserved_output_bytes=(
                            state.per_call_reserved_output_bytes * active_calls
                        ),
                        terminal_receipts=(
                            (
                                AuditCommandReceipt(
                                    receipt_id="terminal-000001",
                                    sequence=1,
                                    command_tag="hmac-sha256:" + "a" * 64,
                                    state="inflight",
                                    returncode=None,
                                    duration_ms=None,
                                    stdout_bytes=None,
                                    stderr_bytes=None,
                                ),
                            )
                            if active_calls
                            else ()
                        ),
                    )
                    audit_docker_broker._write_state_unlocked(locked, orphaned)

                runner = FakeDockerRunner()
                result = cleanup_audit_docker_broker(
                    prepared.state_path,
                    runner=runner,
                    clock=lambda deadline=sealed_deadline: deadline + 1,
                )
                self.assertEqual(0, result.returncode)
                self.assertEqual(
                    [("rm", "-f", CONTAINER_ID)],
                    [call[0][1:] for call in runner.calls],
                )
                recovered = read_audit_docker_broker_state(prepared.state_path)
                self.assertEqual("breached", recovered.phase)
                self.assertEqual("complete", recovered.cleanup_state)
                self.assertEqual(0, recovered.active_terminal_calls)
                self.assertEqual(0, recovered.aggregate_reserved_output_bytes)

    def test_installation_rejects_unsafe_or_mismatched_seals(self) -> None:
        unsafe = replace(self.prepared, container_id="../other")
        with self.assertRaises(AuditDockerBrokerError):
            install_audit_docker_broker(
                unsafe,
                docker_executable=self.trusted_executable,
                limits=HARD_LIMITS,
                deadline=self.deadline,
                python_executable=self.trusted_executable,
                target_commit=TARGET_COMMIT,
                snapshot_digest=SNAPSHOT_DIGEST,
            )

        self.broker_dir.chmod(0o755)
        with self.assertRaises(AuditDockerBrokerError):
            self._install()

    def test_installation_accepts_a_resolved_system_owned_docker_executable(self) -> None:
        system_executable = Path("/usr/bin/true")
        metadata = system_executable.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid == os.geteuid()
            or metadata.st_mode & stat.S_IXUSR == 0
        ):
            self.skipTest("no distinct system-owned executable is available")
        executable = install_audit_docker_broker(
            self.prepared,
            docker_executable=system_executable,
            limits=HARD_LIMITS,
            deadline=self.deadline,
            python_executable=self.trusted_executable,
            target_commit=TARGET_COMMIT,
            snapshot_digest=SNAPSHOT_DIGEST,
        )
        self.assertEqual(self.broker_dir / "docker", executable)

    def test_installation_rejects_group_or_world_writable_executables(self) -> None:
        unsafe_executable = self.root / "unsafe-docker"
        unsafe_executable.write_bytes(b"#!/bin/sh\nexit 0\n")
        unsafe_executable.chmod(0o720)
        with self.assertRaises(AuditDockerBrokerError):
            install_audit_docker_broker(
                self.prepared,
                docker_executable=unsafe_executable,
                limits=HARD_LIMITS,
                deadline=self.deadline,
                python_executable=self.trusted_executable,
                target_commit=TARGET_COMMIT,
                snapshot_digest=SNAPSHOT_DIGEST,
            )

    def test_installation_rejects_executables_owned_by_an_unrelated_user(self) -> None:
        unsafe_executable = self.root / "foreign-docker"
        unsafe_executable.write_bytes(b"#!/bin/sh\nexit 0\n")
        unsafe_executable.chmod(0o700)
        metadata = unsafe_executable.lstat()
        foreign_metadata = os.stat_result(
            (
                metadata.st_mode,
                metadata.st_ino,
                metadata.st_dev,
                metadata.st_nlink,
                os.geteuid() + 1,
                metadata.st_gid,
                metadata.st_size,
                metadata.st_atime,
                metadata.st_mtime,
                metadata.st_ctime,
            )
        )
        original_lstat = Path.lstat

        def foreign_lstat(path: Path) -> os.stat_result:
            if path == unsafe_executable:
                return foreign_metadata
            return original_lstat(path)

        with (
            mock.patch.object(Path, "lstat", foreign_lstat),
            self.assertRaises(AuditDockerBrokerError),
        ):
            install_audit_docker_broker(
                self.prepared,
                docker_executable=unsafe_executable,
                limits=HARD_LIMITS,
                deadline=self.deadline,
                python_executable=self.trusted_executable,
                target_commit=TARGET_COMMIT,
                snapshot_digest=SNAPSHOT_DIGEST,
            )

    def test_deadline_is_resampled_after_waiting_for_the_state_lock(self) -> None:
        deadline = time.monotonic() + 0.05
        self._install(deadline=deadline)
        lock = (self.broker_dir / "state.lock").open("ab", buffering=0)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        result: list[BrokerCommandResult] = []
        worker = threading.Thread(target=lambda: result.append(self._invoke("version")))
        worker.start()
        time.sleep(0.1)
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()
        worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(126, result[0].returncode)
        state = read_audit_docker_broker_state(self.prepared.state_path)
        self.assertEqual("breached", state.phase)

    def test_state_lock_acquisition_has_a_hard_wait_bound(self) -> None:
        self._install()
        lock = (self.broker_dir / "state.lock").open("ab", buffering=0)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        started = time.monotonic()
        try:
            with (
                mock.patch("zeus.audit_docker_broker_core._LOCK_WAIT_SECONDS", 0.05),
                self.assertRaises(AuditDockerBrokerError),
            ):
                self._invoke("version")
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()
        self.assertLess(time.monotonic() - started, 0.5)

    def test_state_updates_stay_bound_to_the_pinned_directory_descriptor(self) -> None:
        self._install()
        initial_state = self.prepared.state_path.read_bytes()
        original_dir = self.root / "broker-original"
        rebound = False

        def rebind_after_lock() -> float:
            nonlocal rebound
            if not rebound:
                rebound = True
                self.broker_dir.rename(original_dir)
                self.broker_dir.mkdir(mode=0o700)
                self.prepared.state_path.write_bytes(initial_state)
                self.prepared.state_path.chmod(0o600)
                (self.broker_dir / "state.lock").write_bytes(b"")
                (self.broker_dir / "state.lock").chmod(0o600)
            return time.monotonic()

        with self.assertRaises(AuditDockerBrokerError):
            self._invoke("version", clock=rebind_after_lock)
        replacement = read_audit_docker_broker_state(self.prepared.state_path)
        self.assertEqual("expect_version", replacement.phase)

    def test_process_group_cleanup_kills_descendants_after_the_leader_exits(self) -> None:
        source = (
            "import signal,subprocess,sys,time\n"
            "child=subprocess.Popen([sys.executable,'-c',"
            '"import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); '
            'time.sleep(30)"])\n'
            "print(child.pid,flush=True)\n"
            "signal.signal(signal.SIGTERM,lambda *_: sys.exit(0))\n"
            "time.sleep(30)\n"
        )
        process = subprocess.Popen(
            [sys.executable, "-c", source],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            text=True,
        )
        self.assertIsNotNone(process.stdout)
        child_pid = int(process.stdout.readline().strip())
        try:
            audit_docker_broker._stop_process(process)
            child_gone = False
            end = time.monotonic() + 2
            while time.monotonic() < end:
                try:
                    os.kill(child_pid, 0)
                except ProcessLookupError:
                    child_gone = True
                    break
                time.sleep(0.02)
            self.assertTrue(child_gone)
        finally:
            with self.subTest("cleanup"):
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, 9)
                process.wait(timeout=2)
                process.stdout.close()

    def test_broker_files_are_private_and_contain_no_ambient_identity(self) -> None:
        executable = self._install()
        lock_path = self.broker_dir / "state.lock"
        self.assertEqual(0o700, stat.S_IMODE(self.broker_dir.lstat().st_mode))
        self.assertEqual(0o500, stat.S_IMODE(executable.lstat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(self.prepared.state_path.lstat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(lock_path.lstat().st_mode))
        state_data = self.prepared.state_path.read_bytes()
        self.assertNotIn(os.fsencode(Path.home()), state_data)


if __name__ == "__main__":
    unittest.main()
