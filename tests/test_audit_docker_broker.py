from __future__ import annotations

import fcntl
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
from zeus.audit_models import HARD_LIMITS

RUN_ID = "1" * 32
PROFILE = f"audit-{RUN_ID}"
IMAGE_REF = "registry.example.invalid/audit@sha256:" + "a" * 64
IMAGE_ID = "sha256:" + "b" * 64
CONTAINER_ID = "c" * 64
OTHER_CONTAINER_ID = "d" * 64


def _bootstrap_script(session_id: str) -> str:
    snapshot = f"/tmp/hermes-snap-{session_id}.sh"
    temporary = f"{snapshot}.tmp.$BASHPID"
    marker = f"__HERMES_CWD_{session_id}__"
    return (
        "umask 077\n"
        f"export -p > {temporary}\n"
        "__hermes_fns=$(declare -F | awk '{print $3}' | grep -vE '^_[^_]') || true\n"
        f'[ -n "$__hermes_fns" ] && declare -f $__hermes_fns >> {temporary} '
        "2>/dev/null || true\n"
        f"alias -p >> {temporary}\n"
        f"echo 'shopt -s expand_aliases' >> {temporary}\n"
        f"echo 'set +e' >> {temporary}\n"
        f"echo 'set +u' >> {temporary}\n"
        f"mv -f {temporary} {snapshot} || rm -f {temporary}\n"
        "builtin cd -- /workspace 2>/dev/null || true\n"
        f"""printf '\\n{marker}%s{marker}\\n' "$(pwd -P)"\n"""
    )


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

    def _install(
        self,
        *,
        runner: FakeDockerRunner | None = None,
        limits=HARD_LIMITS,
        deadline: float | None = None,
    ) -> Path:
        return install_audit_docker_broker(
            self.prepared,
            docker_executable=self.trusted_executable,
            limits=limits,
            deadline=self.deadline if deadline is None else deadline,
            python_executable=self.trusted_executable,
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
                "{{.ID}}\t{{.State}}",
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
                "{{.ID}}\t{{.State}}",
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
                            "{{.ID}}\t{{.State}}",
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

    def test_bootstrap_script_must_match_the_pinned_0190_shape(self) -> None:
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
                        "{{.ID}}\t{{.State}}",
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
                "{{.ID}}\t{{.State}}",
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
                            "{{.ID}}\t{{.State}}",
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
                )
                with audit_docker_broker._locked_state(prepared.state_path) as locked:
                    state = audit_docker_broker._read_state_unlocked(locked)
                    orphaned = replace(
                        state,
                        phase=phase,
                        active_terminal_calls=active_calls,
                        aggregate_reserved_output_bytes=(
                            state.per_call_reserved_output_bytes * active_calls
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
                mock.patch.object(audit_docker_broker, "_LOCK_WAIT_SECONDS", 0.05),
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
