from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

import zeus.audit_docker_broker_main as broker_main
from zeus.audit_docker_broker import AuditDockerBrokerError, BrokerCommandResult


class BinaryOutput:
    def __init__(self, *, fail: bool = False) -> None:
        self.buffer = self
        self.value = bytearray()
        self.fail = fail

    def write(self, value: bytes) -> int:
        if self.fail:
            raise BrokenPipeError
        self.value.extend(value)
        return len(value)

    def flush(self) -> None:
        if self.fail:
            raise OSError("flush failed")


class AuditDockerBrokerMainTests(unittest.TestCase):
    def test_absolute_executable_forwards_state_argv_and_output(self) -> None:
        stdout = BinaryOutput()
        stderr = BinaryOutput()
        result = BrokerCommandResult(7, b"out", b"err")
        with (
            mock.patch.object(broker_main.sys, "stdout", stdout),
            mock.patch.object(broker_main.sys, "stderr", stderr),
            mock.patch.object(
                broker_main, "invoke_audit_docker_broker", return_value=result
            ) as invoke,
        ):
            exit_code = broker_main.main(
                ["image", "inspect", "zeus"],
                executable_path=Path("/private/broker/docker"),
            )

        self.assertEqual(7, exit_code)
        self.assertEqual(
            mock.call(Path("/private/broker/state.json"), ("image", "inspect", "zeus")),
            invoke.call_args,
        )
        self.assertEqual(b"out", bytes(stdout.value))
        self.assertEqual(b"err", bytes(stderr.value))

    def test_relative_executable_is_resolved_from_cwd(self) -> None:
        stdout = BinaryOutput()
        stderr = BinaryOutput()
        with (
            mock.patch.object(broker_main.sys, "stdout", stdout),
            mock.patch.object(broker_main.sys, "stderr", stderr),
            mock.patch.object(broker_main.Path, "cwd", return_value=Path("/work")),
            mock.patch.object(
                broker_main,
                "invoke_audit_docker_broker",
                return_value=BrokerCommandResult(0, b"", b""),
            ) as invoke,
        ):
            exit_code = broker_main.main([], executable_path=Path("broker/docker"))

        self.assertEqual(0, exit_code)
        self.assertEqual(mock.call(Path("/work/broker/state.json"), ()), invoke.call_args)

    def test_defaults_to_process_argv_and_executable(self) -> None:
        stdout = BinaryOutput()
        stderr = BinaryOutput()
        with (
            mock.patch.object(
                broker_main.sys, "argv", ["broker/docker", "container", "inspect", "audit"]
            ),
            mock.patch.object(broker_main.sys, "stdout", stdout),
            mock.patch.object(broker_main.sys, "stderr", stderr),
            mock.patch.object(broker_main.Path, "cwd", return_value=Path("/work")),
            mock.patch.object(
                broker_main,
                "invoke_audit_docker_broker",
                return_value=BrokerCommandResult(0, b"", b""),
            ) as invoke,
        ):
            exit_code = broker_main.main()

        self.assertEqual(0, exit_code)
        self.assertEqual(
            mock.call(Path("/work/broker/state.json"), ("container", "inspect", "audit")),
            invoke.call_args,
        )

    def test_expected_broker_errors_are_redacted(self) -> None:
        errors = (
            AuditDockerBrokerError("sensitive broker failure"),
            OSError("sensitive OS failure"),
            TypeError("sensitive type failure"),
            ValueError("sensitive value failure"),
        )
        for error in errors:
            with self.subTest(error=type(error).__name__):
                stdout = BinaryOutput()
                stderr = BinaryOutput()
                with (
                    mock.patch.object(broker_main.sys, "stdout", stdout),
                    mock.patch.object(broker_main.sys, "stderr", stderr),
                    mock.patch.object(broker_main, "invoke_audit_docker_broker", side_effect=error),
                ):
                    exit_code = broker_main.main([], executable_path=Path("/private/broker/docker"))

                self.assertEqual(126, exit_code)
                self.assertEqual(b"", bytes(stdout.value))
                self.assertEqual(b"audit Docker broker refused request\n", bytes(stderr.value))
                self.assertNotIn(str(error).encode(), bytes(stderr.value))

    def test_output_failure_returns_126(self) -> None:
        result = BrokerCommandResult(0, b"out", b"err")
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream):
                stdout = BinaryOutput(fail=stream == "stdout")
                stderr = BinaryOutput(fail=stream == "stderr")
                with (
                    mock.patch.object(broker_main.sys, "stdout", stdout),
                    mock.patch.object(broker_main.sys, "stderr", stderr),
                    mock.patch.object(
                        broker_main, "invoke_audit_docker_broker", return_value=result
                    ),
                ):
                    exit_code = broker_main.main([], executable_path=Path("/private/broker/docker"))

                self.assertEqual(126, exit_code)


if __name__ == "__main__":
    unittest.main()
