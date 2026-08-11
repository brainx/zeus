from __future__ import annotations

import hashlib
import os
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import suppress
from pathlib import Path

import zeus.audit_workspace as audit_workspace
from zeus.audit_container import AuditContainerRuntime
from zeus.audit_docker_broker import (
    cleanup_audit_docker_broker,
    install_audit_docker_broker,
    invoke_audit_docker_broker,
    read_audit_docker_broker_state,
)
from zeus.audit_docker_broker_protocol import _expected_bootstrap_script
from zeus.audit_models import HARD_LIMITS, AuditCategory
from zeus.audit_surface import build_audit_surface
from zeus.audit_workspace import MaterializedSnapshot, SnapshotManifestEntry

_FIRST_TRUSTED_SCRIPT = r"""
import os, pathlib, socket, stat, subprocess, sys, time

workspace = pathlib.Path("/workspace")
committed = workspace / "committed.txt"
executable = workspace / "executable.sh"
expected_uid = int(sys.argv[5])
expected_gid = int(sys.argv[6])
assert os.getuid() == expected_uid
assert os.getgid() == expected_gid
assert os.getgroups() == [expected_gid]
assert {item.name for item in workspace.iterdir()} == {"committed.txt", "executable.sh"}
assert committed.read_bytes() == b"committed\n"
assert stat.S_IMODE(committed.stat().st_mode) == 0o600
assert executable.read_bytes() == b"#!/bin/sh\nprintf 'workspace-exec-ok\\n'\n"
assert stat.S_IMODE(executable.stat().st_mode) == 0o700
execution = subprocess.run(
    [str(executable)],
    stdin=subprocess.DEVNULL,
    capture_output=True,
    check=False,
)
assert execution.returncode == 0, execution.stderr
assert execution.stdout == b"workspace-exec-ok\n"
assert not (workspace / ".git").exists()

mount_options = {}
with open("/proc/self/mountinfo", encoding="ascii") as source:
    for line in source:
        fields = line.rstrip("\n").split(" ")
        if len(fields) > 5 and fields[4] in {"/workspace", "/tmp"}:
            mount_options[fields[4]] = set(fields[5].split(","))
assert "ro" in mount_options["/workspace"]
assert "rw" not in mount_options["/workspace"]
assert {"rw", "noexec", "nosuid", "nodev"}.issubset(mount_options["/tmp"])
for path in (
    workspace / "write-test",
    pathlib.Path("/rootfs-write-test"),
    pathlib.Path("/run/write-test"),
    pathlib.Path("/var/tmp/write-test"),
):
    try:
        path.write_text("no", encoding="utf-8")
    except OSError:
        pass
    else:
        raise AssertionError(f"unintended writable path: {path}")

with open("/proc/self/status", encoding="ascii") as source:
    process_status = dict(
        line.rstrip("\n").split(":\t", 1)
        for line in source
        if ":\t" in line
    )
assert process_status["NoNewPrivs"] == "1"
assert process_status["Seccomp"] == "2"
assert int(process_status["CapEff"], 16) == 0
assert {path.name for path in pathlib.Path("/sys/class/net").iterdir()} == {"lo"}
addresses = (
    ("1.1.1.1", 53),
    ("127.0.0.1", int(sys.argv[2])),
    (sys.argv[3], int(sys.argv[2])),
)
for address in addresses:
    sock = socket.socket()
    sock.settimeout(0.5)
    try:
        sock.connect(address)
    except OSError:
        pass
    else:
        raise AssertionError(f"network connection unexpectedly succeeded: {address}")
    finally:
        sock.close()
try:
    socket.getaddrinfo("example.com", 443)
except OSError:
    pass
else:
    raise AssertionError("DNS unexpectedly succeeded")

assert not pathlib.Path("/var/run/docker.sock").exists()
assert "ZEUS_AUDIT_HOST_SENTINEL" not in os.environ
assert not pathlib.Path(sys.argv[1]).exists()
marker = pathlib.Path("/tmp/persisted-across-command")
ready = pathlib.Path("/tmp/background-ready")
marker.write_text("first", encoding="ascii")
background_script = (
    "import pathlib,sys,time;"
    "pathlib.Path('/tmp/background-ready').write_text(sys.argv[1],encoding='ascii');"
    "time.sleep(120)"
)
subprocess.Popen(
    [sys.executable, "-I", "-c", background_script, sys.argv[4]],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    close_fds=True,
    start_new_session=True,
)
ready_deadline = time.monotonic() + 5
while not ready.exists() and time.monotonic() < ready_deadline:
    time.sleep(0.01)
assert ready.read_text(encoding="ascii") == sys.argv[4]
print("first-ok")
""".strip()


_SECOND_TRUSTED_SCRIPT = r"""
import os, pathlib, stat, sys

workspace = pathlib.Path("/workspace")
assert {item.name for item in workspace.iterdir()} == {"committed.txt", "executable.sh"}
assert (workspace / "committed.txt").read_bytes() == b"committed\n"
assert stat.S_IMODE((workspace / "committed.txt").stat().st_mode) == 0o600
try:
    (workspace / "second-write-test").write_text("no", encoding="utf-8")
except OSError:
    pass
else:
    raise AssertionError("trusted workspace became writable")

assert not pathlib.Path("/tmp/persisted-across-command").exists()
assert not pathlib.Path("/tmp/background-ready").exists()
second_temp = pathlib.Path("/tmp/second-command-write")
second_temp.write_text("second", encoding="ascii")
assert second_temp.read_text(encoding="ascii") == "second"
second_temp.unlink()

excluded_pids = set()
pid = os.getpid()
while pid > 0 and pid not in excluded_pids:
    excluded_pids.add(pid)
    try:
        status = pathlib.Path(f"/proc/{pid}/status").read_text(encoding="ascii")
    except OSError:
        break
    parent_lines = [line for line in status.splitlines() if line.startswith("PPid:\t")]
    if len(parent_lines) != 1:
        break
    pid = int(parent_lines[0].split("\t", 1)[1])
token = sys.argv[1].encode("ascii")
for command_line in pathlib.Path("/proc").glob("[0-9]*/cmdline"):
    if int(command_line.parent.name) in excluded_pids:
        continue
    try:
        arguments = command_line.read_bytes()
    except OSError:
        continue
    assert token not in arguments, (command_line, arguments)
print("second-ok")
""".strip()


@unittest.skipUnless(
    os.environ.get("ZEUS_RUN_DOCKER_ISOLATION") == "1",
    "set ZEUS_RUN_DOCKER_ISOLATION=1 to run the real Docker isolation test",
)
class RealDockerAuditIsolationTests(unittest.TestCase):
    def test_real_docker_isolation(self) -> None:
        docker_value = shutil.which("docker")
        if docker_value is None:
            self.skipTest("Docker executable is unavailable")
        if os.geteuid() == 0:
            self.skipTest("trusted audit execution intentionally rejects a root caller")
        image = os.environ.get("ZEUS_AUDIT_TEST_IMAGE")
        if image is None:
            self.skipTest("ZEUS_AUDIT_TEST_IMAGE is not configured")
        docker = Path(docker_value).resolve(strict=True)
        python_executable = Path(sys.executable).resolve(strict=True)
        status_before = self._git_status()
        tracked_sentinel = Path("pyproject.toml")
        tracked_hash_before = hashlib.sha256(tracked_sentinel.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            snapshot = self._snapshot(root)
            sentinel = root / "host-sentinel"
            sentinel.write_text("host-only\n", encoding="utf-8")
            bridge_gateway = self._bridge_gateway(docker)
            listener = socket.socket()
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("0.0.0.0", 0))
            listener.listen(2)
            listener.settimeout(0.2)
            listener_port = listener.getsockname()[1]
            accepted = threading.Event()
            stop_listener = threading.Event()

            def accept_connections() -> None:
                while not stop_listener.is_set():
                    try:
                        connection, _address = listener.accept()
                    except TimeoutError:
                        continue
                    except OSError:
                        return
                    accepted.set()
                    connection.close()

            listener_thread = threading.Thread(target=accept_connections, daemon=True)
            listener_thread.start()
            previous_sentinel = os.environ.get("ZEUS_AUDIT_HOST_SENTINEL")
            os.environ["ZEUS_AUDIT_HOST_SENTINEL"] = "caller-host-only"
            runtime = AuditContainerRuntime(docker, root / "control")
            prepared = None
            cleanup = None
            broker_installed = False
            broker_closed = False
            run_id = "7" * 32
            try:
                deadline = time.monotonic() + 180
                prepared = runtime.prepare(
                    run_id=run_id,
                    snapshot=snapshot,
                    image_ref=image,
                    limits=HARD_LIMITS,
                    deadline=deadline,
                    prepare_trusted_workspace=True,
                )
                runtime.validate(prepared)
                self.assertIsNotNone(prepared.trusted_container_id)
                self.assertIsNotNone(prepared.trusted_execution_uid)
                self.assertIsNotNone(prepared.trusted_execution_gid)
                child_token = "zeus-trusted-background-" + "6" * 32
                first_command = shlex.join(
                    (
                        "python3",
                        "-I",
                        "-c",
                        _FIRST_TRUSTED_SCRIPT,
                        str(sentinel),
                        str(listener_port),
                        bridge_gateway,
                        child_token,
                        str(prepared.trusted_execution_uid),
                        str(prepared.trusted_execution_gid),
                    )
                )
                second_command = shlex.join(
                    ("python3", "-I", "-c", _SECOND_TRUSTED_SCRIPT, child_token)
                )
                surface = build_audit_surface(
                    snapshot.manifest,
                    frozenset({AuditCategory.security}),
                )
                broker = install_audit_docker_broker(
                    prepared,
                    docker_executable=docker,
                    limits=HARD_LIMITS,
                    deadline=deadline,
                    python_executable=python_executable,
                    target_commit=snapshot.head,
                    snapshot_digest=surface.snapshot_digest,
                    trusted_command_scripts=(first_command, second_command),
                )
                broker_installed = True
                self.assertEqual(prepared.broker_dir / "docker", broker)

                protocol_arguments = (
                    ("version",),
                    (
                        "run",
                        "--rm",
                        "--cpus",
                        "0.5",
                        "--memory",
                        "64m",
                        "--pids-limit",
                        "32",
                        prepared.image_ref,
                        "sleep",
                        "0",
                    ),
                    ("info", "--format", "{{.Driver}}"),
                    (
                        "image",
                        "inspect",
                        prepared.image_ref,
                        "--format",
                        "{{json .Config.Entrypoint}}",
                    ),
                    (
                        "ps",
                        "-a",
                        "--filter",
                        "label=hermes-agent=1",
                        "--filter",
                        "label=hermes-task-id=default",
                        "--filter",
                        f"label=hermes-profile={prepared.profile_name}",
                        "--format",
                        '{{.ID}}\t{{.State}}\t{{.Label "hermes-egress"}}',
                    ),
                    (
                        "inspect",
                        "--format",
                        "{{.HostConfig.NetworkMode}}",
                        prepared.container_id,
                    ),
                    (
                        "exec",
                        prepared.container_id,
                        "bash",
                        "-l",
                        "-c",
                        _expected_bootstrap_script("0123456789ab"),
                    ),
                )
                for arguments in protocol_arguments:
                    result = invoke_audit_docker_broker(prepared.state_path, arguments)
                    self.assertEqual(
                        0,
                        result.returncode,
                        result.stderr.decode("utf-8", errors="replace"),
                    )

                mutation = invoke_audit_docker_broker(
                    prepared.state_path,
                    (
                        "exec",
                        prepared.container_id,
                        "bash",
                        "-c",
                        "printf 'mutated\\n' > /workspace/committed.txt",
                    ),
                )
                self.assertEqual(
                    0,
                    mutation.returncode,
                    mutation.stderr.decode("utf-8", errors="replace"),
                )
                first = invoke_audit_docker_broker(
                    prepared.state_path,
                    ("exec", prepared.container_id, "bash", "-c", first_command),
                )
                self.assertEqual(
                    0,
                    first.returncode,
                    first.stderr.decode("utf-8", errors="replace"),
                )
                self.assertEqual(b"first-ok\n", first.stdout)
                second = invoke_audit_docker_broker(
                    prepared.state_path,
                    ("exec", prepared.container_id, "bash", "-c", second_command),
                )
                self.assertEqual(
                    0,
                    second.returncode,
                    second.stderr.decode("utf-8", errors="replace"),
                )
                self.assertEqual(b"second-ok\n", second.stdout)
                state = read_audit_docker_broker_state(prepared.state_path)
                self.assertEqual("terminal", state.phase)
                self.assertEqual(3, len(state.terminal_receipts))
                self.assertTrue(
                    all(receipt.state == "exited" for receipt in state.terminal_receipts)
                )
                self.assertIsNone(state.active_trusted_receipt_id)

                removed = invoke_audit_docker_broker(
                    prepared.state_path,
                    ("rm", "-f", prepared.container_id),
                )
                self.assertEqual(
                    0,
                    removed.returncode,
                    removed.stderr.decode("utf-8", errors="replace"),
                )
                self.assertEqual(f"{prepared.container_id}\n".encode("ascii"), removed.stdout)
                broker_closed = True
                cleanup = runtime.cleanup(prepared)
            finally:
                try:
                    if prepared is not None:
                        if broker_installed and not broker_closed:
                            with suppress(Exception):
                                cleanup_audit_docker_broker(prepared.state_path)
                        if cleanup is None:
                            cleanup = runtime.cleanup(prepared)
                finally:
                    if previous_sentinel is None:
                        os.environ.pop("ZEUS_AUDIT_HOST_SENTINEL", None)
                    else:
                        os.environ["ZEUS_AUDIT_HOST_SENTINEL"] = previous_sentinel
                    stop_listener.set()
                    listener.close()
                    listener_thread.join(timeout=1)
            self.assertIsNotNone(prepared)
            self.assertIsNotNone(cleanup)
            self.assertTrue(cleanup.removed, cleanup.observation)  # type: ignore[union-attr]
            self.assertIsNotNone(prepared.trusted_container_id)  # type: ignore[union-attr]
            exact_ids = (
                prepared.container_id,  # type: ignore[union-attr]
                prepared.trusted_container_id,  # type: ignore[union-attr]
            )
            for container_id in exact_ids:
                inspected = subprocess.run(
                    [str(docker), "inspect", container_id],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                    shell=False,
                    timeout=10,
                    check=False,
                )
                self.assertNotEqual(0, inspected.returncode)
            remnants = subprocess.run(
                [
                    str(docker),
                    "ps",
                    "-aq",
                    "--no-trunc",
                    "--filter",
                    f"label=com.zeus.audit.run-id={run_id}",
                ],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                shell=False,
                timeout=10,
                check=False,
            )
            self.assertEqual(
                0,
                remnants.returncode,
                remnants.stderr.decode("utf-8", errors="replace"),
            )
            self.assertEqual(b"", remnants.stdout)
            self.assertFalse(accepted.is_set())
            self.assertEqual("host-only\n", sentinel.read_text(encoding="utf-8"))
        self.assertEqual(status_before, self._git_status())
        self.assertEqual(
            tracked_hash_before,
            hashlib.sha256(tracked_sentinel.read_bytes()).hexdigest(),
        )

    def _bridge_gateway(self, docker: Path) -> str:
        completed = subprocess.run(
            [
                str(docker),
                "network",
                "inspect",
                "bridge",
                "--format",
                "{{(index .IPAM.Config 0).Gateway}}",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            shell=False,
            timeout=10,
            check=False,
        )
        self.assertEqual(
            0,
            completed.returncode,
            completed.stderr.decode("utf-8", errors="replace"),
        )
        gateway = completed.stdout.decode("ascii", errors="strict").strip()
        self.assertTrue(gateway)
        return gateway

    def _git_status(self) -> bytes:
        completed = subprocess.run(
            ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            shell=False,
            timeout=10,
            check=False,
        )
        self.assertEqual(0, completed.returncode)
        return completed.stdout

    def _snapshot(self, root: Path) -> MaterializedSnapshot:
        snapshot_root = root / "snapshot"
        snapshot_root.mkdir(mode=0o700)
        content = b"committed\n"
        source = snapshot_root / "committed.txt"
        source.write_bytes(content)
        source.chmod(0o600)
        executable_content = b"#!/bin/sh\nprintf 'workspace-exec-ok\\n'\n"
        executable = snapshot_root / "executable.sh"
        executable.write_bytes(executable_content)
        executable.chmod(0o700)
        result = snapshot_root.lstat()
        identity = audit_workspace._PathIdentity(
            device=result.st_dev,
            inode=result.st_ino,
            owner=result.st_uid,
            permissions=stat.S_IMODE(result.st_mode),
        )
        return MaterializedSnapshot(
            root=snapshot_root,
            repository_id="8" * 64,
            head="9" * 40,
            manifest=(
                SnapshotManifestEntry(
                    path="committed.txt",
                    object_id="a" * 40,
                    git_mode="100644",
                    mode=0o600,
                    size=len(content),
                    sha256=hashlib.sha256(content).hexdigest(),
                ),
                SnapshotManifestEntry(
                    path="executable.sh",
                    object_id="b" * 40,
                    git_mode="100755",
                    mode=0o700,
                    size=len(executable_content),
                    sha256=hashlib.sha256(executable_content).hexdigest(),
                ),
            ),
            skipped_content=(),
            source_entry_count=2,
            source_blob_bytes=len(content) + len(executable_content),
            excluded_paths=(),
            _root_identity=identity,
        )


if __name__ == "__main__":
    unittest.main()
