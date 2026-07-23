from __future__ import annotations

import hashlib
import os
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

import zeus.audit_workspace as audit_workspace
from zeus.audit_container import AUDIT_GID, AUDIT_UID, AuditContainerRuntime
from zeus.audit_models import HARD_LIMITS
from zeus.audit_workspace import MaterializedSnapshot, SnapshotManifestEntry


@unittest.skipUnless(
    os.environ.get("ZEUS_RUN_DOCKER_ISOLATION") == "1",
    "set ZEUS_RUN_DOCKER_ISOLATION=1 to run the real Docker isolation test",
)
class RealDockerAuditIsolationTests(unittest.TestCase):
    def test_real_docker_isolation(self) -> None:
        docker_value = shutil.which("docker")
        if docker_value is None:
            self.skipTest("Docker executable is unavailable")
        image = os.environ.get("ZEUS_AUDIT_TEST_IMAGE")
        if image is None:
            self.skipTest("ZEUS_AUDIT_TEST_IMAGE is not configured")
        docker = Path(docker_value).resolve(strict=True)
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

            def accept_connections() -> None:
                while True:
                    try:
                        connection, _address = listener.accept()
                    except (OSError, TimeoutError):
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
            try:
                prepared = runtime.prepare(
                    run_id="7" * 32,
                    snapshot=snapshot,
                    image_ref=image,
                    limits=HARD_LIMITS,
                    deadline=time.monotonic() + 60,
                )
                runtime.validate(prepared)
                script = r"""
import os, pathlib, socket, sys
workspace = pathlib.Path("/workspace")
assert (workspace / "committed.txt").read_bytes() == b"committed\n"
assert not (workspace / ".git").exists()
assert not pathlib.Path("/var/run/docker.sock").exists()
assert not pathlib.Path("/root/.docker/config.json").exists()
assert not pathlib.Path("/root/.ssh").exists()
assert "ZEUS_AUDIT_HOST_SENTINEL" not in os.environ
host_sentinel = pathlib.Path(sys.argv[1])
assert not host_sentinel.exists()
(workspace / "write-test").write_text("ok", encoding="utf-8")
(workspace / "write-test").unlink()
temp_test = pathlib.Path("/tmp/write-test")
temp_test.write_text("ok", encoding="utf-8")
temp_test.unlink()
for path in (
    pathlib.Path("/rootfs-write-test"),
    pathlib.Path("/dev/shm/write-test"),
    pathlib.Path("/var/tmp/write-test"),
    pathlib.Path("/run/write-test"),
):
    try:
        path.write_text("no", encoding="utf-8")
    except OSError:
        pass
    else:
        raise AssertionError(f"unintended writable path: {path}")
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
        raise AssertionError("network connection unexpectedly succeeded")
    finally:
        sock.close()
try:
    socket.getaddrinfo("example.com", 443)
except OSError:
    pass
else:
    raise AssertionError("DNS unexpectedly succeeded")
"""
                completed = subprocess.run(
                    [
                        str(docker),
                        "exec",
                        f"--user={AUDIT_UID}:{AUDIT_GID}",
                        prepared.container_id,
                        "python3",
                        "-I",
                        "-c",
                        script,
                        str(sentinel),
                        str(listener_port),
                        bridge_gateway,
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
            finally:
                try:
                    if prepared is not None:
                        cleanup = runtime.cleanup(prepared)
                finally:
                    if previous_sentinel is None:
                        os.environ.pop("ZEUS_AUDIT_HOST_SENTINEL", None)
                    else:
                        os.environ["ZEUS_AUDIT_HOST_SENTINEL"] = previous_sentinel
                    listener.close()
                    listener_thread.join(timeout=1)
            self.assertIsNotNone(prepared)
            self.assertIsNotNone(cleanup)
            self.assertTrue(cleanup.removed, cleanup.observation)  # type: ignore[union-attr]
            inspected = subprocess.run(
                [str(docker), "inspect", prepared.container_id],  # type: ignore[union-attr]
                stdin=subprocess.DEVNULL,
                capture_output=True,
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                shell=False,
                timeout=10,
                check=False,
            )
            self.assertNotEqual(0, inspected.returncode)
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
        source.chmod(0o644)
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
                    mode=0o644,
                    size=len(content),
                    sha256=hashlib.sha256(content).hexdigest(),
                ),
            ),
            skipped_content=(),
            source_entry_count=1,
            source_blob_bytes=len(content),
            excluded_paths=(),
            _root_identity=identity,
        )


if __name__ == "__main__":
    unittest.main()
