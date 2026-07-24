from __future__ import annotations

import hashlib
import io
import json
import os
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from contextlib import suppress
from dataclasses import replace
from pathlib import Path
from unittest import mock

import zeus.audit_container as audit_container
import zeus.audit_workspace as audit_workspace
from zeus.audit_config import DEFAULT_AUDIT_IMAGE
from zeus.audit_container import (
    AUDIT_GID,
    AUDIT_UID,
    AuditContainerError,
    AuditContainerRuntime,
    DockerCommandResult,
)
from zeus.audit_models import HARD_LIMITS
from zeus.audit_workspace import MaterializedSnapshot, SnapshotManifestEntry

RUN_ID = "1" * 32
IMAGE_REF = "registry.example.invalid/audit@sha256:" + "a" * 64
IMAGE_ID = "sha256:" + "b" * 64
CONTAINER_ID = "c" * 64


def _deadline() -> float:
    return time.monotonic() + 10


class FakeDockerRunner:
    def __init__(self, inspect_value: dict[str, object]) -> None:
        self.inspect_value = inspect_value
        self.image_value: dict[str, object] = {
            "Id": IMAGE_ID,
            "RepoDigests": [IMAGE_REF],
            "Config": {
                "Env": [],
                "Healthcheck": None,
                "Labels": None,
                "Volumes": None,
            },
        }
        self.remove_stdout = CONTAINER_ID.encode() + b"\n"
        self.calls: list[tuple[tuple[str, ...], bytes | None, dict[str, str]]] = []

    def run(
        self,
        argv: tuple[str, ...],
        *,
        input_stream: io.BufferedIOBase | io.BytesIO | None,
        deadline: float,
        stdout_limit: int,
        stderr_limit: int,
        env: dict[str, str],
    ) -> DockerCommandResult:
        del deadline, stdout_limit, stderr_limit
        payload = None if input_stream is None else input_stream.read()
        self.calls.append((argv, payload, env))
        if argv[1:3] == ("image", "inspect"):
            return DockerCommandResult(
                stdout=json.dumps(self.image_value, separators=(",", ":")).encode() + b"\n",
                stderr=b"",
            )
        if argv[1] == "create":
            return DockerCommandResult(stdout=CONTAINER_ID.encode() + b"\n", stderr=b"")
        if argv[1] == "inspect":
            return DockerCommandResult(
                stdout=json.dumps([self.inspect_value], separators=(",", ":")).encode() + b"\n",
                stderr=b"",
            )
        if argv[1:3] == ("rm", "-f"):
            return DockerCommandResult(stdout=self.remove_stdout, stderr=b"")
        return DockerCommandResult(stdout=b"", stderr=b"")


class AuditContainerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name).resolve()
        self.snapshot_root = self.root / "snapshot"
        self.snapshot_root.mkdir(mode=0o700)
        (self.snapshot_root / "pkg").mkdir(mode=0o700)
        (self.snapshot_root / "README.md").write_bytes(b"committed\n")
        (self.snapshot_root / "README.md").chmod(0o644)
        (self.snapshot_root / "pkg" / "tool.sh").write_bytes(b"#!/bin/sh\nexit 0\n")
        (self.snapshot_root / "pkg" / "tool.sh").chmod(0o755)
        os.symlink("README.md", self.snapshot_root / "link")
        root_result = self.snapshot_root.lstat()
        identity = audit_workspace._PathIdentity(
            device=root_result.st_dev,
            inode=root_result.st_ino,
            owner=root_result.st_uid,
            permissions=stat.S_IMODE(root_result.st_mode),
        )
        self.snapshot = MaterializedSnapshot(
            root=self.snapshot_root,
            repository_id="d" * 64,
            head="e" * 40,
            manifest=(
                SnapshotManifestEntry(
                    path="README.md",
                    object_id="f" * 40,
                    git_mode="100644",
                    mode=0o644,
                    size=10,
                    sha256="cc2e4bb51f522b77c0c3ad04f7a87386a7e06d4fa287c004b6c066410c5c24dc",
                ),
                SnapshotManifestEntry(
                    path="link",
                    object_id="1" * 40,
                    git_mode="120000",
                    mode=0o777,
                    size=9,
                    sha256="b" * 64,
                    symlink_target="README.md",
                ),
                SnapshotManifestEntry(
                    path="pkg/tool.sh",
                    object_id="2" * 40,
                    git_mode="100755",
                    mode=0o755,
                    size=17,
                    sha256="306c6ca7407560340797866e077e053627ad409277d1b9da58106fce4cf717cb",
                ),
            ),
            skipped_content=(),
            source_entry_count=3,
            source_blob_bytes=36,
            excluded_paths=(),
            _root_identity=identity,
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _inspect(self, **changes: object) -> dict[str, object]:
        name = f"zeus-audit-{RUN_ID}"
        profile = f"audit-{RUN_ID}"
        value: dict[str, object] = {
            "Id": CONTAINER_ID,
            "Name": f"/{name}",
            "Image": IMAGE_ID,
            "Config": {
                "Image": IMAGE_REF,
                "User": f"{AUDIT_UID}:{AUDIT_GID}",
                "WorkingDir": "/workspace",
                "Entrypoint": ["/bin/sh"],
                "Cmd": ["-c", "trap : TERM INT; sleep infinity & wait"],
                "Env": [],
                "Healthcheck": {"Test": ["NONE"]},
                "Volumes": None,
                "Labels": {
                    "com.zeus.audit": "true",
                    "com.zeus.audit.run-id": RUN_ID,
                    "com.zeus.audit.profile": profile,
                },
            },
            "HostConfig": {
                "NetworkMode": "none",
                "Binds": None,
                "Mounts": [],
                "CapAdd": None,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "ReadonlyRootfs": True,
                "PidsLimit": 256,
                "NanoCpus": 2_000_000_000,
                "Memory": 4 * 1024**3,
                "MemorySwap": 4 * 1024**3,
                "Privileged": False,
                "PidMode": "",
                "IpcMode": "none",
                "UTSMode": "",
                "UsernsMode": "",
                "CgroupnsMode": "private",
                "Devices": [],
                "DeviceRequests": [],
                "DeviceCgroupRules": [],
                "GroupAdd": [],
                "PortBindings": {},
                "Tmpfs": {
                    "/workspace": (
                        f"rw,nosuid,nodev,size=2147483648,uid={AUDIT_UID},gid={AUDIT_GID},mode=0700"
                    ),
                    "/tmp": (
                        f"rw,noexec,nosuid,nodev,size=536870912,uid={AUDIT_UID},"
                        f"gid={AUDIT_GID},mode=0700"
                    ),
                },
            },
            "Mounts": [
                {"Type": "tmpfs", "Destination": "/workspace", "RW": True},
                {"Type": "tmpfs", "Destination": "/tmp", "RW": True},
            ],
            "NetworkSettings": {
                "Ports": {},
                "Networks": {
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
                },
                "IPAddress": "",
                "Gateway": "",
                "MacAddress": "",
            },
            "State": {"Running": True},
        }
        value.update(changes)
        return value

    def _runtime(self, inspect_value: dict[str, object] | None = None):
        runner = FakeDockerRunner(self._inspect() if inspect_value is None else inspect_value)
        runtime = AuditContainerRuntime(
            Path("/usr/bin/docker"),
            self.root / "control",
            runner=runner,
        )
        return runtime, runner

    def _prepare(self, inspect_value: dict[str, object] | None = None):
        runtime, runner = self._runtime(inspect_value)
        prepared = runtime.prepare(
            run_id=RUN_ID,
            snapshot=self.snapshot,
            image_ref=IMAGE_REF,
            limits=HARD_LIMITS,
            deadline=_deadline(),
        )
        return runtime, runner, prepared

    def test_prepare_uses_exact_commands_minimal_environment_and_archive(self) -> None:
        _runtime, runner, prepared = self._prepare()
        docker = "/usr/bin/docker"
        name = f"zeus-audit-{RUN_ID}"
        profile = f"audit-{RUN_ID}"
        self.assertEqual(
            (docker, "image", "inspect", "--format", "{{json .}}", IMAGE_REF),
            runner.calls[0][0],
        )
        self.assertEqual(
            (
                docker,
                "create",
                "--pull=never",
                "--name",
                name,
                "--label",
                "com.zeus.audit=true",
                "--label",
                f"com.zeus.audit.run-id={RUN_ID}",
                "--label",
                f"com.zeus.audit.profile={profile}",
                "--network=none",
                f"--user={AUDIT_UID}:{AUDIT_GID}",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "--read-only",
                "--no-healthcheck",
                "--ipc=none",
                "--pids-limit=256",
                "--cpus=2",
                "--memory=4294967296",
                "--memory-swap=4294967296",
                (
                    f"--tmpfs=/workspace:rw,nosuid,nodev,size=2147483648,"
                    f"uid={AUDIT_UID},gid={AUDIT_GID},mode=0700"
                ),
                (
                    f"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=536870912,"
                    f"uid={AUDIT_UID},gid={AUDIT_GID},mode=0700"
                ),
                "--workdir=/workspace",
                "--entrypoint=/bin/sh",
                IMAGE_REF,
                "-c",
                "trap : TERM INT; sleep infinity & wait",
            ),
            runner.calls[1][0],
        )
        self.assertEqual((docker, "start", CONTAINER_ID), runner.calls[2][0])
        self.assertEqual(
            (docker, "cp", "--archive", "-", f"{CONTAINER_ID}:/workspace"),
            runner.calls[3][0],
        )
        archive_bytes = runner.calls[3][1] or b""
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
            members = {member.name: member for member in archive.getmembers()}
            self.assertEqual(
                {"README.md", "link", "pkg", "pkg/tool.sh"},
                set(members),
            )
            self.assertEqual(AUDIT_UID, members["README.md"].uid)
            self.assertEqual(AUDIT_GID, members["README.md"].gid)
            self.assertEqual(0, members["README.md"].mtime)
            self.assertEqual(0o644, members["README.md"].mode)
            self.assertEqual(0o700, members["pkg"].mode)
            self.assertEqual("README.md", members["link"].linkname)
            source = archive.extractfile(members["pkg/tool.sh"])
            self.assertIsNotNone(source)
            self.assertEqual(b"#!/bin/sh\nexit 0\n", source.read())  # type: ignore[union-attr]
        self.assertEqual(
            (
                docker,
                "exec",
                "-i",
                f"--user={AUDIT_UID}:{AUDIT_GID}",
                "--workdir=/workspace",
                CONTAINER_ID,
                "python3",
                "-I",
                "-c",
                audit_container._VALIDATION_SCRIPT,
                str(AUDIT_UID),
                str(AUDIT_GID),
                str(AUDIT_UID),
                str(AUDIT_GID),
                "[]",
                "/proc/self/status",
                ".",
            ),
            runner.calls[4][0],
        )
        self.assertEqual((docker, "inspect", CONTAINER_ID), runner.calls[5][0])
        for _argv, _payload, env in runner.calls:
            self.assertEqual({"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}, env)
        self.assertEqual(CONTAINER_ID, prepared.container_id)
        self.assertEqual(0o700, stat.S_IMODE(prepared.broker_dir.lstat().st_mode))

    def test_tagged_digest_uses_configured_ref_and_canonical_repo_digest_binding(self) -> None:
        digest = DEFAULT_AUDIT_IMAGE.rsplit("@sha256:", 1)[1]
        repository = DEFAULT_AUDIT_IMAGE.rsplit("@sha256:", 1)[0]
        prefix, separator, component = repository.rpartition("/")
        canonical = f"{prefix}{separator}{component.rsplit(':', 1)[0]}@sha256:{digest}"
        runtime, runner = self._runtime()
        runner.image_value = {
            "Id": IMAGE_ID,
            "RepoDigests": [canonical],
            "Config": {
                "Env": [],
                "Healthcheck": None,
                "Labels": None,
                "Volumes": None,
            },
        }
        inspect_value = self._inspect()
        inspect_value["Config"]["Image"] = DEFAULT_AUDIT_IMAGE  # type: ignore[index]
        runner.inspect_value = inspect_value

        prepared = runtime.prepare(
            run_id=RUN_ID,
            snapshot=self.snapshot,
            image_ref=DEFAULT_AUDIT_IMAGE,
            limits=HARD_LIMITS,
            deadline=_deadline(),
        )

        self.assertEqual(DEFAULT_AUDIT_IMAGE, prepared.image_ref)
        self.assertEqual(DEFAULT_AUDIT_IMAGE, runner.calls[0][0][-1])
        create = next(call[0] for call in runner.calls if call[0][1] == "create")
        self.assertIn(DEFAULT_AUDIT_IMAGE, create)

    def test_inherited_healthcheck_is_disabled_and_effective_drift_is_rejected(self) -> None:
        runtime, runner = self._runtime()
        runner.image_value["Config"] = {
            "Env": [],
            "Healthcheck": {"Test": ["CMD-SHELL", "curl http://127.0.0.1/"]},
            "Labels": None,
            "Volumes": None,
        }

        prepared = runtime.prepare(
            run_id=RUN_ID,
            snapshot=self.snapshot,
            image_ref=IMAGE_REF,
            limits=HARD_LIMITS,
            deadline=_deadline(),
        )
        create = next(call[0] for call in runner.calls if call[0][1] == "create")
        self.assertIn("--no-healthcheck", create)
        self.assertEqual(CONTAINER_ID, prepared.container_id)

        runtime, _runner = self._runtime(
            self._inspect(
                Config={
                    **self._inspect()["Config"],  # type: ignore[dict-item]
                    "Healthcheck": {"Test": ["CMD", "true"]},
                }
            )
        )
        with self.assertRaises(AuditContainerError):
            runtime.prepare(
                run_id=RUN_ID,
                snapshot=self.snapshot,
                image_ref=IMAGE_REF,
                limits=HARD_LIMITS,
                deadline=_deadline(),
            )

    def test_image_labels_are_merged_exactly_with_zeus_ownership_overrides(self) -> None:
        runtime, runner = self._runtime()
        runner.image_value["Config"] = {
            "Env": [],
            "Healthcheck": None,
            "Labels": {
                "com.example.image": "trusted",
                "com.zeus.audit": "false",
                "com.zeus.audit.run-id": "image-value",
            },
            "Volumes": None,
        }
        inspect_value = self._inspect()
        inspect_value["Config"]["Labels"] = {  # type: ignore[index]
            "com.example.image": "trusted",
            "com.zeus.audit": "true",
            "com.zeus.audit.run-id": RUN_ID,
            "com.zeus.audit.profile": f"audit-{RUN_ID}",
        }
        runner.inspect_value = inspect_value

        prepared = runtime.prepare(
            run_id=RUN_ID,
            snapshot=self.snapshot,
            image_ref=IMAGE_REF,
            limits=HARD_LIMITS,
            deadline=_deadline(),
        )

        self.assertEqual(CONTAINER_ID, prepared.container_id)
        runtime.validate(prepared)

    def test_image_declared_volume_is_rejected_before_create(self) -> None:
        runtime, runner = self._runtime()
        runner.image_value["Config"] = {"Env": [], "Volumes": {"/data": {}}}

        with self.assertRaises(AuditContainerError):
            runtime.prepare(
                run_id=RUN_ID,
                snapshot=self.snapshot,
                image_ref=IMAGE_REF,
                limits=HARD_LIMITS,
                deadline=_deadline(),
            )

        self.assertFalse(any(call[0][1] == "create" for call in runner.calls))

    def test_rejects_mutable_image_and_image_id_or_digest_binding_drift(self) -> None:
        runtime, _runner = self._runtime()
        for image in ("audit:latest", "audit", "https://example.invalid/audit@sha256:" + "a" * 64):
            with self.subTest(image=image), self.assertRaises(AuditContainerError):
                runtime.prepare(
                    run_id=RUN_ID,
                    snapshot=self.snapshot,
                    image_ref=image,
                    limits=HARD_LIMITS,
                    deadline=_deadline(),
                )
        runner = FakeDockerRunner(self._inspect())
        original_run = runner.run

        def altered(*args: object, **kwargs: object) -> DockerCommandResult:
            result = original_run(*args, **kwargs)  # type: ignore[arg-type]
            if args[0][1:3] == ("image", "inspect"):  # type: ignore[index]
                return DockerCommandResult(
                    stdout=json.dumps(
                        {
                            "Id": "sha256:" + "9" * 64,
                            "RepoDigests": [],
                            "Config": {"Env": []},
                        }
                    ).encode()
                    + b"\n",
                    stderr=b"",
                )
            return result

        runner.run = altered  # type: ignore[method-assign]
        runtime = AuditContainerRuntime(
            Path("/usr/bin/docker"), self.root / "other-control", runner=runner
        )
        with self.assertRaises(AuditContainerError):
            runtime.prepare(
                run_id=RUN_ID,
                snapshot=self.snapshot,
                image_ref="sha256:" + "a" * 64,
                limits=HARD_LIMITS,
                deadline=_deadline(),
            )

    def test_seed_archive_rejects_snapshot_drift_and_never_follows_symlinks(self) -> None:
        outside = self.root / "outside"
        outside.write_text("secret", encoding="utf-8")
        (self.snapshot_root / "README.md").unlink()
        os.symlink(outside, self.snapshot_root / "README.md")
        runtime, _runner = self._runtime()
        with self.assertRaises(AuditContainerError):
            runtime.prepare(
                run_id=RUN_ID,
                snapshot=self.snapshot,
                image_ref=IMAGE_REF,
                limits=HARD_LIMITS,
                deadline=_deadline(),
            )

    def test_rejects_mount_volume_port_device_privilege_and_namespace_drift(self) -> None:
        mutations = {
            "mount": ("Mounts", [{"Type": "bind", "Source": "/", "Destination": "/host"}]),
            "host-mount": (
                "HostConfig.Mounts",
                [{"Type": "bind", "Source": "/", "Target": "/host"}],
            ),
            "volume": ("Config.Volumes", {"/data": {}}),
            "port": ("HostConfig.PortBindings", {"80/tcp": [{"HostPort": "8080"}]}),
            "effective-port": ("NetworkSettings.Ports", {"80/tcp": []}),
            "device": ("HostConfig.Devices", [{"PathOnHost": "/dev/null"}]),
            "device-request": ("HostConfig.DeviceRequests", [{"Driver": "nvidia"}]),
            "device-cgroup-rule": ("HostConfig.DeviceCgroupRules", ["c 1:3 rwm"]),
            "supplementary-group": ("HostConfig.GroupAdd", ["123"]),
            "privileged": ("HostConfig.Privileged", True),
            "pid-host": ("HostConfig.PidMode", "host"),
            "ipc-private": ("HostConfig.IpcMode", "private"),
            "uts-host": ("HostConfig.UTSMode", "host"),
            "userns-host": ("HostConfig.UsernsMode", "host"),
            "cgroupns-host": ("HostConfig.CgroupnsMode", "host"),
        }
        for name, (path, replacement) in mutations.items():
            with self.subTest(name=name):
                value = self._inspect()
                target: dict[str, object] = value
                components = path.split(".")
                for component in components[:-1]:
                    target = target[component]  # type: ignore[assignment]
                target[components[-1]] = replacement
                runtime, _runner = self._runtime(value)
                with self.assertRaises(AuditContainerError):
                    runtime.prepare(
                        run_id=RUN_ID,
                        snapshot=self.snapshot,
                        image_ref=IMAGE_REF,
                        limits=HARD_LIMITS,
                        deadline=_deadline(),
                    )

    def test_rejects_network_security_user_resource_and_identity_drift(self) -> None:
        mutations = {
            "network": ("HostConfig.NetworkMode", "bridge"),
            "rootfs": ("HostConfig.ReadonlyRootfs", False),
            "cap-add": ("HostConfig.CapAdd", ["SYS_ADMIN"]),
            "cap-drop": ("HostConfig.CapDrop", []),
            "security": ("HostConfig.SecurityOpt", ["seccomp=unconfined"]),
            "security-extra": (
                "HostConfig.SecurityOpt",
                ["no-new-privileges:true", "seccomp=unconfined"],
            ),
            "user": ("Config.User", "0:0"),
            "pids": ("HostConfig.PidsLimit", 257),
            "cpus": ("HostConfig.NanoCpus", 1_000_000_000),
            "memory": ("HostConfig.Memory", 1024),
            "swap": ("HostConfig.MemorySwap", 8 * 1024**3),
            "name": ("Name", "/replacement"),
            "image": ("Image", "sha256:" + "9" * 64),
            "id": ("Id", "9" * 64),
            "labels": ("Config.Labels", {"com.zeus.audit": "true"}),
            "env": ("Config.Env", ["SECRET=value"]),
            "workdir": ("Config.WorkingDir", "/"),
            "entrypoint": ("Config.Entrypoint", ["/usr/bin/env"]),
            "command": ("Config.Cmd", ["sleep", "1"]),
            "tmpfs": ("HostConfig.Tmpfs", {}),
            "healthcheck": ("Config.Healthcheck", {"Test": ["CMD", "true"]}),
            "network-attachment": (
                "NetworkSettings.Networks",
                {
                    "bridge": {
                        "IPAddress": "172.17.0.2",
                        "Gateway": "172.17.0.1",
                        "MacAddress": "02:42:ac:11:00:02",
                    }
                },
            ),
            "effective-ip": ("NetworkSettings.IPAddress", "172.17.0.2"),
            "effective-gateway": ("NetworkSettings.Gateway", "172.17.0.1"),
            "effective-mac": ("NetworkSettings.MacAddress", "02:42:ac:11:00:02"),
            "none-network-ip": (
                "NetworkSettings.Networks",
                {
                    "none": {
                        **self._inspect()["NetworkSettings"]["Networks"]["none"],  # type: ignore[index]
                        "IPAddress": "172.17.0.2",
                    }
                },
            ),
        }
        for name, (path, replacement) in mutations.items():
            with self.subTest(name=name):
                value = self._inspect()
                target: dict[str, object] = value
                components = path.split(".")
                for component in components[:-1]:
                    target = target[component]  # type: ignore[assignment]
                target[components[-1]] = replacement
                runtime, _runner = self._runtime(value)
                with self.assertRaises(AuditContainerError):
                    runtime.prepare(
                        run_id=RUN_ID,
                        snapshot=self.snapshot,
                        image_ref=IMAGE_REF,
                        limits=HARD_LIMITS,
                        deadline=_deadline(),
                    )

    def test_cleanup_removes_only_exact_reinspected_owned_identity(self) -> None:
        runtime, runner, prepared = self._prepare()
        result = runtime.cleanup(prepared)
        self.assertTrue(result.removed)
        self.assertFalse(result.ambiguous)
        self.assertEqual(
            ("/usr/bin/docker", "rm", "-f", CONTAINER_ID),
            runner.calls[-1][0],
        )

        runtime, runner, prepared = self._prepare()
        replacement = self._inspect(
            Id="9" * 64,
            Name="/replacement",
        )
        replacement["Config"]["Labels"] = {"com.zeus.audit": "replacement"}  # type: ignore[index]
        runner.inspect_value = replacement
        result = runtime.cleanup(prepared)
        self.assertFalse(result.removed)
        self.assertTrue(result.ambiguous)
        self.assertFalse(any(call[0][1:3] == ("rm", "-f") for call in runner.calls))

    def test_cleanup_requires_exact_remove_identity_output(self) -> None:
        runtime, runner, prepared = self._prepare()
        runner.remove_stdout = ("9" * 64).encode() + b"\n"

        result = runtime.cleanup(prepared)

        self.assertFalse(result.removed)
        self.assertTrue(result.ambiguous)

    def test_deadline_output_and_process_contracts_are_fail_closed(self) -> None:
        runtime, _runner = self._runtime()
        with self.assertRaises(AuditContainerError):
            runtime.prepare(
                run_id=RUN_ID,
                snapshot=self.snapshot,
                image_ref=IMAGE_REF,
                limits=HARD_LIMITS,
                deadline=time.monotonic() - 1,
            )
        with self.assertRaises(AuditContainerError):
            runtime.prepare(
                run_id=RUN_ID,
                snapshot=self.snapshot,
                image_ref=IMAGE_REF,
                limits=replace(HARD_LIMITS, cpu_count=3),
                deadline=_deadline(),
            )
        for invalid_seconds in (True, 1.5, 0, HARD_LIMITS.docker_control_seconds + 1):
            with (
                self.subTest(docker_control_seconds=invalid_seconds),
                self.assertRaises(AuditContainerError),
            ):
                runtime.prepare(
                    run_id=RUN_ID,
                    snapshot=self.snapshot,
                    image_ref=IMAGE_REF,
                    limits=replace(
                        HARD_LIMITS,
                        docker_control_seconds=invalid_seconds,  # type: ignore[arg-type]
                    ),
                    deadline=_deadline(),
                )

    def _validation_fixture(
        self,
        root: Path,
    ) -> tuple[Path, list[dict[str, object]]]:
        workspace = root / "workspace"
        workspace.mkdir(mode=0o700)
        file_content = b"content\n"
        source = workspace / "file.txt"
        source.write_bytes(file_content)
        source.chmod(0o640)
        os.symlink("file.txt", workspace / "link")
        manifest: list[dict[str, object]] = [
            {
                "mode": 0o640,
                "path": "file.txt",
                "sha256": hashlib.sha256(file_content).hexdigest(),
                "size": len(file_content),
                "type": "file",
            },
            {"path": "link", "target": "file.txt", "type": "symlink"},
        ]
        return workspace, manifest

    def _run_validation(
        self,
        workspace: Path,
        manifest: list[dict[str, object]],
        *,
        expected_uid: int | None = None,
        expected_gid: int | None = None,
        expected_entry_uid: int | None = None,
        expected_entry_gid: int | None = None,
        expected_groups: list[int] | None = None,
        process_status: str = "NoNewPrivs:\t1\nSeccomp:\t2\nCapEff:\t0000000000000000\n",
        probe_root: Path | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        status_path = workspace.parent / "process-status"
        status_path.write_text(process_status, encoding="ascii")
        return subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                audit_container._VALIDATION_SCRIPT,
                str(os.getuid() if expected_uid is None else expected_uid),
                str(os.getgid() if expected_gid is None else expected_gid),
                str(os.getuid() if expected_entry_uid is None else expected_entry_uid),
                str(os.getgid() if expected_entry_gid is None else expected_entry_gid),
                json.dumps(os.getgroups() if expected_groups is None else expected_groups),
                str(status_path),
                str(workspace if probe_root is None else probe_root),
            ],
            cwd=workspace,
            input=json.dumps(manifest, separators=(",", ":")).encode(),
            capture_output=True,
            shell=False,
            timeout=5,
            check=False,
        )

    def test_workspace_validation_accepts_exact_copy_and_rejects_manifest_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            workspace, manifest = self._validation_fixture(base)
            self.assertEqual(0, self._run_validation(workspace, manifest).returncode)

        mutations = {
            "path": lambda root, value: value.__setitem__(0, {**value[0], "path": "other.txt"}),
            "type": lambda root, value: (
                (root / "file.txt").unlink() or (root / "file.txt").mkdir(mode=0o700)
            ),
            "mode": lambda root, value: (root / "file.txt").chmod(0o600),
            "size": lambda root, value: value[0].__setitem__("size", 99),
            "hash": lambda root, value: value[0].__setitem__("sha256", "0" * 64),
            "symlink": lambda root, value: (
                (root / "link").unlink() or os.symlink("missing", root / "link")
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                workspace, manifest = self._validation_fixture(Path(temporary))
                mutate(workspace, manifest)
                self.assertNotEqual(0, self._run_validation(workspace, manifest).returncode)

    def test_workspace_validation_rejects_ownership_and_effective_control_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace, manifest = self._validation_fixture(Path(temporary))
            self.assertNotEqual(
                0,
                self._run_validation(
                    workspace,
                    manifest,
                    expected_entry_gid=os.getgid() + 1,
                ).returncode,
            )

        cases = {
            "uid": {"expected_uid": os.getuid() + 1},
            "gid": {"expected_gid": os.getgid() + 1},
            "supplementary-groups": {
                "expected_groups": [group + 1 for group in os.getgroups()]
                if os.getgroups()
                else [1]
            },
            "no-new-privileges": {"process_status": "NoNewPrivs:\t0\nSeccomp:\t2\nCapEff:\t0\n"},
            "seccomp": {"process_status": "NoNewPrivs:\t1\nSeccomp:\t0\nCapEff:\t0\n"},
            "capabilities": {"process_status": "NoNewPrivs:\t1\nSeccomp:\t2\nCapEff:\t1\n"},
        }
        for name, options in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                workspace, manifest = self._validation_fixture(Path(temporary))
                self.assertNotEqual(
                    0,
                    self._run_validation(workspace, manifest, **options).returncode,  # type: ignore[arg-type]
                )

    def test_workspace_validation_rejects_write_probe_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            workspace, manifest = self._validation_fixture(base)
            unwritable = base / "unwritable"
            unwritable.mkdir(mode=0o500)
            self.assertNotEqual(
                0,
                self._run_validation(workspace, manifest, probe_root=unwritable).returncode,
            )

    def test_archive_enforces_limits_deadline_and_private_spool(self) -> None:
        private_spool = self.root / "spool"
        private_spool.mkdir(mode=0o700)
        with mock.patch(
            "zeus.audit_container.tempfile.SpooledTemporaryFile",
            wraps=tempfile.SpooledTemporaryFile,
        ) as spool:
            archive = audit_container._build_seed_archive(
                self.snapshot,
                _deadline(),
                limits=HARD_LIMITS,
                spool_dir=private_spool,
            )
            archive.close()
        self.assertEqual(str(private_spool), spool.call_args.kwargs["dir"])

        with self.assertRaises(AuditContainerError):
            audit_container._build_seed_archive(
                self.snapshot,
                _deadline(),
                limits=replace(HARD_LIMITS, snapshot_entries=2),
                spool_dir=private_spool,
            )
        with self.assertRaises(AuditContainerError):
            audit_container._build_seed_archive(
                self.snapshot,
                _deadline(),
                limits=replace(HARD_LIMITS, snapshot_blob_bytes=26),
                spool_dir=private_spool,
            )
        private_spool.chmod(0o755)
        with self.assertRaises(AuditContainerError):
            audit_container._build_seed_archive(
                self.snapshot,
                _deadline(),
                limits=HARD_LIMITS,
                spool_dir=private_spool,
            )

        descriptor = os.open(self.snapshot_root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaises(AuditContainerError):
                audit_container._actual_snapshot_paths(
                    descriptor,
                    deadline=time.monotonic() - 1,
                )
        finally:
            os.close(descriptor)
        with self.assertRaises(AuditContainerError):
            audit_container._DeadlineReader(
                io.BytesIO(b"second-read"),
                time.monotonic() - 1,
            ).read()

    def test_archive_rejects_same_size_mutation_between_hash_and_tar_stream(self) -> None:
        private_spool = self.root / "race-spool"
        private_spool.mkdir(mode=0o700)
        original_addfile = tarfile.TarFile.addfile

        def mutate_before_stream(
            archive: tarfile.TarFile,
            tarinfo: tarfile.TarInfo,
            fileobj: io.BufferedIOBase | None = None,
        ) -> None:
            if tarinfo.name == "README.md" and fileobj is not None:
                (self.snapshot_root / "README.md").write_bytes(b"tampered!\n")
                (self.snapshot_root / "README.md").chmod(0o644)
            original_addfile(archive, tarinfo, fileobj)

        with mock.patch.object(tarfile.TarFile, "addfile", new=mutate_before_stream):
            try:
                produced = audit_container._build_seed_archive(
                    self.snapshot,
                    _deadline(),
                    limits=HARD_LIMITS,
                    spool_dir=private_spool,
                )
            except AuditContainerError:
                pass
            else:
                produced.close()
                self.fail("archive accepted bytes that did not match the manifest digest")

    @unittest.skipUnless(os.name == "posix", "requires POSIX process groups")
    def test_stop_process_kills_lingering_group_after_leader_exit(self) -> None:
        marker = self.root / "descendant-signalled"
        ready = self.root / "descendant-ready"
        child_script = (
            "import os,pathlib,signal,time;"
            f"marker=pathlib.Path({str(marker)!r});"
            f"ready=pathlib.Path({str(ready)!r});"
            "signal.signal(signal.SIGTERM,lambda *_:(marker.write_text('term'),os._exit(0)));"
            "ready.write_text('ready');"
            "time.sleep(30)"
        )
        leader = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import pathlib,subprocess,sys,time;"
                "subprocess.Popen([sys.executable,'-c',sys.argv[1]]);"
                "ready=pathlib.Path(sys.argv[2]);"
                "\nwhile not ready.exists(): time.sleep(0.01)",
                child_script,
                str(ready),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        from zeus.audit_process import wait_process_exit

        wait_process_exit(leader, deadline=time.monotonic() + 5)
        try:
            audit_container._stop_process(leader)
            with self.assertRaises((PermissionError, ProcessLookupError)):
                os.killpg(leader.pid, 0)
        finally:
            with suppress(PermissionError, ProcessLookupError):
                os.killpg(leader.pid, signal.SIGKILL)

    def test_subprocess_runner_uses_argv_minimal_env_new_group_and_separate_pipes(self) -> None:
        runner = audit_container._SubprocessDockerRunner()
        script = (
            "import os,sys;"
            "sys.stdout.write(sys.argv[1]+'\\n');"
            "sys.stderr.write('stderr-only\\n');"
            "sys.stdout.write(str(os.getpid()==os.getsid(0))+'\\n');"
            "sys.stdout.write(','.join(sorted(os.environ))+'\\n')"
        )
        result = runner.run(
            (sys.executable, "-c", script, "$(touch should-not-run);*"),
            input_stream=None,
            deadline=_deadline(),
            stdout_limit=1024,
            stderr_limit=1024,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
        self.assertEqual(b"stderr-only\n", result.stderr)
        lines = result.stdout.decode("utf-8").splitlines()
        self.assertEqual("$(touch should-not-run);*", lines[0])
        self.assertEqual("True", lines[1])
        observed_environment = set(lines[2].split(","))
        self.assertTrue({"LANG", "LC_ALL", "PATH"} <= observed_environment)
        self.assertTrue(
            observed_environment <= {"LANG", "LC_ALL", "PATH", "__CF_USER_TEXT_ENCODING"}
        )
        self.assertFalse((self.root / "should-not-run").exists())

    def test_subprocess_runner_enforces_independent_output_caps_and_deadline(self) -> None:
        runner = audit_container._SubprocessDockerRunner()
        with self.assertRaises(AuditContainerError):
            runner.run(
                (sys.executable, "-c", "import sys;sys.stderr.write('x'*33)"),
                input_stream=None,
                deadline=_deadline(),
                stdout_limit=1024,
                stderr_limit=32,
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            )
        with self.assertRaises(AuditContainerError):
            runner.run(
                (sys.executable, "-c", "import time;time.sleep(5)"),
                input_stream=None,
                deadline=time.monotonic() + 0.05,
                stdout_limit=1024,
                stderr_limit=1024,
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            )


if __name__ == "__main__":
    unittest.main()
