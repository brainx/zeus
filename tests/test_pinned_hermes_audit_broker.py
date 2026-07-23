from __future__ import annotations

import importlib.metadata
import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

from zeus.audit_container import PreparedAuditContainer
from zeus.audit_docker_broker import (
    cleanup_audit_docker_broker,
    install_audit_docker_broker,
    read_audit_docker_broker_state,
)
from zeus.audit_models import HARD_LIMITS

RUN_ID = "2" * 32
PROFILE = f"audit-{RUN_ID}"
IMAGE_REF = "registry.example.invalid/audit@sha256:" + "a" * 64
IMAGE_ID = "sha256:" + "b" * 64
CONTAINER_ID = "c" * 64


def _installed_pinned_hermes() -> bool:
    try:
        return importlib.metadata.version("hermes-agent") == "0.19.0"
    except importlib.metadata.PackageNotFoundError:
        return False


@unittest.skipUnless(
    _installed_pinned_hermes(),
    "requires installed hermes-agent==0.19.0",
)
class PinnedHermesAuditBrokerTests(unittest.TestCase):
    def test_pinned_backend_completes_the_sealed_broker_protocol(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            broker_dir = root / "broker"
            broker_dir.mkdir(mode=0o700)
            state_path = broker_dir / "state.json"
            log_path = root / "real-docker.log"
            real_docker = root / "real-docker"
            real_docker.write_text(
                textwrap.dedent(
                    f"""\
                    #!{sys.executable}
                    import json
                    import re
                    import sys

                    argv = sys.argv[1:]
                    with open({str(log_path)!r}, "a", encoding="utf-8") as log:
                        log.write(json.dumps(argv, separators=(",", ":")) + "\\n")
                    if argv[:2] == ["image", "inspect"]:
                        sys.stdout.write('["/bin/sh"]\\n')
                    elif argv[:2] == ["inspect", "--format"]:
                        sys.stdout.write("none\\n")
                    elif argv[0] == "exec":
                        script = argv[-1]
                        match = re.search(r"(__HERMES_CWD_[0-9a-f]{{12}}__)", script)
                        if match:
                            marker = match.group(1)
                            if argv[3:5] == ["-l", "-c"]:
                                sys.stdout.write(f"\\n{{marker}}/workspace{{marker}}\\n")
                            else:
                                sys.stdout.write(
                                    f"AUDIT_BROKER_OK\\n{{marker}}/workspace{{marker}}\\n"
                                )
                    elif argv[:2] == ["rm", "-f"]:
                        sys.stdout.write(argv[2] + "\\n")
                    else:
                        raise SystemExit(125)
                    """
                ),
                encoding="utf-8",
            )
            real_docker.chmod(0o500)
            prepared = PreparedAuditContainer(
                container_id=CONTAINER_ID,
                container_name=f"zeus-audit-{RUN_ID}",
                profile_name=PROFILE,
                image_ref=IMAGE_REF,
                image_id=IMAGE_ID,
                broker_dir=broker_dir,
                state_path=state_path,
            )
            broker_executable = install_audit_docker_broker(
                prepared,
                docker_executable=real_docker,
                limits=HARD_LIMITS,
                deadline=time.monotonic() + 120,
                python_executable=Path(sys.executable).resolve(),
            )
            self.assertEqual(0o500, stat.S_IMODE(broker_executable.lstat().st_mode))

            source = textwrap.dedent(
                f"""\
                import json
                import tools.environments.docker as docker_backend

                docker_backend._docker_executable = None
                docker_backend._cgroup_limits_ok = None
                docker_backend._storage_opt_ok = None
                docker_backend._get_active_profile_name = lambda: {PROFILE!r}
                environment = docker_backend.DockerEnvironment(
                    image={IMAGE_REF!r},
                    cwd="/workspace",
                    timeout=30,
                    cpu=2,
                    memory=4096,
                    disk=0,
                    persistent_filesystem=False,
                    task_id="default",
                    volumes=[],
                    forward_env=[],
                    env={{}},
                    network=False,
                    host_cwd=None,
                    auto_mount_cwd=False,
                    run_as_host_user=False,
                    extra_args=[],
                    persist_across_processes=True,
                )
                result = environment.execute("printf AUDIT_BROKER_OK")
                print(json.dumps(result, sort_keys=True))
                environment.cleanup()
                """
            )
            environment = {
                "HOME": str(root / "home"),
                "HERMES_HOME": str(root / "hermes-home"),
                "HERMES_DOCKER_BINARY": str(broker_executable),
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "PYTHONPATH": str(Path.cwd()),
            }
            (root / "home").mkdir(mode=0o700)
            (root / "hermes-home").mkdir(mode=0o700)
            result = subprocess.run(
                [sys.executable, "-c", source],
                cwd=root,
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            payload = json.loads(result.stdout.strip().splitlines()[-1])
            self.assertEqual(0, payload["returncode"])
            self.assertIn("AUDIT_BROKER_OK", payload["output"])

            cleanup = cleanup_audit_docker_broker(state_path)
            self.assertEqual(0, cleanup.returncode)
            state = read_audit_docker_broker_state(state_path)
            self.assertEqual("closed", state.phase)
            self.assertTrue(state.bootstrap_complete)
            self.assertEqual(1, state.terminal_calls)
            self.assertFalse(state.limit_breach)
            self.assertEqual("complete", state.cleanup_state)

            real_calls = [
                json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual("image", real_calls[0][0])
            self.assertEqual(
                ["inspect", "--format", "{{.HostConfig.NetworkMode}}", CONTAINER_ID],
                real_calls[1],
            )
            self.assertEqual(["exec", CONTAINER_ID, "bash", "-l", "-c"], real_calls[2][:5])
            self.assertEqual(["exec", CONTAINER_ID, "bash", "-c"], real_calls[3][:4])
            self.assertEqual(["rm", "-f", CONTAINER_ID], real_calls[4])


if __name__ == "__main__":
    unittest.main()
