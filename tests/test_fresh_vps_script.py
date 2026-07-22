from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "fresh_vps_verify.sh"
INSTALLER_URL = "https://hermes-agent.nousresearch.com/install.sh"


class FreshVPSVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)
        self.root = Path(self._temporary_directory.name)
        self.checkout = self.root / "checkout"
        self.checkout.mkdir()
        (self.checkout / "scripts").mkdir()
        (self.checkout / "zeus").mkdir()
        shutil.copy2(SCRIPT, self.checkout / "scripts" / SCRIPT.name)
        (self.checkout / "pyproject.toml").write_text("[project]\nname='test'\n")
        (self.checkout / "zeus" / "cli.py").write_text("# verifier fixture\n")

        self.home = self.root / "home"
        self.home.mkdir()
        self.stub_bin = self.root / "bin"
        self.stub_bin.mkdir()
        self.curl_capture = self.root / "curl.jsonl"
        self.apt_capture = self.root / "apt.log"
        self.installer_executed = self.root / "installer-executed"
        self.fake_installer = self.root / "fake-hermes-installer.sh"
        self.fake_installer.write_text(
            "\n".join(
                [
                    "#!/usr/bin/env bash",
                    "set -eu",
                    'mkdir -p "$HOME/.local/bin"',
                    "cat > \"$HOME/.local/bin/hermes\" <<'HERMES'",
                    "#!/usr/bin/env bash",
                    "exit 0",
                    "HERMES",
                    'chmod 700 "$HOME/.local/bin/hermes"',
                    "printf 'executed\\n' > \"$INSTALLER_EXECUTED\"",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        self.installer_digest = hashlib.sha256(self.fake_installer.read_bytes()).hexdigest()
        self._write_stubs()

    def _write_executable(self, name: str, content: str) -> None:
        path = self.stub_bin / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o700)

    def _write_stubs(self) -> None:
        python_stub = textwrap.dedent(
            f"""\
            #!/usr/bin/env bash
            set -eu
            real_python={str(Path(sys.executable))!r}
            if [ "${{1:-}}" = "-I" ]; then
              exec "$real_python" "$@"
            fi
            if [ "${{1:-}}" = "-B" ] && [ "${{2:-}}" = "-c" ]; then
              exec "$real_python" "$@"
            fi
            if [ "${{1:-}}" = "-m" ] && [ "${{2:-}}" = "venv" ]; then
              mkdir -p "$3/bin"
              : > "$3/bin/activate"
              exit 0
            fi
            if [ "${{1:-}}" = "--version" ]; then
              printf 'Python fixture\n'
            fi
            exit 0
            """
        )
        self._write_executable("python3", python_stub)
        self._write_executable("python", python_stub)
        self._write_executable(
            "sh",
            "#!/usr/bin/env bash\nset -eu\nexit 0\n",
        )

        curl_stub = textwrap.dedent(
            f"""\
            #!{sys.executable}
            import json
            import os
            from pathlib import Path
            import shutil
            import sys

            args = sys.argv[1:]
            config_stdin = sys.stdin.read() if "--config" in args and "-" in args else ""
            capture = Path(os.environ["CURL_CAPTURE"])
            with capture.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({{"argv": args, "stdin": config_stdin}}) + "\\n")

            if {INSTALLER_URL!r} in args:
                source = Path(os.environ["FAKE_INSTALLER_SOURCE"])
                if "-o" in args:
                    output = Path(args[args.index("-o") + 1])
                    shutil.copyfile(source, output)
                else:
                    sys.stdout.buffer.write(source.read_bytes())
            else:
                print('{{"status":"ok"}}')
            """
        )
        self._write_executable("curl", curl_stub)

    def _base_environment(self) -> dict[str, str]:
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{self.stub_bin}:/usr/bin:/bin",
                "HOME": str(self.home),
                "CURL_CAPTURE": str(self.curl_capture),
                "FAKE_INSTALLER_SOURCE": str(self.fake_installer),
                "INSTALLER_EXECUTED": str(self.installer_executed),
                "ZEUS_VPS_INSTALL_HERMES": "1",
                "ZEUS_VPS_LOG_DIR": "evidence",
                "ZEUS_VPS_VENV_DIR": ".fixture-venv",
                "ZEUS_VPS_MULTI_STATE_DIR": ".fixture-multi",
                "ZEUS_VPS_API_STATE_DIR": ".fixture-api",
            }
        )
        environment.pop("ZEUS_VPS_API_KEY", None)
        environment.pop("ZEUS_VPS_HERMES_INSTALLER_SHA256", None)
        return environment

    def _pythonless_bootstrap_path(self) -> str:
        bootstrap_bin = self.root / "bootstrap-bin"
        bootstrap_bin.mkdir()
        for name in ("curl", "sh"):
            (bootstrap_bin / name).symlink_to(self.stub_bin / name)
        for name in (
            "bash",
            "cat",
            "chmod",
            "date",
            "dirname",
            "env",
            "ln",
            "mkdir",
            "rm",
            "seq",
            "sleep",
            "tee",
            "uname",
        ):
            executable = shutil.which(name)
            if executable is None:
                self.fail(f"required fixture executable is unavailable: {name}")
            (bootstrap_bin / name).symlink_to(executable)

        sudo = bootstrap_bin / "sudo"
        sudo.write_text('#!/bin/bash\nset -eu\nexec "$@"\n', encoding="utf-8")
        sudo.chmod(0o700)
        apt_get = bootstrap_bin / "apt-get"
        apt_get.write_text(
            "\n".join(
                [
                    "#!/bin/bash",
                    "set -eu",
                    'printf \'%s\\n\' "$*" >> "$APT_CAPTURE"',
                    'if [ "${1:-}" = "install" ]; then',
                    '  ln -sf "$PYTHON_STUB_SOURCE" "$BOOTSTRAP_BIN/python3"',
                    '  ln -sf "$PYTHON_STUB_SOURCE" "$BOOTSTRAP_BIN/python"',
                    "fi",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        apt_get.chmod(0o700)
        return str(bootstrap_bin)

    def _run(
        self,
        *,
        timeout: float = 20,
        **overrides: str,
    ) -> subprocess.CompletedProcess[str]:
        environment = self._base_environment()
        environment.update(overrides)
        arguments = ["/bin/bash", "scripts/fresh_vps_verify.sh"]
        process = subprocess.Popen(
            arguments,
            cwd=self.checkout,
            env=environment,
            text=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate("", timeout=timeout)
        except subprocess.TimeoutExpired as error:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
            raise subprocess.TimeoutExpired(
                error.cmd,
                error.timeout,
                output=stdout,
                stderr=stderr,
            ) from None
        return subprocess.CompletedProcess(arguments, process.returncode, stdout, stderr)

    def _curl_records(self) -> list[dict[str, object]]:
        if not self.curl_capture.exists():
            return []
        return [
            json.loads(line) for line in self.curl_capture.read_text(encoding="utf-8").splitlines()
        ]

    def test_missing_installer_digest_fails_before_download(self) -> None:
        result = self._run()

        self.assertNotEqual(0, result.returncode)
        self.assertIn("ZEUS_VPS_HERMES_INSTALLER_SHA256", result.stdout + result.stderr)
        self.assertFalse(self.installer_executed.exists())
        self.assertFalse(any(INSTALLER_URL in record["argv"] for record in self._curl_records()))

    def test_pythonless_bootstrap_path_contains_only_explicit_stubs(self) -> None:
        bootstrap_path = self._pythonless_bootstrap_path()

        self.assertEqual([str(self.root / "bootstrap-bin")], bootstrap_path.split(os.pathsep))
        self.assertIsNone(shutil.which("python3", path=bootstrap_path))

    def test_missing_python_is_bootstrapped_before_private_evidence(self) -> None:
        bootstrap_path = self._pythonless_bootstrap_path()
        result = self._run(
            PATH=bootstrap_path,
            APT_CAPTURE=str(self.apt_capture),
            BOOTSTRAP_BIN=bootstrap_path.removesuffix(":/bin"),
            PYTHON_STUB_SOURCE=str(self.stub_bin / "python3"),
            ZEUS_VPS_INSTALL_PACKAGES="1",
            ZEUS_VPS_HERMES_INSTALLER_SHA256=self.installer_digest,
            ZEUS_VPS_API_KEY="bootstrap-test-key",
        )

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("Bootstrapping the Python 3 prerequisite", result.stdout)
        apt_commands = self.apt_capture.read_text(encoding="utf-8").splitlines()
        self.assertIn("install -y python3", apt_commands)
        self.assertTrue(any("python3-venv" in command for command in apt_commands))
        self.assertEqual(0o700, stat.S_IMODE((self.checkout / "evidence").stat().st_mode))

    def test_missing_python_without_package_bootstrap_fails_deterministically(self) -> None:
        bootstrap_path = self._pythonless_bootstrap_path()
        result = self._run(
            PATH=bootstrap_path,
            APT_CAPTURE=str(self.apt_capture),
            BOOTSTRAP_BIN=bootstrap_path.removesuffix(":/bin"),
            PYTHON_STUB_SOURCE=str(self.stub_bin / "python3"),
        )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("Python 3 is required", result.stdout + result.stderr)
        self.assertFalse((self.checkout / "evidence").exists())

    def test_malformed_installer_digest_fails_before_download(self) -> None:
        result = self._run(ZEUS_VPS_HERMES_INSTALLER_SHA256="g" * 64)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("64", result.stdout + result.stderr)
        self.assertFalse(self.installer_executed.exists())
        self.assertFalse(any(INSTALLER_URL in record["argv"] for record in self._curl_records()))

    def test_mismatched_installer_digest_never_executes(self) -> None:
        result = self._run(ZEUS_VPS_HERMES_INSTALLER_SHA256="0" * 64)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("mismatch", (result.stdout + result.stderr).lower())
        self.assertFalse(self.installer_executed.exists())
        self.assertTrue(any(INSTALLER_URL in record["argv"] for record in self._curl_records()))

    def test_matching_digest_executes_and_sensitive_curl_uses_stdin(self) -> None:
        api_key = 'sentinel-api-key-"quote\\nslash'
        result = self._run(
            ZEUS_VPS_HERMES_INSTALLER_SHA256=self.installer_digest,
            ZEUS_VPS_API_KEY=api_key,
        )

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertTrue(self.installer_executed.exists())
        transcript = result.stdout + result.stderr
        run_log = (self.checkout / "evidence" / "run.log").read_text(encoding="utf-8")
        self.assertNotIn(api_key, transcript)
        self.assertNotIn(api_key, run_log)
        self.assertIn("authenticated API request [redacted]", transcript)

        records = self._curl_records()
        argv_text = "\n".join(" ".join(record["argv"]) for record in records)
        self.assertNotIn(api_key, argv_text)
        authenticated = [record for record in records if record["stdin"]]
        self.assertEqual(2, len(authenticated))
        escaped = api_key.replace("\\", "\\\\").replace('"', '\\"')
        for record in authenticated:
            self.assertIn("--config", record["argv"])
            self.assertNotIn("-H", record["argv"])
            self.assertIn(f'header = "x-zeus-api-key: {escaped}"', record["stdin"])

        evidence = self.checkout / "evidence"
        self.assertEqual(0o700, stat.S_IMODE(evidence.stat().st_mode))
        for name in ("run.log", "zeus-api.log", "hermes-install.sh"):
            with self.subTest(name=name):
                self.assertEqual(0o600, stat.S_IMODE((evidence / name).stat().st_mode))

    def test_existing_evidence_permissions_are_repaired(self) -> None:
        evidence = self.checkout / "evidence"
        evidence.mkdir()
        evidence.chmod(0o777)
        for name in ("run.log", "zeus-api.log", "hermes-install.sh"):
            path = evidence / name
            path.write_text("old evidence\n", encoding="utf-8")
            path.chmod(0o666)

        result = self._run(
            ZEUS_VPS_HERMES_INSTALLER_SHA256=self.installer_digest,
            ZEUS_VPS_API_KEY="permission-test-key",
        )

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(0o700, stat.S_IMODE(evidence.stat().st_mode))
        for name in ("run.log", "zeus-api.log", "hermes-install.sh"):
            with self.subTest(name=name):
                self.assertEqual(0o600, stat.S_IMODE((evidence / name).stat().st_mode))

    def test_async_prompt_uses_a_fixed_sensitive_transcript_label(self) -> None:
        prompt = "SENTINEL_ASYNC_PROMPT_must_not_be_logged"
        result = self._run(
            ZEUS_VPS_HERMES_INSTALLER_SHA256=self.installer_digest,
            ZEUS_VPS_API_KEY="async-test-key",
            ZEUS_VPS_ASYNC_PROMPT=prompt,
        )

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        transcript = result.stdout + result.stderr
        run_log = (self.checkout / "evidence" / "run.log").read_text(encoding="utf-8")
        self.assertIn("Hermes async prompt [redacted]", transcript)
        self.assertNotIn(prompt, transcript)
        self.assertNotIn(prompt, run_log)

    def test_default_api_key_is_ephemeral_and_generated_by_secrets(self) -> None:
        result = self._run(ZEUS_VPS_HERMES_INSTALLER_SHA256=self.installer_digest)

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        authenticated = [record for record in self._curl_records() if record["stdin"]]
        self.assertEqual(2, len(authenticated))
        headers = []
        for record in authenticated:
            for line in str(record["stdin"]).splitlines():
                if line.startswith('header = "x-zeus-api-key: '):
                    header = line.removeprefix('header = "x-zeus-api-key: ')
                    headers.append(header.removesuffix('"'))
        self.assertEqual(2, len(headers))
        self.assertEqual(headers[0], headers[1])
        self.assertRegex(headers[0], r"^[0-9a-f]{64}$")
        self.assertNotIn(headers[0], result.stdout + result.stderr)

    def test_api_key_with_line_breaks_is_rejected_without_disclosure(self) -> None:
        api_key = "sentinel\r\ninjected-header"
        result = self._run(
            ZEUS_VPS_HERMES_INSTALLER_SHA256=self.installer_digest,
            ZEUS_VPS_API_KEY=api_key,
        )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("line break", (result.stdout + result.stderr).lower())
        self.assertNotIn(api_key, result.stdout + result.stderr)
        self.assertFalse(any(record["stdin"] for record in self._curl_records()))

    def test_symlinked_evidence_directory_is_rejected_without_mutating_target(self) -> None:
        external = self.root / "external"
        external.mkdir(mode=0o755)
        (self.checkout / "evidence").symlink_to(external, target_is_directory=True)

        result = self._run(ZEUS_VPS_HERMES_INSTALLER_SHA256=self.installer_digest)

        self.assertNotEqual(0, result.returncode)
        self.assertEqual([], list(external.iterdir()))
        self.assertEqual(0o755, stat.S_IMODE(external.stat().st_mode))
        self.assertFalse(self.installer_executed.exists())

    def test_symlinked_evidence_file_is_rejected_without_mutating_target(self) -> None:
        evidence = self.checkout / "evidence"
        evidence.mkdir(mode=0o700)
        external = self.root / "external.log"
        external.write_text("preserve me\n", encoding="utf-8")
        external.chmod(0o644)
        (evidence / "run.log").symlink_to(external)

        result = self._run(ZEUS_VPS_HERMES_INSTALLER_SHA256=self.installer_digest)

        self.assertNotEqual(0, result.returncode)
        self.assertEqual("preserve me\n", external.read_text(encoding="utf-8"))
        self.assertEqual(0o644, stat.S_IMODE(external.stat().st_mode))
        self.assertFalse(self.installer_executed.exists())

    def test_fifo_evidence_file_is_rejected_without_blocking(self) -> None:
        evidence = self.checkout / "evidence"
        evidence.mkdir(mode=0o700)
        fifo = evidence / "run.log"
        os.mkfifo(fifo, mode=0o600)

        try:
            result = self._run(
                timeout=1.0,
                ZEUS_VPS_HERMES_INSTALLER_SHA256=self.installer_digest,
            )
        except subprocess.TimeoutExpired:
            self.fail("verifier blocked while opening a pre-existing evidence FIFO")

        self.assertNotEqual(0, result.returncode)
        self.assertTrue(stat.S_ISFIFO(fifo.lstat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(fifo.lstat().st_mode))
        self.assertFalse(self.installer_executed.exists())


if __name__ == "__main__":
    unittest.main()
