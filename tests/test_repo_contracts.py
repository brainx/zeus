from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import tomllib
import unittest
from pathlib import Path

from zeus.state import SCHEMA_VERSION


def _workflow_job_bodies(workflow: str) -> dict[str, str]:
    jobs_header = re.search(r"(?m)^jobs:\s*$", workflow)
    if jobs_header is None:
        raise ValueError("workflow has no jobs mapping")

    jobs_text = workflow[jobs_header.end() :]
    next_top_level = re.search(r"(?m)^[A-Za-z_][A-Za-z0-9_-]*:\s*", jobs_text)
    if next_top_level is not None:
        jobs_text = jobs_text[: next_top_level.start()]

    headers = list(re.finditer(r"(?m)^  (?P<name>[A-Za-z0-9_-]+):\s*$", jobs_text))
    if not headers:
        raise ValueError("workflow jobs mapping is empty")

    jobs: dict[str, str] = {}
    for index, header in enumerate(headers):
        name = header.group("name")
        if name in jobs:
            raise ValueError(f"duplicate workflow job: {name}")
        end = headers[index + 1].start() if index + 1 < len(headers) else len(jobs_text)
        jobs[name] = jobs_text[header.end() : end]
    return jobs


def _job_level_scalar(job_body: str, key: str) -> str:
    values = re.findall(
        rf"(?m)^    {re.escape(key)}:\s*(?P<value>[^\s#][^\n#]*?)\s*(?:#.*)?$",
        job_body,
    )
    if len(values) != 1:
        raise ValueError(f"expected one job-level {key}, found {len(values)}")
    return values[0]


def _job_python_versions(job_body: str) -> tuple[str, ...]:
    matrix = re.search(r"(?m)^        python-version:\s*(?P<versions>\[[^\n]+\])\s*$", job_body)
    if matrix is not None:
        versions = json.loads(matrix.group("versions"))
        if not isinstance(versions, list) or not all(isinstance(item, str) for item in versions):
            raise ValueError("python-version matrix must be a list of strings")
        return tuple(versions)

    setup_versions = re.findall(
        r'(?m)^          python-version:\s*"(?P<version>3\.\d+)"\s*$', job_body
    )
    if len(setup_versions) != 1:
        raise ValueError(f"expected one setup-python version, found {len(setup_versions)}")
    return tuple(setup_versions)


def _job_run_commands(job_body: str) -> tuple[str, ...]:
    lines = job_body.splitlines()
    commands: list[str] = []
    index = 0
    while index < len(lines):
        match = re.match(r"^        run:\s*(?P<value>.*)$", lines[index])
        if match is None:
            index += 1
            continue

        value = match.group("value").strip()
        if value not in {"|", "|-"}:
            commands.append(value)
            index += 1
            continue

        index += 1
        block: list[str] = []
        while index < len(lines):
            line = lines[index]
            if line.strip() and len(line) - len(line.lstrip(" ")) <= 8:
                break
            block.append(line)
            index += 1
        commands.append(textwrap.dedent("\n".join(block)).strip())
    return tuple(commands)


def _markdown_table_rows(markdown: str) -> dict[str, tuple[str, ...]]:
    rows: dict[str, tuple[str, ...]] = {}
    for line in markdown.splitlines():
        if not line.startswith("|"):
            continue
        cells = tuple(cell.strip() for cell in line.strip().strip("|").split("|"))
        if not cells or cells[0] == "Gate" or set(cells[0]) <= {"-", ":"}:
            continue
        if cells[0] in rows:
            raise ValueError(f"duplicate Markdown table row: {cells[0]}")
        rows[cells[0]] = cells[1:]
    return rows


class RepoContractTests(unittest.TestCase):
    def test_builtin_template_copies_are_identical_and_images_are_digest_pinned(
        self,
    ) -> None:
        source_root = Path("templates")
        bundled_root = Path("zeus/bundled_templates")
        expected_image = (
            "nikolaik/python-nodejs:python3.11-nodejs20@sha256:"
            "8f958bdc1b4a422bfafd97cab4f69836401f616ae985d4b57a53d254f5bcb038"
        )
        source_names = sorted(path.name for path in source_root.glob("*.toml"))
        bundled_names = sorted(path.name for path in bundled_root.glob("*.toml"))

        self.assertEqual(source_names, bundled_names)
        self.assertGreaterEqual(len(source_names), 7)
        for name in source_names:
            with self.subTest(template=name):
                source_text = (source_root / name).read_text(encoding="utf-8")
                bundled_text = (bundled_root / name).read_text(encoding="utf-8")
                self.assertEqual(source_text, bundled_text)

                data = tomllib.loads(source_text)
                docker_image = data["hermes"]["terminal"]["docker_image"]
                self.assertIsInstance(docker_image, str)
                self.assertEqual(expected_image, docker_image)
                self.assertRegex(
                    docker_image,
                    r"\A[a-z0-9./_-]+:[a-zA-Z0-9._-]+@sha256:[0-9a-f]{64}\Z",
                )

    def test_publishable_repository_files_exist(self) -> None:
        required = [
            "README.md",
            "LICENSE",
            "CREDITS.md",
            "CONTRIBUTING.md",
            "CODE_OF_CONDUCT.md",
            "SECURITY.md",
            "CHANGELOG.md",
            "docs/ARCHITECTURE.md",
            "docs/API.md",
            "docs/TEMPLATE_AUTHORING.md",
            "docs/REAL_HERMES_VERIFICATION.md",
            "docs/FRESH_VPS_TEST.md",
            "docs/SYSTEMD.md",
            "docs/OPERATIONS.md",
            "docs/RECONCILE.md",
            "docs/RELEASE.md",
            "docs/COMPATIBILITY.md",
            "docs/openapi.json",
            "docs/ROADMAP.md",
            "docs/assets/demo.cast",
            "docs/assets/zeus-hero.png",
            ".coveragerc",
            "requirements-hermes-ci.txt",
            ".github/workflows/release.yml",
            ".github/ISSUE_TEMPLATE/bug_report.yml",
            ".github/ISSUE_TEMPLATE/feature_request.yml",
            ".github/ISSUE_TEMPLATE/config.yml",
            ".github/pull_request_template.md",
            "systemd/zeus-api.service",
            "systemd/zeus-reconcile.service",
            "systemd/zeus-reconcile.timer",
            "scripts/repo_check.sh",
            "scripts/check_verified_release_ref.py",
            "scripts/wheel_smoke.sh",
            "scripts/fresh_vps_verify.sh",
            "zeus/bundled_skills/__init__.py",
            "zeus/bundled_skills/audit/__init__.py",
            "zeus/bundled_skills/audit/SKILL.md",
            "zeus/audit_profile.py",
            "zeus/bundled_templates/__init__.py",
            "zeus/bundled_templates/coding-bot.toml",
            "zeus/bundled_templates/deepseek-coding-bot.toml",
            "zeus/bundled_templates/docs-writer-bot.toml",
            "zeus/bundled_templates/gateway-operator.toml",
            "zeus/bundled_templates/log-triage-bot.toml",
            "zeus/bundled_templates/research-bot.toml",
            "zeus/bundled_templates/support-gateway.toml",
            "templates/deepseek-coding-bot.toml",
            "templates/docs-writer-bot.toml",
            "templates/gateway-operator.toml",
            "templates/log-triage-bot.toml",
        ]

        for path in required:
            with self.subTest(path=path):
                self.assertTrue(Path(path).is_file())

        self.assertFalse(Path("docs/superpowers").exists())
        self.assertFalse(Path("docs/REPO_GENERATION.md").exists())

    def test_ci_runs_project_test_script_on_supported_python_versions(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        jobs = _workflow_job_bodies(workflow)

        expected_runners = {
            "test": "ubuntu-24.04",
            "python-3-14": "ubuntu-24.04",
            "lifecycle-subprocess": "ubuntu-24.04",
            "macos-process-lifecycle": "macos-26",
            "real-hermes": "ubuntu-24.04",
            "package": "ubuntu-24.04",
        }
        expected_python_versions = {
            "test": ("3.11", "3.12", "3.13"),
            "python-3-14": ("3.14",),
            "lifecycle-subprocess": ("3.11",),
            "macos-process-lifecycle": ("3.13",),
            "real-hermes": ("3.11",),
            "package": ("3.11",),
        }
        expected_setup_python = {
            "test": "${{ matrix.python-version }}",
            "python-3-14": '"3.14"',
            "lifecycle-subprocess": '"3.11"',
            "macos-process-lifecycle": '"3.13"',
            "real-hermes": '"3.11"',
            "package": '"3.11"',
        }
        expected_commands = {
            "test": (
                "sudo apt-get update\nsudo apt-get install -y shellcheck",
                'python -m pip install -e ".[dev]"',
                "ruff format --check .",
                "ruff check .",
                "mypy zeus",
                "bandit -r zeus",
                "shellcheck scripts/*.sh",
                "sh scripts/test.sh",
                "sh scripts/repo_check.sh",
                "coverage erase\ncoverage run -m unittest discover -s tests\ncoverage report",
            ),
            "python-3-14": (
                'python -m pip install -e ".[dev]"',
                "sh scripts/test.sh",
            ),
            "lifecycle-subprocess": (
                'python -m pip install -e ".[dev]"',
                "python -m unittest tests.test_subprocess_lifecycle",
            ),
            "macos-process-lifecycle": (
                'python -m pip install -e ".[dev]"',
                "python -m unittest -v \\\n"
                "  tests.test_subprocess_lifecycle \\\n"
                "  tests.test_fake_hermes_integration \\\n"
                "  tests.test_crash_recovery.GatewayLauncherTests",
            ),
            "real-hermes": (
                "mkdir -p .tmp/real-hermes-evidence\n"
                "printf '%s\\n' 'result=failed' 'failure_stage=ci_setup' > "
                ".tmp/real-hermes-evidence/summary.txt",
                "python -m pip install --require-hashes --only-binary=:all: "
                "-r requirements-hermes-ci.txt",
                "python -m pip install -e .",
                "python -m pip check",
                "ZEUS_VERIFY_START_GATEWAY=1 \\\n"
                "ZEUS_VERIFY_EXPECTED_HERMES_VERSION=0.19.0 \\\n"
                "ZEUS_VERIFY_EVIDENCE_DIR=.tmp/real-hermes-evidence \\\n"
                "sh scripts/verify_real_hermes.sh",
            ),
            "package": (
                'python -m pip install -e ".[dev]"',
                "python -m pip check",
                "rm -rf dist\npython -m build",
                "ZEUS_WHEEL_SMOKE_BUILD=0 sh scripts/wheel_smoke.sh",
                "twine check dist/*",
            ),
        }

        self.assertEqual(set(expected_runners), set(jobs))
        self.assertIn("workflow_dispatch:", workflow)
        for job_name, job_body in jobs.items():
            with self.subTest(job=job_name):
                self.assertEqual(expected_runners[job_name], _job_level_scalar(job_body, "runs-on"))
                self.assertEqual(expected_python_versions[job_name], _job_python_versions(job_body))
                self.assertEqual(
                    [expected_setup_python[job_name]],
                    re.findall(r"(?m)^          python-version:\s*(.+?)\s*$", job_body),
                )
                self.assertEqual(expected_commands[job_name], _job_run_commands(job_body))

        job_level_continue_on_error: dict[str, str] = {}
        for job_name, job_body in jobs.items():
            values = re.findall(r"(?m)^    continue-on-error:\s*([^\s#]+)\s*$", job_body)
            self.assertLessEqual(len(values), 1, msg=f"duplicate setting in {job_name}")
            if values:
                job_level_continue_on_error[job_name] = values[0]
        self.assertEqual({"python-3-14": "true"}, job_level_continue_on_error)

        real_hermes = jobs["real-hermes"]
        self.assertEqual("15", _job_level_scalar(real_hermes, "timeout-minutes"))
        self.assertNotIn("secrets.", real_hermes)
        self.assertNotRegex(real_hermes, r"(?i)(openai|anthropic|openrouter).*api[_-]?key")
        self.assertRegex(real_hermes, r"(?m)^        if: failure\(\)\s*$")
        self.assertIn(".tmp/real-hermes-evidence/summary.txt", real_hermes)
        self.assertIn("if-no-files-found: error", real_hermes)

        python_314 = jobs["python-3-14"].lower()
        self.assertNotIn("hermes", python_314)
        self.assertNotIn("verify_real_hermes", python_314)

        macos_selectors = re.findall(
            r"(?<![\w.])(tests(?:\.[A-Za-z_][A-Za-z0-9_]*)+)",
            jobs["macos-process-lifecycle"],
        )
        self.assertEqual(
            [
                "tests.test_subprocess_lifecycle",
                "tests.test_fake_hermes_integration",
                "tests.test_crash_recovery.GatewayLauncherTests",
            ],
            macos_selectors,
        )

        package_commands = _job_run_commands(jobs["package"])
        pip_check_index = package_commands.index("python -m pip check")
        for later_command in (
            "rm -rf dist\npython -m build",
            "ZEUS_WHEEL_SMOKE_BUILD=0 sh scripts/wheel_smoke.sh",
            "twine check dist/*",
        ):
            self.assertLess(pip_check_index, package_commands.index(later_command))

    def test_test_script_preserves_failures_and_gates_resource_warnings(self) -> None:
        script_source = Path("scripts/test.sh").read_text(encoding="utf-8")
        fake_python_source = textwrap.dedent(
            """\
            #!/bin/sh
            set -eu
            : "${FAKE_PYTHON_LOG:?}"
            : "${FAKE_UNITTEST_MODE:?}"
            printf '%s\\n' "$*" >> "$FAKE_PYTHON_LOG"
            case "$*" in
              *"-m compileall zeus tests")
                exit 0
                ;;
              *"-m unittest discover -s tests -v")
                case "$FAKE_UNITTEST_MODE" in
                  warning)
                    printf '%s\\n' "Exception ignored in: <_io.FileIO name='fixture'>" >&2
                    printf '%s\\n' "ResourceWarning: unclosed file <fixture>" >&2
                    exit 0
                    ;;
                  exit7)
                    printf '%s\\n' "synthetic unittest failure" >&2
                    exit 7
                    ;;
                  clean)
                    exit 0
                    ;;
                  *)
                    exit 98
                    ;;
                esac
                ;;
              *"-m zeus.cli doctor --json")
                printf '%s\\n' '{"ok": true}'
                ;;
              *"-m zeus.cli template list")
                printf '%s\\n' 'coding-bot'
                ;;
              *)
                printf '%s\\n' "unexpected python invocation: $*" >&2
                exit 97
                ;;
            esac
            """
        )

        def run_case(
            root: Path, mode: str
        ) -> tuple[subprocess.CompletedProcess[str], tuple[str, ...]]:
            case_root = root / mode
            scripts_dir = case_root / "scripts"
            bin_dir = case_root / "bin"
            scripts_dir.mkdir(parents=True)
            bin_dir.mkdir()
            script = scripts_dir / "test.sh"
            fake_python = bin_dir / "python3"
            log = case_root / "python-calls.log"
            script.write_text(script_source, encoding="utf-8")
            fake_python.write_text(fake_python_source, encoding="utf-8")
            fake_python.chmod(0o755)

            environment = os.environ.copy()
            environment.update(
                {
                    "FAKE_PYTHON_LOG": str(log),
                    "FAKE_UNITTEST_MODE": mode,
                    "PATH": str(bin_dir) + os.pathsep + environment.get("PATH", ""),
                }
            )
            shell = shutil.which("sh", path=environment["PATH"])
            if shell is None:
                self.fail("POSIX sh is required for the shell contract")
            result = subprocess.run(
                [shell, str(script)],
                cwd=case_root,
                env=environment,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            calls = tuple(log.read_text(encoding="utf-8").splitlines())
            return result, calls

        pre_gate_calls = (
            "-B -m compileall zeus tests",
            "-B -W error::ResourceWarning -m unittest discover -s tests -v",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)

            warning_result, warning_calls = run_case(root, "warning")
            self.assertNotEqual(0, warning_result.returncode)
            self.assertIn("Exception ignored in:", warning_result.stderr)
            self.assertIn("ResourceWarning", warning_result.stderr)
            self.assertEqual(pre_gate_calls, warning_calls)

            failed_result, failed_calls = run_case(root, "exit7")
            self.assertEqual(7, failed_result.returncode)
            self.assertNotIn("ResourceWarning", failed_result.stderr)
            self.assertEqual(pre_gate_calls, failed_calls)

            clean_result, clean_calls = run_case(root, "clean")
            self.assertEqual(0, clean_result.returncode)
            self.assertEqual(
                (
                    *pre_gate_calls,
                    "-B -m zeus.cli doctor --json",
                    "-B -m zeus.cli template list",
                ),
                clean_calls,
            )

    def test_wheel_smoke_exercises_installed_demo_entrypoint(self) -> None:
        script = Path("scripts/wheel_smoke.sh").read_text(encoding="utf-8")

        canonical_root = 'repo_root="$(pwd -P)"'
        tmp_dir = 'tmp_dir="$repo_root/.tmp/wheel-smoke"'
        self.assertIn(canonical_root, script)
        self.assertIn(tmp_dir, script)
        self.assertLess(script.index(canonical_root), script.index(tmp_dir))
        self.assertNotIn('repo_root="$(pwd)"', script)

        trap_index = script.index("trap cleanup EXIT INT TERM")
        for initialization in ('venv_zeus=""', 'state_dir="$tmp_dir/state"', "demo_started=0"):
            self.assertIn(initialization, script)
            self.assertLess(script.index(initialization), trap_index)

        cleanup = script[script.index("cleanup() {") : trap_index]
        self.assertIn('[ "$demo_started" = "1" ]', cleanup)
        self.assertIn('ZEUS_STATE_DIR="$state_dir" "$venv_zeus" demo down --json', cleanup)
        self.assertLess(cleanup.index("demo down --json"), cleanup.index('rm -rf "$tmp_dir"'))

        help_command = '"$venv_zeus" --help'
        pip_check_command = '"$venv_python" -m pip check'
        self.assertIn(help_command, script)
        self.assertIn(pip_check_command, script)
        cd_index = script.index('cd "$tmp_dir"')
        help_index = script.index(help_command)
        pip_check_index = script.index(pip_check_command)
        self.assertLess(cd_index, help_index)
        self.assertLess(cd_index, pip_check_index)
        self.assertIn("unset PYTHONPATH PYTHONHOME", script)
        self.assertIn("export PYTHONNOUSERSITE=1", script)
        self.assertIn('export PATH="$tmp_dir/venv/bin:$PATH"', script)
        self.assertIn("command -v zeus-fake-hermes", script)
        self.assertIn('"$venv_zeus" --help >zeus-help.txt', script)
        self.assertIn('grep -F "usage: zeus" zeus-help.txt', script)

        self.assertIn('version("zeus-hermes-orchestrator")', script)
        self.assertIn("import zeus; print(zeus.__version__)", script)
        self.assertIn('cli_version=$("$venv_zeus" --version)', script)
        self.assertIn('[ "$metadata_version" = "$module_version" ]', script)
        self.assertIn('[ "$cli_version" = "zeus $metadata_version" ]', script)
        self.assertIn("zeus.__file__", script)
        self.assertGreaterEqual(script.count('[ ! -e "$state_dir" ]'), 2)

        for template_id in (
            "coding-bot",
            "deepseek-coding-bot",
            "docs-writer-bot",
            "gateway-operator",
            "log-triage-bot",
            "research-bot",
            "support-gateway",
        ):
            self.assertIn(template_id, script)

        self.assertIn('export ZEUS_STATE_DIR="$state_dir"', script)
        self.assertIn('"$venv_zeus" doctor --json', script)
        up_index = script.index('"$venv_zeus" demo up --json')
        status_index = script.index('"$venv_zeus" demo status --json')
        down_index = script.index('"$venv_zeus" demo down --json', up_index)
        self.assertLess(up_index, status_index)
        self.assertLess(status_index, down_index)
        self.assertNotEqual(-1, script.rfind("demo_started=1", 0, up_index))
        self.assertNotEqual(-1, script.find("demo_started=0", down_index))
        self.assertIn('"fake_hermes_bin"', script)
        self.assertIn('"status": "running"', script)
        self.assertIn('"status": "stopped"', script)

    def test_coverage_artifacts_are_ignored(self) -> None:
        gitignore = Path(".gitignore").read_text(encoding="utf-8")

        self.assertIn(".coverage", gitignore)
        self.assertIn(".mypy_cache/", gitignore)

    def test_coverage_gate_measures_production_source_and_branches(self) -> None:
        config = Path(".coveragerc").read_text(encoding="utf-8")

        self.assertIn("branch = True", config)
        self.assertRegex(config, r"(?m)^source =\s*$")
        self.assertRegex(config, r"(?m)^[ \t]+zeus[ \t]*$")
        self.assertIn("fail_under = 79", config)
        self.assertNotIn("fail_under = 70", config)
        self.assertIn("precision = 2", config)

    def test_workflow_actions_are_pinned_to_immutable_commits(self) -> None:
        for path in [Path(".github/workflows/ci.yml"), Path(".github/workflows/release.yml")]:
            workflow = path.read_text(encoding="utf-8")
            uses = re.findall(r"(?m)^\s*-?\s*uses:\s*[^@\s]+@([^\s#]+)", workflow)

            self.assertTrue(uses, f"expected action references in {path}")
            for ref in uses:
                with self.subTest(path=str(path), ref=ref):
                    self.assertRegex(ref, r"^[0-9a-f]{40}$")

    def test_repo_check_script_verifies_required_handoff_artifacts(self) -> None:
        script = Path("scripts/repo_check.sh").read_text(encoding="utf-8")

        self.assertIn('tmp_dir=".tmp/repo-check"', script)
        self.assertIn("trap cleanup EXIT INT TERM", script)
        self.assertIn('ZEUS_STATE_DIR="$tmp_dir/state"', script)
        self.assertIn("LICENSE", script)
        self.assertIn("SECURITY.md", script)
        self.assertIn(".coveragerc", script)
        self.assertIn("docs/ARCHITECTURE.md", script)
        self.assertIn("docs/TEMPLATE_AUTHORING.md", script)
        self.assertIn("docs/FRESH_VPS_TEST.md", script)
        self.assertIn("docs/SYSTEMD.md", script)
        self.assertIn("docs/OPERATIONS.md", script)
        self.assertIn("docs/RECONCILE.md", script)
        self.assertIn("docs/RELEASE.md", script)
        self.assertIn("docs/openapi.json", script)
        self.assertIn("CODE_OF_CONDUCT.md", script)
        self.assertIn(".github/workflows/release.yml", script)
        self.assertIn("systemd/zeus-api.service", script)
        self.assertIn("systemd/zeus-reconcile.service", script)
        self.assertIn("systemd/zeus-reconcile.timer", script)
        self.assertIn("scripts/wheel_smoke.sh", script)
        self.assertIn("scripts/fresh_vps_verify.sh", script)
        self.assertIn("zeus/bundled_templates/coding-bot.toml", script)
        self.assertIn("templates/deepseek-coding-bot.toml", script)
        self.assertIn("templates/docs-writer-bot.toml", script)
        self.assertIn("templates/gateway-operator.toml", script)
        self.assertIn("templates/log-triage-bot.toml", script)
        self.assertIn("Repository readiness check passed.", script)
        self.assertIn("internal planning path must not be published", script)

    def test_repository_audit_contract_is_documented_and_packaged(self) -> None:
        readme = Path("README.md").read_text(encoding="utf-8")
        security = Path("SECURITY.md").read_text(encoding="utf-8")
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        audit = Path("docs/AUDIT.md").read_text(encoding="utf-8")
        architecture = Path("docs/ARCHITECTURE.md").read_text(encoding="utf-8")
        operations = Path("docs/OPERATIONS.md").read_text(encoding="utf-8")
        compatibility = Path("docs/COMPATIBILITY.md").read_text(encoding="utf-8")
        roadmap = Path("docs/ROADMAP.md").read_text(encoding="utf-8")
        repo_check = Path("scripts/repo_check.sh").read_text(encoding="utf-8")
        pyproject = Path("pyproject.toml").read_text(encoding="utf-8")

        self.assertIn("docs/AUDIT.md", repo_check)
        self.assertIn("zeus/bundled_skills/audit/SKILL.md", repo_check)
        self.assertIn('"zeus.bundled_skills.audit" = ["SKILL.md"]', pyproject)
        self.assertIn("Status: implemented.", audit)
        self.assertIn("environment-dependent release verification", audit)

        readme_audit = readme.split("## Repository Audit", 1)[1].split("\n## ", 1)[0]
        readiness_docs = readme_audit.split("### Check readiness", 1)[1].split(
            "### Run an audit", 1
        )[0]
        run_docs = readme_audit.split("### Run an audit", 1)[1].split("### Read stored reports", 1)[
            0
        ]
        stored_report_docs = readme_audit.split("### Read stored reports", 1)[1]
        self.assertIn("zeus audit doctor", readiness_docs)
        self.assertNotIn("zeus audit run", readiness_docs)
        self.assertIn("zeus audit run", run_docs)
        for prerequisite in (
            "Docker",
            "Hermes Agent 0.19.0",
            "provider credentials",
            "preloaded",
        ):
            with self.subTest(run_prerequisite=prerequisite):
                self.assertIn(prerequisite, readiness_docs + run_docs)
        self.assertIn("zeus audit list", stored_report_docs)
        self.assertIn("zeus audit show <run-id>", stored_report_docs)
        self.assertNotIn("zeus audit run", stored_report_docs)
        for runtime_check in ("Docker", "Hermes", "credential", "image"):
            with self.subTest(stored_report_runtime_check=runtime_check):
                self.assertRegex(stored_report_docs, rf"do not invoke[^.]*{runtime_check}")

        for command in (
            "zeus audit doctor [--json]",
            "zeus audit run [--json]",
            "zeus audit list [--json]",
            "zeus audit show <run-id> [--json]",
        ):
            with self.subTest(command=command):
                self.assertIn(command, audit)
                self.assertIn(command.split(" [", 1)[0], readme)

        for text in (readme, security, audit, architecture, operations, compatibility, roadmap):
            with self.subTest(document=text[:24]):
                self.assertIn("committed `HEAD`", text)
                self.assertIn("Hermes Agent 0.19.0", text)
                self.assertIn("cross-host", text)

        self.assertIn("preloaded", readme)
        self.assertIn("provider", readme.lower())
        self.assertIn("network mode `none`", " ".join(security.split()))
        self.assertIn("Linux Docker isolation", " ".join(compatibility.split()))
        self.assertIn("ZEUS_RUN_DOCKER_ISOLATION=1", compatibility)
        self.assertIn("does not establish runtime isolation", compatibility)
        self.assertIn("report.json", operations)
        self.assertIn("report.md", operations)
        self.assertIn("one concurrent audit per repository", audit)
        self.assertIn("never remediates", audit)
        self.assertIn("does not schedule", audit)
        self.assertIn("fixed credential", audit)
        self.assertIn("selected snapshot scope", audit)
        self.assertIn("`.git/info/exclude`", audit)
        self.assertIn("exactly `summary`, `findings`, `checks`, and", audit)
        self.assertIn("explicit lowercase Hermes provider", readme)
        self.assertIn("Human\noutput shows run ID, status, and target commit.", audit)
        self.assertIn("fails during pre-run validation\nwithout creating an audit artifact", audit)
        self.assertIn("Cleanup attempts to stop run-owned processes", operations)
        self.assertIn("$ZEUS_STATE_DIR/audit/runs/<run-id>", audit)
        self.assertIn("no stale-resource scanner or cleanup command", audit)
        self.assertIn("explicit operator\ninspection and removal", audit)
        self.assertNotIn("stale cleanup", audit)
        self.assertEqual(1, audit.count("- `check`: the name of a check present in the report"))
        self.assertEqual(
            1,
            audit.count("The test also inspects the effective container network mode"),
        )
        self.assertIn("repository audit", changelog.lower())

    def test_readme_has_informative_github_landing_sections(self) -> None:
        readme = Path("README.md").read_text(encoding="utf-8")

        self.assertIn("Many Hermes bots, one local supervisor.", readme)
        self.assertIn("## Why Zeus", readme)
        self.assertIn("## How It Works", readme)
        self.assertIn("## Quick Start", readme)
        self.assertIn("## 60-Second Demo", readme)
        self.assertIn("docs/assets/zeus-hero.png", readme)
        self.assertIn("docs/assets/demo.cast", readme)
        self.assertIn("docs/SYSTEMD.md", readme)
        self.assertIn("docs/OPERATIONS.md", readme)
        self.assertIn("docs/RECONCILE.md", readme)
        self.assertIn("docs/RELEASE.md", readme)
        self.assertIn("docs/ROADMAP.md", readme)
        self.assertIn("actions/workflows/ci.yml/badge.svg", readme)
        self.assertIn("badge.svg?branch=main", readme)
        self.assertIn("CODE_OF_CONDUCT.md", readme)
        self.assertNotIn("REPO_GENERATION.md", readme)
        self.assertIn("Package Build", readme)
        self.assertIn("Security Policy", readme)
        self.assertIn("```mermaid", readme)
        self.assertIn("local process orchestrator, not a sandbox", readme)
        self.assertIn("Do not expose the API", readme)
        self.assertIn("## Known Limitations", readme)

    def test_onboarding_compatibility_and_roadmap_match_current_evidence(self) -> None:
        readme = Path("README.md").read_text(encoding="utf-8")
        contributing = Path("CONTRIBUTING.md").read_text(encoding="utf-8")
        roadmap = Path("docs/ROADMAP.md").read_text(encoding="utf-8")
        roadmap_text = " ".join(roadmap.split())
        ci_workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        release_workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
        pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
        compatibility_path = Path("docs/COMPATIBILITY.md")

        self.assertTrue(compatibility_path.is_file())
        compatibility = compatibility_path.read_text(encoding="utf-8")
        compatibility_text = " ".join(compatibility.split())

        offline_heading = "### 1. Credential-free offline demo"
        hermes_heading = "### 2. Real Hermes setup"
        self.assertLess(readme.index(offline_heading), readme.index(hermes_heading))
        offline_path = readme.split(offline_heading, 1)[1].split(hermes_heading, 1)[0]
        hermes_path = readme.split(hermes_heading, 1)[1].split("\n## ", 1)[0]
        for command in (
            "python3 -m venv .venv",
            "python -m pip install -e .",
            "zeus demo up",
            "zeus demo status",
            "zeus demo down",
        ):
            self.assertIn(command, offline_path)
        for command in (
            "hermes version",
            "cp .env.example .env",
            "chmod 0600 .env",
            "zeus doctor",
            "--env-from OPENROUTER_API_KEY",
            "zeus bot doctor coder",
        ):
            self.assertIn(command, hermes_path)
        self.assertIn("real, non-empty provider key", hermes_path)
        self.assertIn("docs/COMPATIBILITY.md", readme)
        self.assertIn("no required third-party Python runtime dependencies", readme)

        self.assertIn('python -m pip install -e ".[dev]"', contributing)
        self.assertIn("make check", contributing)
        self.assertIn("docs/COMPATIBILITY.md", contributing)
        self.assertIn("sh scripts/verify_real_hermes.sh", contributing)

        for heading in (
            "## Current status",
            "## Shipped",
            "## Near term",
            "## Under evaluation",
            "## Out of scope",
        ):
            self.assertIn(heading, roadmap)
        for statement in (
            "v0.3.0",
            "alpha",
            "host-local",
            "cross-host placement",
            "distributed approvals",
            "fleet rollout policy",
            "control-plane ownership",
            "Olymp",
        ):
            self.assertIn(statement, roadmap_text)

        ci_jobs = _workflow_job_bodies(ci_workflow)
        release_jobs = _workflow_job_bodies(release_workflow)
        automated_matrix = compatibility.split("## Automated matrix", 1)[1].split("\n## ", 1)[0]
        compatibility_rows = _markdown_table_rows(automated_matrix)
        compatibility_contracts = {
            "test": (
                ci_jobs["test"],
                "Main CI matrix",
                "ubuntu-24.04",
                ("3.11", "3.12", "3.13"),
                (
                    "Linux `ubuntu-24.04`",
                    "Python 3.11, 3.12, and 3.13",
                    "Unit and integration tests, repository contracts, source-and-branch "
                    "coverage, formatting, lint, typing, Bandit, and ShellCheck",
                ),
            ),
            "python-3-14": (
                ci_jobs["python-3-14"],
                "Provisional Python compatibility",
                "ubuntu-24.04",
                ("3.14",),
                (
                    "Linux `ubuntu-24.04`",
                    "Python 3.14",
                    "Full Zeus test suite; non-required and Zeus-only because the pinned "
                    "Hermes baseline requires Python below 3.14",
                ),
            ),
            "lifecycle-subprocess": (
                ci_jobs["lifecycle-subprocess"],
                "Subprocess lifecycle",
                "ubuntu-24.04",
                ("3.11",),
                (
                    "Linux `ubuntu-24.04`",
                    "Python 3.11",
                    "Focused multi-process lifecycle and locking behavior",
                ),
            ),
            "macos-process-lifecycle": (
                ci_jobs["macos-process-lifecycle"],
                "macOS process lifecycle",
                "macos-26",
                ("3.13",),
                (
                    "macOS `macos-26`",
                    "Python 3.13",
                    "Focused process, fake-Hermes integration, and gateway-launcher recovery tests",
                ),
            ),
            "real-hermes": (
                ci_jobs["real-hermes"],
                "Real Hermes compatibility",
                "ubuntu-24.04",
                ("3.11",),
                (
                    "Linux `ubuntu-24.04`",
                    "Python 3.11",
                    "Hash-locked Hermes Agent 0.19.0 profile rendering, strict diagnostics, "
                    "loopback gateway readiness, process ownership, and clean shutdown "
                    "without a model-provider credential",
                ),
            ),
            "package": (
                ci_jobs["package"],
                "Package build",
                "ubuntu-24.04",
                ("3.11",),
                (
                    "Linux `ubuntu-24.04`",
                    "Python 3.11",
                    "Wheel and source build, installed-wheel smoke test, dependency "
                    "consistency, and metadata checks",
                ),
            ),
            "release:build": (
                release_jobs["build"],
                "Tagged release build",
                "ubuntu-latest",
                ("3.11",),
                (
                    "Linux `ubuntu-latest`",
                    "Python 3.11",
                    "Full release gate, artifact checksums, and GitHub release artifacts",
                ),
            ),
        }
        requires_python = re.search(r'(?m)^requires-python = "([^"]+)"$', pyproject)

        self.assertIsNotNone(requires_python)
        self.assertEqual(
            {contract[1] for contract in compatibility_contracts.values()},
            set(compatibility_rows),
        )
        for job_name, contract in compatibility_contracts.items():
            job_body, row_name, runner, python_versions, expected_row = contract
            with self.subTest(compatibility_job=job_name):
                self.assertEqual(runner, _job_level_scalar(job_body, "runs-on"))
                self.assertEqual(python_versions, _job_python_versions(job_body))
                self.assertEqual(expected_row, compatibility_rows[row_name])
        self.assertIn(
            f'`requires-python = "{requires_python.group(1)}"`',
            compatibility_text,
        )
        self.assertIn("lifecycle and package jobs use Python 3.11", compatibility_text)
        self.assertIn("Debian and Ubuntu", compatibility_text)
        self.assertIn("Hermes Agent 0.19.0", compatibility_text)
        self.assertIn("complete 60-package wheel closure", compatibility_text)
        self.assertIn("no model-provider credential", compatibility_text)
        self.assertIn("whichever `hermes` executable is installed", compatibility_text)
        self.assertIn("Python 3.14", compatibility_text)
        self.assertIn("provisional Zeus-only", compatibility_text)
        self.assertIn("focused process", compatibility_text.lower())
        self.assertIn("Windows is not currently automated", compatibility_text)

    def test_env_example_lists_deepseek_and_api_auth(self) -> None:
        env = Path(".env.example").read_text(encoding="utf-8")
        api_docs = Path("docs/API.md").read_text(encoding="utf-8")

        self.assertIn("ZEUS_API_KEY=", env)
        self.assertIn("ZEUS_ALLOW_UNAUTH_READS=0", env)
        self.assertIn("DEEPSEEK_API_KEY=", env)
        self.assertIn("ZEUS_ENV_PASSTHROUGH=", env)
        self.assertIn("All non-health endpoints require", api_docs)
        self.assertIn("POST /bots/<bot-id>/restart", api_docs)
        self.assertIn("unsupported_media_type", api_docs)
        self.assertIn("docs/openapi.json", api_docs)

    def test_observability_and_lifecycle_history_are_documented(self) -> None:
        readme = Path("README.md").read_text(encoding="utf-8")
        api_docs = Path("docs/API.md").read_text(encoding="utf-8")
        architecture = Path("docs/ARCHITECTURE.md").read_text(encoding="utf-8")
        operations = Path("docs/OPERATIONS.md").read_text(encoding="utf-8")
        env_example = Path(".env.example").read_text(encoding="utf-8")

        self.assertIn("X-Request-ID", api_docs)
        self.assertIn("zeus bot history", readme)
        self.assertIn("lifecycle_events", architecture)
        self.assertIn("ZEUS_API_LOG_ENABLED", env_example)
        self.assertIn("$ZEUS_STATE_DIR/logs/api.jsonl", api_docs)
        self.assertIn("mode `0700`", api_docs)
        self.assertIn("`0600`", api_docs)
        self.assertIn("fail open", api_docs)
        self.assertIn("next_before", api_docs)
        self.assertIn("even when `ZEUS_ALLOW_UNAUTH_READS=1`", api_docs)
        self.assertIn("best-effort compatibility mirror", architecture)
        self.assertIn("`BEGIN IMMEDIATE` transaction", architecture)
        self.assertIn("v2-to-v3 migration is one-way", operations)
        self.assertIn("pre-migration database backup", operations)

        access_fields = {
            "schema_version",
            "ts",
            "level",
            "event",
            "request_id",
            "method",
            "route",
            "status",
            "error_code",
            "duration_ms",
            "auth_outcome",
            "idempotency_outcome",
        }
        for field in access_fields:
            self.assertIn(f"`{field}`", api_docs)

    def test_architecture_terminal_schema_compatibility_matches_runtime(self) -> None:
        architecture = Path("docs/ARCHITECTURE.md").read_text(encoding="utf-8")
        compatibility_statements = re.findall(
            r"Databases newer than\s+schema v(?P<version>\d+) "
            r"are rejected rather than downgraded\.",
            architecture,
        )

        self.assertEqual(1, len(compatibility_statements))
        self.assertEqual(str(SCHEMA_VERSION), compatibility_statements[0])

    def test_every_openapi_response_documents_request_id_header(self) -> None:
        document = json.loads(Path("docs/openapi.json").read_text(encoding="utf-8"))
        request_id_header = document["components"]["headers"]["XRequestID"]
        self.assertEqual("string", request_id_header["schema"]["type"])
        self.assertEqual("^[0-9a-f]{32}$", request_id_header["schema"]["pattern"])

        for path, path_item in document["paths"].items():
            for method, operation in path_item.items():
                if method not in {"get", "post", "put", "patch", "delete", "options"}:
                    continue
                for status, response in operation["responses"].items():
                    with self.subTest(path=path, method=method, status=status):
                        self.assertEqual(
                            {"$ref": "#/components/headers/XRequestID"},
                            response["headers"]["X-Request-ID"],
                        )

    def test_deepseek_template_uses_native_provider(self) -> None:
        text = Path("templates/deepseek-coding-bot.toml").read_text(encoding="utf-8")

        self.assertIn('provider = "deepseek"', text)
        self.assertIn('default = "deepseek-v4-pro"', text)
        self.assertNotIn("base_url", text)
        self.assertNotIn("api_mode", text)
        self.assertIn("DEEPSEEK_API_KEY", text)

    def test_real_hermes_verifier_is_isolated_and_checks_async_cap(self) -> None:
        script = Path("scripts/verify_real_hermes.sh").read_text(encoding="utf-8")

        self.assertIn("command -v hermes", script)
        self.assertIn(".zeus-real-hermes-check", script)
        self.assertIn("bot doctor", script)
        self.assertIn("max_async_children", script)
        self.assertIn("ZEUS_VERIFY_START_GATEWAY", script)
        self.assertIn("ZEUS_VERIFY_API_KEY", script)
        self.assertIn("ZEUS_VERIFY_API_SERVER_PORT", script)
        self.assertIn("ZEUS_VERIFY_HEALTH_TIMEOUT_SECONDS", script)
        self.assertIn("ZEUS_VERIFY_HEALTH_INTERVAL_SECONDS", script)
        self.assertIn("API_SERVER_ENABLED", script)
        self.assertIn("ZEUS_ENV_PASSTHROUGH", script)
        self.assertIn("bot inspect", script)
        self.assertIn("/health", script)
        self.assertIn("time.monotonic", script)
        self.assertIn("Hermes /health did not become ready", script)
        self.assertIn("ZEUS_VERIFY_EXPECTED_HERMES_VERSION", script)
        self.assertIn('bot start "$bot_id" --wait', script)
        self.assertIn("ZEUS_VERIFY_EVIDENCE_DIR", script)
        self.assertIn("failure_stage=%s", script)
        self.assertIn('rm -rf -- "$state_dir"', script)

    def test_real_hermes_ci_lock_is_complete_and_hash_pinned(self) -> None:
        requirements = Path("requirements-hermes-ci.txt").read_text(encoding="utf-8")
        entries = re.findall(
            r"(?m)^([a-z0-9][a-z0-9._-]*)==([^\\\s]+) \\$",
            requirements,
        )
        hashes = re.findall(r"(?m)^    --hash=sha256:([0-9a-f]{64})(?: \\)?$", requirements)

        self.assertEqual(60, len(entries))
        self.assertEqual(60, len({name for name, _version in entries}))
        self.assertEqual(74, len(hashes))
        self.assertIn(("hermes-agent", "0.19.0"), entries)
        self.assertIn(
            "bd0bac012aee38a60894781f4597dc29ee7bedb3448540249921f10d3bef327f",
            hashes,
        )
        self.assertNotIn("--index-url", requirements)
        self.assertNotIn("git+", requirements)

    def test_fresh_vps_verifier_bootstraps_and_captures_evidence(self) -> None:
        script = Path("scripts/fresh_vps_verify.sh").read_text(encoding="utf-8")

        self.assertIn("ZEUS_VPS_INSTALL_PACKAGES", script)
        self.assertIn("ZEUS_VPS_INSTALL_HERMES", script)
        self.assertIn("https://hermes-agent.nousresearch.com/install.sh", script)
        self.assertIn("scripts/verify_real_hermes.sh", script)
        self.assertIn("ZEUS_VPS_ASYNC_PROMPT", script)
        self.assertIn("zeus-api.log", script)
        self.assertIn("safe_relative_dir", script)
        self.assertIn("git rev-parse HEAD", script)
        self.assertIn("git status --short", script)

    def test_pyproject_has_no_placeholder_repository_urls(self) -> None:
        pyproject = Path("pyproject.toml").read_text(encoding="utf-8")

        self.assertNotIn("github.com/" + "example", pyproject)
        self.assertIn('license = "MIT"', pyproject)
        self.assertIn('zeus = "zeus.cli:main"', pyproject)
        self.assertIn('zeus-fake-hermes = "zeus.demo.fake_hermes:main"', pyproject)
        self.assertIn("[project.optional-dependencies]", pyproject)
        self.assertIn("ruff>=0.6.0", pyproject)
        self.assertIn("mypy>=1.11.0", pyproject)
        self.assertIn("bandit>=1.7.9", pyproject)
        self.assertIn("coverage>=7.0.0", pyproject)
        self.assertNotIn('"pytest', pyproject)
        self.assertIn('dynamic = ["version"]', pyproject)
        self.assertIn('version = {attr = "zeus.__version__"}', pyproject)
        self.assertIn('Repository = "https://github.com/brainx/zeus"', pyproject)
        self.assertIn('Documentation = "https://github.com/brainx/zeus/tree/main/docs"', pyproject)
        self.assertIn('Issues = "https://github.com/brainx/zeus/issues"', pyproject)
        self.assertIn(
            'Changelog = "https://github.com/brainx/zeus/blob/main/CHANGELOG.md"', pyproject
        )
        self.assertNotIn('version = "0.1.3"', pyproject)
        self.assertIn("[tool.setuptools.package-data]", pyproject)
        self.assertIn('"zeus.bundled_templates" = ["*.toml"]', pyproject)
        self.assertIn('"zeus.bundled_skills.audit" = ["SKILL.md"]', pyproject)
        self.assertIn("[tool.ruff]", pyproject)
        self.assertIn("[tool.mypy]", pyproject)
        self.assertIn("[tool.bandit]", pyproject)

    def test_package_version_is_single_sourced_from_zeus_init(self) -> None:
        init_text = Path("zeus/__init__.py").read_text(encoding="utf-8")
        pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        openapi = Path("docs/openapi.json").read_text(encoding="utf-8")

        self.assertIn('__version__ = "0.3.0"', init_text)
        self.assertIn('dynamic = ["version"]', pyproject)
        self.assertIn('version = {attr = "zeus.__version__"}', pyproject)
        self.assertNotIn('version = "0.1.3"', pyproject)
        self.assertIn("## 0.3.0", changelog)
        self.assertIn('"version": "0.3.0"', openapi)

    def test_inspect_api_is_documented_and_secured(self) -> None:
        api = Path("zeus/api.py").read_text(encoding="utf-8")
        docs = Path("docs/API.md").read_text(encoding="utf-8")
        openapi = Path("docs/openapi.json").read_text(encoding="utf-8")
        tests = Path("tests/test_api.py").read_text(encoding="utf-8")

        self.assertIn('path.endswith("/inspect")', api)
        self.assertIn("supervisor.inspect(bot_id)", api)
        self.assertIn("GET /bots/<bot-id>/inspect", docs)
        self.assertIn("/bots/{bot_id}/inspect", openapi)
        self.assertIn("test_bot_inspect_requires_key", tests)

    def test_sensitive_get_diagnostics_require_auth(self) -> None:
        api = Path("zeus/api.py").read_text(encoding="utf-8")
        docs = Path("docs/API.md").read_text(encoding="utf-8")
        tests = Path("tests/test_api.py").read_text(encoding="utf-8")

        self.assertIn('path.endswith("/logs")', api)
        self.assertIn('path.endswith("/inspect")', api)
        self.assertIn("_get_requires_strict_auth", api)
        self.assertIn("GET /bots/<bot-id>/logs", docs)
        self.assertIn("test_bot_logs_requires_key", tests)

    def test_cli_exposes_restart_lifecycle_command(self) -> None:
        cli = Path("zeus/cli.py").read_text(encoding="utf-8")
        supervisor = Path("zeus/supervisor.py").read_text(encoding="utf-8")
        api = Path("zeus/api.py").read_text(encoding="utf-8")
        readme = Path("README.md").read_text(encoding="utf-8")

        self.assertIn('"restart"', cli)
        self.assertIn('"reconcile"', cli)
        self.assertIn("def restart", supervisor)
        self.assertIn("def reconcile", supervisor)
        self.assertIn(".restart(", api)
        self.assertIn(".reconcile(", api)
        self.assertIn("zeus bot restart coder", readme)
        self.assertIn("zeus bot reconcile coder", readme)

    def test_systemd_and_operations_docs_are_actionable(self) -> None:
        service = Path("systemd/zeus-api.service").read_text(encoding="utf-8")
        reconcile_service = Path("systemd/zeus-reconcile.service").read_text(encoding="utf-8")
        reconcile_timer = Path("systemd/zeus-reconcile.timer").read_text(encoding="utf-8")
        systemd_docs = Path("docs/SYSTEMD.md").read_text(encoding="utf-8")
        operations = Path("docs/OPERATIONS.md").read_text(encoding="utf-8")
        reconcile_docs = Path("docs/RECONCILE.md").read_text(encoding="utf-8")

        self.assertIn("EnvironmentFile=/etc/zeus/zeus.env", service)
        self.assertIn("ExecStart=/opt/zeus/.venv/bin/python -m zeus.api", service)
        self.assertIn("Restart=on-failure", service)
        self.assertIn("ProtectSystem=strict", service)
        self.assertIn("ReadWritePaths=/var/lib/zeus", service)
        self.assertIn("ZEUS_API_KEY=replace-with-a-long-random-value", systemd_docs)
        self.assertIn(
            "sudo install -o zeus -g zeus -m 0750 -d /var/lib/zeus",
            systemd_docs,
        )
        self.assertIn("sudo systemctl enable --now zeus-api", systemd_docs)
        self.assertIn("Backup", operations)
        self.assertIn("sqlite3 /var/lib/zeus/zeus.db", operations)
        self.assertIn(".backup", operations)
        self.assertIn("Restore", operations)
        self.assertIn("zeus doctor --strict", operations)
        self.assertIn("Migration Rollback", operations)
        self.assertIn("Logs", operations)
        self.assertIn("/var/lib/zeus/logs/*.log", operations)
        self.assertIn("/var/lib/zeus/logs/*.jsonl", operations)
        self.assertIn("rotate 14", operations)
        self.assertIn("copytruncate", operations)
        self.assertIn("create 0600 zeus zeus", operations)
        self.assertIn("Upgrade", operations)
        self.assertIn("release_tag=vX.Y.Z", operations)
        self.assertIn(
            "sudo systemctl stop zeus-reconcile.timer zeus-reconcile.service zeus-api",
            operations,
        )
        self.assertLess(
            operations.index("sudo systemctl stop zeus-reconcile.timer"),
            operations.index('sudo -u zeus git checkout --detach "${release_tag}"'),
        )
        self.assertNotIn("git checkout v0.1.5", operations)
        self.assertIn("Restart Policy", operations)
        self.assertIn("ExecStart=/opt/zeus/.venv/bin/zeus bot reconcile", reconcile_service)
        self.assertIn("ReadWritePaths=/var/lib/zeus", reconcile_service)
        self.assertIn("OnUnitActiveSec=30s", reconcile_timer)
        self.assertIn("zeus bot reconcile", reconcile_docs)
        self.assertIn("zeus-reconcile.timer", reconcile_docs)

    def test_release_workflow_builds_tag_artifacts(self) -> None:
        release_docs = Path("docs/RELEASE.md").read_text(encoding="utf-8")
        workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
        wheel_smoke = Path("scripts/wheel_smoke.sh").read_text(encoding="utf-8")

        self.assertIn("sh scripts/test.sh", release_docs)
        self.assertIn("sh scripts/repo_check.sh", release_docs)
        self.assertIn("sh scripts/wheel_smoke.sh", release_docs)
        self.assertIn("coverage erase", release_docs)
        self.assertIn("coverage report", release_docs)
        self.assertIn("python -m build", release_docs)
        self.assertIn("twine check dist/*", release_docs)
        self.assertIn("SHA256SUMS.txt", release_docs)
        self.assertIn("tags:", workflow)
        self.assertIn('"v*.*.*"', workflow)
        self.assertIn("make release-check", workflow)
        self.assertIn("needs: build", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("contents: write", workflow)
        self.assertIn("id-token: write", workflow)
        self.assertIn("attestations: write", workflow)
        self.assertIn("git cat-file -t", workflow)
        self.assertIn("Release tags must be annotated tags.", workflow)
        self.assertIn("Require GitHub-verified release ref", workflow)
        self.assertIn("python scripts/check_verified_release_ref.py", workflow)
        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", workflow)
        self.assertIn("actions/attest-build-provenance@", workflow)
        self.assertIn("dist/*.tar.gz", workflow)
        self.assertIn("dist/*.whl", workflow)
        self.assertIn("dist/SHA256SUMS.txt", workflow)
        self.assertIn("actions/upload-artifact@", workflow)
        self.assertIn("actions/download-artifact@", workflow)
        self.assertIn("cd dist && sha256sum -c SHA256SUMS.txt", workflow)
        self.assertIn("annotated version tags", release_docs)
        self.assertIn("GitHub-verified annotated tag", release_docs)
        self.assertIn("v0.3.0 release predates", release_docs)
        self.assertIn("gh attestation verify", release_docs)
        self.assertIn('build_artifacts="${ZEUS_WHEEL_SMOKE_BUILD:-1}"', wheel_smoke)
        self.assertIn('fail "ZEUS_WHEEL_SMOKE_BUILD must be 0 or 1"', wheel_smoke)
        self.assertIn('fail "expected exactly one wheel in dist/"', wheel_smoke)

    def test_makefile_has_release_check_target(self) -> None:
        makefile = Path("Makefile").read_text(encoding="utf-8")
        check_recipe = re.search(r"(?m)^check:\n(?P<body>(?:\t[^\n]*\n)+)", makefile)
        build_recipe = re.search(r"(?m)^build:\n(?P<body>(?:\t[^\n]*\n)+)", makefile)
        release_recipe = re.search(r"(?m)^release-check:\n(?P<body>(?:\t[^\n]*\n)+)", makefile)

        self.assertIn("release-check:", makefile)
        self.assertIn("coverage:", makefile)
        self.assertIn("wheel-smoke:", makefile)
        self.assertIn("coverage erase", makefile)
        self.assertIn("coverage run -m unittest discover -s tests", makefile)
        self.assertIn("coverage report", makefile)
        self.assertNotIn("coverage report --fail-under", makefile)
        self.assertIn("shellcheck scripts/*.sh", makefile)
        self.assertIsNotNone(check_recipe)
        self.assertIsNotNone(build_recipe)
        self.assertIsNotNone(release_recipe)
        self.assertIn("shellcheck scripts/*.sh", check_recipe.group("body"))
        self.assertIn("python -m pip check", build_recipe.group("body"))
        self.assertIn("python -m pip check", release_recipe.group("body"))
        self.assertIn("rm -rf dist", makefile)
        self.assertIn("python -m build", makefile)
        self.assertIn("ZEUS_WHEEL_SMOKE_BUILD=0 sh scripts/wheel_smoke.sh", makefile)
        self.assertIn("twine check dist/*", makefile)
        self.assertIn("sh scripts/generate_checksums.sh dist", makefile)
        checksum_script = Path("scripts/generate_checksums.sh").read_text(encoding="utf-8")
        self.assertIn("sha256sum", checksum_script)
        self.assertIn("shasum -a 256", checksum_script)

    def test_openapi_contract_loads_and_documents_required_paths(self) -> None:
        spec = json.loads(Path("docs/openapi.json").read_text(encoding="utf-8"))
        paths = spec["paths"]
        required_paths = [
            "/health",
            "/doctor",
            "/templates",
            "/bots",
            "/bots/{bot_id}/status",
            "/bots/{bot_id}/logs",
            "/bots/{bot_id}/history",
            "/bots/{bot_id}/inspect",
            "/bots/{bot_id}/start",
            "/bots/{bot_id}/stop",
            "/bots/{bot_id}/restart",
            "/bots/{bot_id}/reconcile",
            "/bots/reconcile",
        ]

        for path in required_paths:
            with self.subTest(path=path):
                self.assertIn(path, paths)

        error_codes = spec["components"]["schemas"]["Error"]["properties"]["error"]["properties"][
            "code"
        ]["enum"]
        self.assertIn("missing_api_key", error_codes)
        self.assertIn("invalid_api_key", error_codes)
        self.assertIn("unsupported_media_type", error_codes)
        self.assertIn("method_not_allowed", error_codes)
        self.assertIn("internal_error", error_codes)
        history = paths["/bots/{bot_id}/history"]["get"]
        self.assertEqual([{"ZeusApiKey": []}], history["security"])
        parameters = {parameter["name"]: parameter for parameter in history["parameters"]}
        self.assertEqual(1, parameters["limit"]["schema"]["minimum"])
        self.assertEqual(1000, parameters["limit"]["schema"]["maximum"])
        self.assertEqual(1, parameters["before"]["schema"]["minimum"])
        self.assertEqual(
            "#/components/schemas/LifecycleHistory",
            history["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        )

    def test_readiness_openapi_and_operator_documentation_contract(self) -> None:
        spec = json.loads(Path("docs/openapi.json").read_text(encoding="utf-8"))
        api_docs = Path("docs/API.md").read_text(encoding="utf-8")
        operations = Path("docs/OPERATIONS.md").read_text(encoding="utf-8")

        self.assertIn("/ready", spec["paths"])
        self.assertNotIn("/v1/ready", spec["paths"])
        self.assertEqual([], spec["paths"]["/health"]["get"]["security"])
        readiness = spec["paths"]["/ready"]["get"]
        self.assertEqual([{"ZeusApiKey": []}], readiness["security"])
        self.assertEqual({"200", "400", "401", "429", "503"}, set(readiness["responses"]))
        self.assertEqual(
            "#/components/schemas/ReadinessResponse",
            readiness["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        )
        retry_after = readiness["responses"]["429"]["headers"]["Retry-After"]
        self.assertNotIn("$ref", retry_after)
        self.assertEqual({"type": "integer", "minimum": 1}, retry_after["schema"])
        for response in readiness["responses"].values():
            self.assertEqual(
                {"$ref": "#/components/headers/XRequestID"},
                response["headers"]["X-Request-ID"],
            )

        schema = spec["components"]["schemas"]["ReadinessResponse"]
        self.assertEqual(["schema_version", "status"], schema["required"])
        self.assertEqual(SCHEMA_VERSION, schema["properties"]["schema_version"]["const"])
        self.assertEqual("ready", schema["properties"]["status"]["const"])
        error_codes = spec["components"]["schemas"]["Error"]["properties"]["error"]["properties"][
            "code"
        ]["enum"]
        self.assertIn("not_ready", error_codes)
        for text in (api_docs, operations):
            self.assertIn("/ready", text)
            self.assertIn("/health", text)
            self.assertIn("ZEUS_ALLOW_UNAUTH_READS", text)

    def test_wave_two_replay_and_recovery_contracts_are_documented(self) -> None:
        spec = json.loads(Path("docs/openapi.json").read_text(encoding="utf-8"))
        api_docs = Path("docs/API.md").read_text(encoding="utf-8")
        architecture = Path("docs/ARCHITECTURE.md").read_text(encoding="utf-8")
        operations = Path("docs/OPERATIONS.md").read_text(encoding="utf-8")
        reconcile = Path("docs/RECONCILE.md").read_text(encoding="utf-8")
        readme = Path("README.md").read_text(encoding="utf-8")
        env_example = Path(".env.example").read_text(encoding="utf-8")

        bot = spec["components"]["schemas"]["Bot"]
        self.assertIn("desired_state", bot["required"])
        self.assertIn("converged", bot["required"])
        self.assertEqual(["running", "stopped"], bot["properties"]["desired_state"]["enum"])
        self.assertEqual("boolean", bot["properties"]["converged"]["type"])

        error_codes = spec["components"]["schemas"]["Error"]["properties"]["error"]["properties"][
            "code"
        ]["enum"]
        for code in (
            "idempotency_key_conflict",
            "idempotency_in_progress",
            "idempotency_indeterminate",
            "idempotency_store_unavailable",
        ):
            with self.subTest(code=code):
                self.assertIn(code, error_codes)

        mutation_paths = (
            "/bots",
            "/bots/reconcile",
            "/bots/{bot_id}/start",
            "/bots/{bot_id}/stop",
            "/bots/{bot_id}/restart",
            "/bots/{bot_id}/reconcile",
        )
        for path in mutation_paths:
            with self.subTest(path=path):
                operation = spec["paths"][path]["post"]
                parameters = {parameter["name"]: parameter for parameter in operation["parameters"]}
                key = parameters["Idempotency-Key"]
                self.assertFalse(key["required"])
                self.assertEqual("header", key["in"])
                self.assertEqual("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", key["schema"]["pattern"])
                self.assertIn("400", operation["responses"])
                self.assertIn("409", operation["responses"])
                self.assertIn("500", operation["responses"])
                self.assertIn("503", operation["responses"])
                for status in ("200", "400", "409", "500"):
                    self.assertIn(
                        "Idempotency-Replayed",
                        operation["responses"][status]["headers"],
                    )
                self.assertIn("Retry-After", operation["responses"]["409"]["headers"])
                self.assertNotIn(
                    "Idempotency-Replayed",
                    operation["responses"]["503"]["headers"],
                )
                if "{bot_id}" in path:
                    self.assertIn("404", operation["responses"])
                    self.assertIn(
                        "Idempotency-Replayed",
                        operation["responses"]["404"]["headers"],
                    )

        self.assertIn("Idempotency-Key", api_docs)
        self.assertIn("Idempotency-Replayed", api_docs)
        self.assertIn("retention window", api_docs)
        self.assertIn("idempotency_indeterminate", api_docs)
        self.assertIn("launcher", architecture.lower())
        self.assertIn("schema v5", architecture)
        self.assertIn("pre-v4/v5", operations)
        self.assertIn("forward-only", operations)
        self.assertIn("manual restart policy", reconcile)
        self.assertIn("at most one", reconcile)
        self.assertIn("desired_state", readme)
        self.assertIn("converged", readme)
        self.assertIn("ZEUS_API_IDEMPOTENCY_RETENTION_SECONDS=86400", env_example)
        self.assertIn("ZEUS_API_IDEMPOTENCY_MAX_RECORDS=10000", env_example)

    def test_wave_three_limits_and_reconcile_runs_are_documented(self) -> None:
        spec = json.loads(Path("docs/openapi.json").read_text(encoding="utf-8"))
        api_docs = Path("docs/API.md").read_text(encoding="utf-8")
        operations = Path("docs/OPERATIONS.md").read_text(encoding="utf-8")
        reconcile = Path("docs/RECONCILE.md").read_text(encoding="utf-8")
        readme = Path("README.md").read_text(encoding="utf-8")
        env_example = Path(".env.example").read_text(encoding="utf-8")
        systemd_service = Path("systemd/zeus-reconcile.service").read_text(encoding="utf-8")

        for setting in (
            "ZEUS_API_AUTH_FAILURE_RATE_PER_MINUTE=30",
            "ZEUS_API_AUTH_FAILURE_BURST=10",
            "ZEUS_API_MUTATION_RATE_PER_MINUTE=120",
            "ZEUS_API_MUTATION_BURST=30",
        ):
            with self.subTest(setting=setting):
                self.assertIn(setting, env_example)

        error_codes = spec["components"]["schemas"]["Error"]["properties"]["error"]["properties"][
            "code"
        ]["enum"]
        self.assertIn("auth_rate_limited", error_codes)
        self.assertIn("mutation_rate_limited", error_codes)
        self.assertIn("reconcile_locked", error_codes)

        for path in ("/bots/reconcile", "/bots/{bot_id}/reconcile"):
            with self.subTest(path=path):
                operation = spec["paths"][path]["post"]
                parameters = {parameter["name"]: parameter for parameter in operation["parameters"]}
                self.assertEqual("1", parameters["summary"]["schema"]["const"])
                response_schema = operation["responses"]["200"]["content"]["application/json"][
                    "schema"
                ]
                self.assertIn("oneOf", response_schema)

        self.assertIn("process-local", api_docs)
        self.assertIn("Retry-After", api_docs)
        self.assertIn("completed_with_errors", api_docs)
        self.assertIn("--summary", reconcile)
        self.assertIn("reconcile_runs", operations)
        self.assertIn("reconcile_results", operations)
        self.assertIn("https://github.com/brainx/olymp", readme)
        self.assertIn(
            "ExecStart=/opt/zeus/.venv/bin/zeus bot reconcile",
            systemd_service,
        )
        self.assertNotIn("--summary", systemd_service)

    def test_cli_api_docs_and_openapi_lifecycle_parity(self) -> None:
        cli = Path("zeus/cli.py").read_text(encoding="utf-8")
        api_docs = Path("docs/API.md").read_text(encoding="utf-8")
        openapi = json.loads(Path("docs/openapi.json").read_text(encoding="utf-8"))
        lifecycle = [
            "start",
            "stop",
            "restart",
            "status",
            "logs",
            "history",
            "inspect",
            "reconcile",
        ]

        for action in lifecycle:
            with self.subTest(action=action):
                self.assertIn(f'"{action}"', cli)

        required_paths = [
            "/bots/{bot_id}/status",
            "/bots/{bot_id}/logs",
            "/bots/{bot_id}/history",
            "/bots/{bot_id}/inspect",
            "/bots/{bot_id}/start",
            "/bots/{bot_id}/stop",
            "/bots/{bot_id}/restart",
            "/bots/{bot_id}/reconcile",
            "/bots/reconcile",
        ]
        for path in required_paths:
            with self.subTest(path=path):
                self.assertIn(path, openapi["paths"])
                self.assertIn(path.replace("{bot_id}", "<bot-id>"), api_docs)

    def test_brainx_maintainer_is_credited(self) -> None:
        readme = Path("README.md").read_text(encoding="utf-8")
        credits = Path("CREDITS.md").read_text(encoding="utf-8")
        architecture = Path("docs/ARCHITECTURE.md").read_text(encoding="utf-8")
        pyproject = Path("pyproject.toml").read_text(encoding="utf-8")

        self.assertIn("[Credits](CREDITS.md)", readme)
        opener = (
            "Zeus is an orchestration layer for running many Hermes Agent bots "
            "from reusable templates."
        )
        self.assertIn(opener, readme)
        self.assertNotIn(
            "[BrainX](https://github.com/brainx)-maintained orchestration layer", readme
        )
        self.assertIn("Zeus is maintained by [BrainX](https://github.com/brainx).", readme)
        self.assertIn("https://github.com/brainx", readme)
        self.assertIn("https://github.com/brainx", credits)
        self.assertIn("https://github.com/brainx", architecture)
        self.assertIn('Maintainer = "https://github.com/brainx"', pyproject)

    def test_sqlite_durability_policy_is_consistent_across_runtime_and_docs(self) -> None:
        env_example = Path(".env.example").read_text(encoding="utf-8")
        api_service = Path("systemd/zeus-api.service").read_text(encoding="utf-8")
        reconcile_service = Path("systemd/zeus-reconcile.service").read_text(encoding="utf-8")
        timer = Path("systemd/zeus-reconcile.timer").read_text(encoding="utf-8")
        systemd_docs = Path("docs/SYSTEMD.md").read_text(encoding="utf-8")
        compatibility = Path("docs/COMPATIBILITY.md").read_text(encoding="utf-8").lower()
        architecture = Path("docs/ARCHITECTURE.md").read_text(encoding="utf-8").lower()
        operations = Path("docs/OPERATIONS.md").read_text(encoding="utf-8").lower()

        self.assertEqual(1, env_example.count("ZEUS_SQLITE_SYNCHRONOUS=NORMAL"))
        self.assertNotIn("ZEUS_SQLITE_SYNCHRONOUS=FULL", env_example)
        for service in (api_service, reconcile_service):
            with self.subTest(service=service[:32]):
                self.assertEqual(
                    1,
                    service.count("Environment=ZEUS_SQLITE_SYNCHRONOUS=FULL"),
                )
                self.assertIn("EnvironmentFile=/etc/zeus/zeus.env", service)
        self.assertNotIn("ZEUS_SQLITE_SYNCHRONOUS", timer)
        self.assertIn("ZEUS_SQLITE_SYNCHRONOUS=FULL", systemd_docs)
        self.assertIn("normal", compatibility)
        self.assertIn("unset", compatibility)
        self.assertIn("empty", compatibility)
        self.assertIn("schema v6", compatibility)
        for text in (architecture, operations):
            self.assertIn("process crash", text)
            self.assertIn("power loss", text)
        self.assertIn("every process that writes the same database", operations)
        self.assertIn("sqlite only", operations)
        self.assertIn("rendered profile files", operations)
        self.assertIn("audit jsonl", operations)
        self.assertIn("backup", operations)

    def test_root_scripts_credit_repo_maintainers(self) -> None:
        script_paths = [Path("Makefile"), *sorted(Path("scripts").glob("*.sh"))]

        for path in script_paths:
            with self.subTest(path=str(path)):
                text = path.read_text(encoding="utf-8")
                self.assertIn("Zeus Hermes Orchestrator", text)
                self.assertIn("BrainX", text)
                self.assertIn("https://github.com/brainx", text)


if __name__ == "__main__":
    unittest.main()
