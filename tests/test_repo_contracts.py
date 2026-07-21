from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from zeus.state import SCHEMA_VERSION


class RepoContractTests(unittest.TestCase):
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
            "docs/openapi.json",
            "docs/ROADMAP.md",
            "docs/assets/demo.cast",
            "docs/assets/zeus-hero.png",
            ".coveragerc",
            ".github/workflows/release.yml",
            ".github/ISSUE_TEMPLATE/bug_report.yml",
            ".github/ISSUE_TEMPLATE/feature_request.yml",
            ".github/ISSUE_TEMPLATE/config.yml",
            ".github/pull_request_template.md",
            "systemd/zeus-api.service",
            "systemd/zeus-reconcile.service",
            "systemd/zeus-reconcile.timer",
            "scripts/repo_check.sh",
            "scripts/wheel_smoke.sh",
            "scripts/fresh_vps_verify.sh",
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

        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("3.11", workflow)
        self.assertIn("3.12", workflow)
        self.assertIn("3.13", workflow)
        self.assertIn('pip install -e ".[dev]"', workflow)
        self.assertIn("ruff format --check .", workflow)
        self.assertIn("ruff check .", workflow)
        self.assertIn("mypy zeus", workflow)
        self.assertIn("bandit -r zeus", workflow)
        self.assertIn("shellcheck scripts/*.sh", workflow)
        self.assertIn("sh scripts/test.sh", workflow)
        self.assertIn("coverage erase", workflow)
        self.assertIn("coverage run -m unittest discover -s tests", workflow)
        self.assertIn("coverage report", workflow)
        self.assertNotIn("coverage report --fail-under", workflow)
        self.assertIn("python -m build", workflow)
        self.assertIn("twine check dist/*", workflow)
        self.assertIn("sh scripts/wheel_smoke.sh", workflow)

    def test_test_script_runs_compile_unittest_and_doctor(self) -> None:
        script = Path("scripts/test.sh").read_text(encoding="utf-8")

        self.assertIn("compileall zeus tests", script)
        self.assertIn("unittest discover -s tests -v", script)
        self.assertIn("trap cleanup EXIT INT TERM", script)
        self.assertIn('mkdir -p "$tmp_dir"', script)
        self.assertIn("zeus.cli doctor --json", script)

    def test_wheel_smoke_exercises_installed_demo_entrypoint(self) -> None:
        script = Path("scripts/wheel_smoke.sh").read_text(encoding="utf-8")

        self.assertIn('"$venv_zeus" demo up --json', script)
        self.assertIn('"$venv_zeus" demo status --json', script)
        self.assertIn('"$venv_zeus" demo down --json', script)
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
        self.assertIn("fail_under = 70", config)
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
        compatibility_statement = re.search(
            r"Databases newer than\s+schema v(?P<version>\d+) are rejected rather than downgraded\.",
            architecture,
        )

        self.assertIsNotNone(compatibility_statement)
        self.assertEqual(str(SCHEMA_VERSION), compatibility_statement["version"])

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
        self.assertIn("actions/attest-build-provenance@", workflow)
        self.assertIn("dist/*.tar.gz", workflow)
        self.assertIn("dist/*.whl", workflow)
        self.assertIn("dist/SHA256SUMS.txt", workflow)
        self.assertIn("actions/upload-artifact@", workflow)
        self.assertIn("actions/download-artifact@", workflow)
        self.assertIn("cd dist && sha256sum -c SHA256SUMS.txt", workflow)
        self.assertIn("annotated version tags", release_docs)
        self.assertIn("does not cryptographically verify signer identity", release_docs)
        self.assertIn("gh attestation verify", release_docs)
        self.assertIn('build_artifacts="${ZEUS_WHEEL_SMOKE_BUILD:-1}"', wheel_smoke)
        self.assertIn('fail "ZEUS_WHEEL_SMOKE_BUILD must be 0 or 1"', wheel_smoke)
        self.assertIn('fail "expected exactly one wheel in dist/"', wheel_smoke)

    def test_makefile_has_release_check_target(self) -> None:
        makefile = Path("Makefile").read_text(encoding="utf-8")

        self.assertIn("release-check:", makefile)
        self.assertIn("coverage:", makefile)
        self.assertIn("wheel-smoke:", makefile)
        self.assertIn("coverage erase", makefile)
        self.assertIn("coverage run -m unittest discover -s tests", makefile)
        self.assertIn("coverage report", makefile)
        self.assertNotIn("coverage report --fail-under", makefile)
        self.assertIn("shellcheck scripts/*.sh", makefile)
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
