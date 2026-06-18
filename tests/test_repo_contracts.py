from __future__ import annotations

import unittest
from pathlib import Path


class RepoContractTests(unittest.TestCase):
    def test_publishable_repository_files_exist(self) -> None:
        required = [
            "README.md",
            "LICENSE",
            "CREDITS.md",
            "CONTRIBUTING.md",
            "SECURITY.md",
            "CHANGELOG.md",
            "docs/ARCHITECTURE.md",
            "docs/API.md",
            "docs/TEMPLATE_AUTHORING.md",
            "docs/REAL_HERMES_VERIFICATION.md",
            "docs/FRESH_VPS_TEST.md",
            "docs/SYSTEMD.md",
            "docs/OPERATIONS.md",
            "docs/REPO_GENERATION.md",
            "docs/ROADMAP.md",
            "docs/assets/demo.cast",
            "docs/assets/zeus-hero.png",
            "systemd/zeus-api.service",
            "scripts/repo_check.sh",
            "scripts/fresh_vps_verify.sh",
            "templates/deepseek-coding-bot.toml",
        ]

        for path in required:
            with self.subTest(path=path):
                self.assertTrue(Path(path).is_file())

    def test_ci_runs_project_test_script_on_supported_python_versions(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")

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
        self.assertIn("python -m build", workflow)
        self.assertIn("twine check dist/*", workflow)

    def test_test_script_runs_compile_unittest_and_doctor(self) -> None:
        script = Path("scripts/test.sh").read_text(encoding="utf-8")

        self.assertIn("compileall zeus tests", script)
        self.assertIn("unittest discover -s tests -v", script)
        self.assertIn("trap cleanup EXIT INT TERM", script)
        self.assertIn('mkdir -p "$tmp_dir"', script)
        self.assertIn("zeus.cli doctor --json", script)

    def test_repo_check_script_verifies_required_handoff_artifacts(self) -> None:
        script = Path("scripts/repo_check.sh").read_text(encoding="utf-8")

        self.assertIn('tmp_dir=".tmp/repo-check"', script)
        self.assertIn("trap cleanup EXIT INT TERM", script)
        self.assertIn('ZEUS_STATE_DIR="$tmp_dir/state"', script)
        self.assertIn("LICENSE", script)
        self.assertIn("SECURITY.md", script)
        self.assertIn("docs/ARCHITECTURE.md", script)
        self.assertIn("docs/TEMPLATE_AUTHORING.md", script)
        self.assertIn("docs/FRESH_VPS_TEST.md", script)
        self.assertIn("docs/SYSTEMD.md", script)
        self.assertIn("docs/OPERATIONS.md", script)
        self.assertIn("docs/REPO_GENERATION.md", script)
        self.assertIn("systemd/zeus-api.service", script)
        self.assertIn("scripts/fresh_vps_verify.sh", script)
        self.assertIn("templates/deepseek-coding-bot.toml", script)
        self.assertIn("Repository readiness check passed.", script)

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
        self.assertIn("docs/ROADMAP.md", readme)
        self.assertIn("actions/workflows/ci.yml/badge.svg", readme)
        self.assertIn("Package Build", readme)
        self.assertIn("Security Policy", readme)
        self.assertIn("```mermaid", readme)

    def test_env_example_lists_deepseek_and_api_auth(self) -> None:
        env = Path(".env.example").read_text(encoding="utf-8")
        api_docs = Path("docs/API.md").read_text(encoding="utf-8")

        self.assertIn("ZEUS_API_KEY=", env)
        self.assertIn("ZEUS_ALLOW_UNAUTH_READS=0", env)
        self.assertIn("DEEPSEEK_API_KEY=", env)
        self.assertIn("All non-health endpoints require", api_docs)
        self.assertIn("POST /bots/<bot-id>/restart", api_docs)

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
        self.assertIn("[project.optional-dependencies]", pyproject)
        self.assertIn("ruff>=0.6.0", pyproject)
        self.assertIn("mypy>=1.11.0", pyproject)
        self.assertIn("bandit>=1.7.9", pyproject)
        self.assertIn("[tool.ruff]", pyproject)
        self.assertIn("[tool.mypy]", pyproject)
        self.assertIn("[tool.bandit]", pyproject)

    def test_cli_exposes_restart_lifecycle_command(self) -> None:
        cli = Path("zeus/cli.py").read_text(encoding="utf-8")
        supervisor = Path("zeus/supervisor.py").read_text(encoding="utf-8")
        api = Path("zeus/api.py").read_text(encoding="utf-8")
        readme = Path("README.md").read_text(encoding="utf-8")

        self.assertIn('"restart"', cli)
        self.assertIn("def restart", supervisor)
        self.assertIn(".restart(bot_id)", api)
        self.assertIn("zeus bot restart coder", readme)

    def test_systemd_and_operations_docs_are_actionable(self) -> None:
        service = Path("systemd/zeus-api.service").read_text(encoding="utf-8")
        systemd_docs = Path("docs/SYSTEMD.md").read_text(encoding="utf-8")
        operations = Path("docs/OPERATIONS.md").read_text(encoding="utf-8")

        self.assertIn("EnvironmentFile=/etc/zeus/zeus.env", service)
        self.assertIn("ExecStart=/opt/zeus/.venv/bin/python -m zeus.api", service)
        self.assertIn("Restart=on-failure", service)
        self.assertIn("ProtectSystem=strict", service)
        self.assertIn("ReadWritePaths=/var/lib/zeus", service)
        self.assertIn("ZEUS_API_KEY=replace-with-a-long-random-value", systemd_docs)
        self.assertIn("sudo systemctl enable --now zeus-api", systemd_docs)
        self.assertIn("Backup", operations)
        self.assertIn("Logs", operations)
        self.assertIn("Upgrade", operations)
        self.assertIn("Restart Policy", operations)

    def test_brainx_maintainer_is_credited(self) -> None:
        readme = Path("README.md").read_text(encoding="utf-8")
        credits = Path("CREDITS.md").read_text(encoding="utf-8")
        architecture = Path("docs/ARCHITECTURE.md").read_text(encoding="utf-8")
        pyproject = Path("pyproject.toml").read_text(encoding="utf-8")

        self.assertIn("[Credits](CREDITS.md)", readme)
        opener = (
            "Zeus is a orchestration layer for running many Hermes Agent bots "
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
