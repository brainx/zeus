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
            "docs/REPO_GENERATION.md",
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
        self.assertIn("sh scripts/test.sh", workflow)

    def test_test_script_runs_compile_unittest_and_doctor(self) -> None:
        script = Path("scripts/test.sh").read_text(encoding="utf-8")

        self.assertIn("compileall zeus tests", script)
        self.assertIn("unittest discover -s tests -v", script)
        self.assertIn("trap cleanup EXIT INT TERM", script)
        self.assertIn("mkdir -p \"$tmp_dir\"", script)
        self.assertIn("zeus.cli doctor --json", script)

    def test_repo_check_script_verifies_required_handoff_artifacts(self) -> None:
        script = Path("scripts/repo_check.sh").read_text(encoding="utf-8")

        self.assertIn("tmp_dir=\".tmp/repo-check\"", script)
        self.assertIn("trap cleanup EXIT INT TERM", script)
        self.assertIn("ZEUS_STATE_DIR=\"$tmp_dir/state\"", script)
        self.assertIn("LICENSE", script)
        self.assertIn("SECURITY.md", script)
        self.assertIn("docs/ARCHITECTURE.md", script)
        self.assertIn("docs/TEMPLATE_AUTHORING.md", script)
        self.assertIn("docs/FRESH_VPS_TEST.md", script)
        self.assertIn("docs/REPO_GENERATION.md", script)
        self.assertIn("scripts/fresh_vps_verify.sh", script)
        self.assertIn("templates/deepseek-coding-bot.toml", script)
        self.assertIn("Repository readiness check passed.", script)

    def test_readme_has_informative_github_landing_sections(self) -> None:
        readme = Path("README.md").read_text(encoding="utf-8")

        self.assertIn("Many Hermes bots, one local supervisor.", readme)
        self.assertIn("## Why Zeus", readme)
        self.assertIn("## How It Works", readme)
        self.assertIn("## Quick Start", readme)
        self.assertIn("```mermaid", readme)

    def test_env_example_lists_deepseek_and_api_auth(self) -> None:
        env = Path(".env.example").read_text(encoding="utf-8")
        api_docs = Path("docs/API.md").read_text(encoding="utf-8")

        self.assertIn("ZEUS_API_KEY=", env)
        self.assertIn("DEEPSEEK_API_KEY=", env)
        self.assertIn("Mutating endpoints always require", api_docs)

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
        self.assertIn("license = \"MIT\"", pyproject)
        self.assertIn("zeus = \"zeus.cli:main\"", pyproject)

    def test_brainx_maintainer_is_credited(self) -> None:
        readme = Path("README.md").read_text(encoding="utf-8")
        credits = Path("CREDITS.md").read_text(encoding="utf-8")
        architecture = Path("docs/ARCHITECTURE.md").read_text(encoding="utf-8")
        pyproject = Path("pyproject.toml").read_text(encoding="utf-8")

        self.assertIn("[Credits](CREDITS.md)", readme)
        self.assertIn("Zeus is an orchestration layer", readme)
        self.assertNotIn("[BrainX](https://github.com/brainx)-maintained orchestration layer", readme)
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
