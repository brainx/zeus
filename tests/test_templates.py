from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from zeus.models import BotCreateRequest, HermesTemplate, TemplateError
from zeus.renderer import ProfileRenderer
from zeus.templates import TemplateStore


class TemplateTests(unittest.TestCase):
    def test_builtin_templates_include_async_delegation_caps(self) -> None:
        templates = TemplateStore().list()
        self.assertGreaterEqual(len(templates), 7)
        for template in templates:
            self.assertGreaterEqual(template.hermes.delegation.max_async_children, 1)
            self.assertLessEqual(template.hermes.delegation.max_async_children, 32)

    def test_builtin_templates_have_metadata_and_required_env_placeholders(self) -> None:
        templates = TemplateStore().list()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for template in templates:
                with self.subTest(template=template.id):
                    self.assertTrue(template.hermes.required_env)
                    for name in template.hermes.required_env:
                        self.assertRegex(name, r"^[A-Z][A-Z0-9_]{1,127}$")
                    self.assertTrue(template.metadata.get("use_case"))
                    self.assertIn(template.metadata.get("risk_level"), {"low", "medium", "high"})
                    self.assertEqual("manual", template.metadata.get("recommended_restart_policy"))

                    env = {name: f"${{{name}}}" for name in template.hermes.required_env}
                    ProfileRenderer(root / template.id).render(
                        BotCreateRequest(
                            bot_id=template.id,
                            template_id=template.id,
                            env=env,
                        ),
                        template,
                    )
                    env_text = (root / template.id / "profiles" / template.id / ".env").read_text(
                        encoding="utf-8"
                    )
                    for name in template.hermes.required_env:
                        self.assertIn(f'{name}="${{{name}}}"', env_text)

    def test_rejects_inline_secret_like_value(self) -> None:
        with self.assertRaises(TemplateError):
            HermesTemplate.from_dict(
                {
                    "id": "secret-bot",
                    "name": "Secret Bot",
                    "description": "Invalid secret",
                    "version": "0.1.0",
                    "hermes": {
                        "model": {"provider": "openrouter", "default": "x/y"},
                        "extra": {"OPENROUTER_API_KEY": "plain-secret-value"},
                    },
                    "soul": "valid soul",
                }
            )

    def test_rejects_lowercase_inline_secret_like_value(self) -> None:
        with self.assertRaises(TemplateError):
            HermesTemplate.from_dict(
                {
                    "id": "secret-bot",
                    "name": "Secret Bot",
                    "description": "Invalid secret",
                    "version": "0.1.0",
                    "hermes": {
                        "model": {
                            "provider": "openrouter",
                            "default": "x/y",
                            "api_key": "plain-secret-value",
                        },
                    },
                    "soul": "valid soul",
                }
            )

    def test_template_store_falls_back_to_packaged_templates_when_local_root_is_missing(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "does-not-exist"
            templates = TemplateStore(missing).list()

        ids = {template.id for template in templates}
        self.assertIn("coding-bot", ids)
        self.assertIn("deepseek-coding-bot", ids)

    def test_local_template_does_not_hide_bundled_templates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "custom-bot.toml").write_text(
                """
id = "custom-bot"
name = "Custom Bot"
description = "Local custom bot"
version = "0.1.0"
soul = "valid soul"
[hermes.model]
provider = "openrouter"
default = "x/y"
""",
                encoding="utf-8",
            )

            templates = TemplateStore(root).list()

        ids = {template.id for template in templates}
        self.assertIn("coding-bot", ids)
        self.assertIn("custom-bot", ids)

    def test_rejects_unbounded_async_delegation_capacity(self) -> None:
        with self.assertRaises(TemplateError):
            HermesTemplate.from_dict(
                {
                    "id": "runaway-bot",
                    "name": "Runaway Bot",
                    "description": "Invalid async capacity",
                    "version": "0.1.0",
                    "hermes": {
                        "model": {"provider": "openrouter", "default": "x/y"},
                        "delegation": {"max_async_children": 1000},
                    },
                    "soul": "valid soul",
                }
            )

    def test_rejects_duplicate_template_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = """
id = "coding-bot"
name = "Coding Bot"
description = "Repository maintenance bot"
version = "0.1.0"
soul = "valid soul"
[hermes.model]
provider = "openrouter"
default = "x/y"
"""
            (root / "a.toml").write_text(body, encoding="utf-8")
            (root / "b.toml").write_text(body, encoding="utf-8")
            with self.assertRaises(ValueError):
                TemplateStore(root).list()


if __name__ == "__main__":
    unittest.main()
