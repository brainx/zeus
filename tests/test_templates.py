from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from zeus.models import HermesTemplate, TemplateError
from zeus.templates import TemplateStore


class TemplateTests(unittest.TestCase):
    def test_builtin_templates_include_async_delegation_caps(self) -> None:
        templates = TemplateStore().list()
        self.assertGreaterEqual(len(templates), 3)
        for template in templates:
            self.assertGreaterEqual(template.hermes.delegation.max_async_children, 1)
            self.assertLessEqual(template.hermes.delegation.max_async_children, 32)

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
