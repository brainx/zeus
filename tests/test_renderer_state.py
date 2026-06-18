from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from zeus.models import BotCreateRequest, BotStatus
from zeus.renderer import ProfileRenderer
from zeus.state import StateStore
from zeus.templates import TemplateStore


class RendererStateTests(unittest.TestCase):
    def test_renderer_creates_async_aware_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            template = TemplateStore().get("coding-bot")
            record = ProfileRenderer(root / ".zeus" / "hermes").render(
                BotCreateRequest(
                    bot_id="coder",
                    template_id="coding-bot",
                    env={"OPENROUTER_API_KEY": "${OPENROUTER_API_KEY}"},
                ),
                template,
            )
            profile = root / ".zeus" / "hermes" / "profiles" / "coder"
            self.assertTrue((profile / "SOUL.md").exists())
            self.assertTrue((profile / "mcp.json").exists())
            self.assertTrue((profile / "cron" / "jobs.json").exists())
            self.assertIn("max_async_children: 3", (profile / "config.yaml").read_text())
            self.assertEqual(
                "OPENROUTER_API_KEY=${OPENROUTER_API_KEY}\n",
                (profile / ".env").read_text(encoding="utf-8"),
            )
            self.assertTrue(record.profile_path.endswith(".zeus/hermes/profiles/coder"))

    def test_state_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            template = TemplateStore().get("coding-bot")
            record = ProfileRenderer(root / ".zeus" / "hermes").render(
                BotCreateRequest(bot_id="coder", template_id="coding-bot"),
                template,
            )
            store.upsert_bot(record)
            store.update_status("coder", BotStatus.running, pid=1234)

            loaded = store.get_bot("coder")
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(BotStatus.running, loaded.status)
            self.assertEqual(1234, loaded.pid)

    def test_renderer_uses_native_deepseek_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            template = TemplateStore().get("deepseek-coding-bot")
            ProfileRenderer(root / ".zeus" / "hermes").render(
                BotCreateRequest(
                    bot_id="deepseek-coder",
                    template_id="deepseek-coding-bot",
                    env={"DEEPSEEK_API_KEY": "${DEEPSEEK_API_KEY}"},
                ),
                template,
            )
            profile = root / ".zeus" / "hermes" / "profiles" / "deepseek-coder"
            config = (profile / "config.yaml").read_text(encoding="utf-8")
            self.assertIn('provider: "deepseek"', config)
            self.assertIn('default: "deepseek-v4-pro"', config)
            self.assertNotIn("base_url:", config)
            self.assertNotIn("api_mode:", config)
            self.assertEqual(
                "DEEPSEEK_API_KEY=${DEEPSEEK_API_KEY}\n",
                (profile / ".env").read_text(encoding="utf-8"),
            )

    def test_renderer_rejects_newline_env_injection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            template = TemplateStore().get("coding-bot")

            with self.assertRaisesRegex(ValueError, "control"):
                ProfileRenderer(root / ".zeus" / "hermes").render(
                    BotCreateRequest(
                        bot_id="coder",
                        template_id="coding-bot",
                        env={"OPENROUTER_API_KEY": "good\nEVIL=value"},
                    ),
                    template,
                )

            env_path = root / ".zeus" / "hermes" / "profiles" / "coder" / ".env"
            self.assertFalse(env_path.exists())


if __name__ == "__main__":
    unittest.main()
