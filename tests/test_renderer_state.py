from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from zeus.hermes_adapter import HermesAdapter
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
                'OPENROUTER_API_KEY="${OPENROUTER_API_KEY}"\n',
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

    def test_state_initializes_schema_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")

            store.init()

            with closing(sqlite3.connect(root / "zeus.db")) as conn:
                version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
            self.assertEqual(1, version)

    def test_state_migrates_existing_database_without_schema_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            database = root / "zeus.db"
            with closing(sqlite3.connect(database)) as conn:
                conn.execute(
                    """
                    CREATE TABLE bots (
                        bot_id TEXT PRIMARY KEY,
                        template_id TEXT NOT NULL,
                        display_name TEXT NOT NULL,
                        profile_path TEXT NOT NULL,
                        status TEXT NOT NULL,
                        pid INTEGER,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                conn.commit()

            store = StateStore(database)
            store.init()

            with closing(sqlite3.connect(database)) as conn:
                columns = {row[1] for row in conn.execute("PRAGMA table_info(bots)").fetchall()}
                version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
            self.assertEqual(1, version)
            self.assertIn("restart_policy", columns)
            self.assertIn("next_restart_at", columns)

    def test_state_init_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")

            store.init()
            store.init()

            with closing(sqlite3.connect(root / "zeus.db")) as conn:
                count = conn.execute("SELECT COUNT(*) FROM schema_version").fetchone()[0]
                version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
            self.assertEqual(1, count)
            self.assertEqual(1, version)

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
                'DEEPSEEK_API_KEY="${DEEPSEEK_API_KEY}"\n',
                (profile / ".env").read_text(encoding="utf-8"),
            )

    def test_renderer_quotes_env_values_without_line_injection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_root = root / ".zeus" / "hermes"
            template = TemplateStore().get("coding-bot")
            value = "good\nEVIL=value # still value"

            ProfileRenderer(hermes_root).render(
                BotCreateRequest(
                    bot_id="coder",
                    template_id="coding-bot",
                    env={"OPENROUTER_API_KEY": value},
                ),
                template,
            )

            env_path = hermes_root / "profiles" / "coder" / ".env"
            env_text = env_path.read_text(encoding="utf-8")
            self.assertEqual(1, len(env_text.splitlines()))
            self.assertNotIn("\nEVIL=", env_text)

            _, env = HermesAdapter("hermes", hermes_root).command("coder", "gateway", "run")
            self.assertEqual(value, env["OPENROUTER_API_KEY"])


if __name__ == "__main__":
    unittest.main()
