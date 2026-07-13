from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from zeus.hermes_adapter import HermesAdapter
from zeus.lifecycle import LifecycleEventInput
from zeus.models import BotCreateRequest, BotRecord, BotStatus, HermesTemplate, TemplateError
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

    def test_state_connect_configures_wal_and_busy_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()

            with closing(store.connect()) as conn:
                journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
                busy_timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]

            self.assertEqual("wal", str(journal_mode).lower())
            self.assertEqual(5000, busy_timeout)

    def test_state_handles_concurrent_operations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()

            def worker(index: int) -> None:
                bot_id = f"bot-{index}"
                record = BotRecord(
                    bot_id=bot_id,
                    template_id="coding-bot",
                    display_name=f"Bot {index}",
                    profile_path=str(root / "profiles" / bot_id),
                )
                for step in range(25):
                    store.upsert_bot(record)
                    running = step % 2 == 0
                    store.update_status(
                        bot_id,
                        BotStatus.running if running else BotStatus.stopped,
                        pid=index if running else None,
                    )
                    self.assertIsNotNone(store.get_bot(bot_id))
                    store.list_bots()

            with ThreadPoolExecutor(max_workers=8) as executor:
                list(executor.map(worker, range(8)))

            self.assertEqual(8, len(store.list_bots()))

    def test_state_initializes_schema_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")

            store.init()

            with closing(sqlite3.connect(root / "zeus.db")) as conn:
                version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
            self.assertEqual(6, version)

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
            self.assertEqual(6, version)
            self.assertIn("restart_policy", columns)
            self.assertIn("next_restart_at", columns)
            self.assertIn("started_at", columns)
            self.assertIn("last_transition_reason", columns)
            self.assertIn("last_event_id", columns)

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
            self.assertEqual(6, version)

    def test_state_v3_to_v6_migration_is_exact_additive_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "zeus.db"
            store = StateStore(database)
            store.init()
            store.upsert_bot_with_event(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(Path(tmp) / "profiles" / "coder"),
                ),
                event=LifecycleEventInput(
                    bot_id="coder",
                    operation_id="a" * 32,
                    source="cli",
                    action="bot.create",
                    outcome="success",
                ),
            )
            with closing(sqlite3.connect(database)) as conn:
                conn.execute("DROP TABLE reconcile_results")
                conn.execute("DROP TABLE reconcile_runs")
                conn.execute("DROP TABLE idempotency_records")
                conn.execute("DROP TRIGGER bots_desired_intent_reject_partial_insert")
                conn.execute("DROP TRIGGER bots_desired_intent_reject_partial_update")
                conn.execute("UPDATE schema_version SET version = 3")
                conn.commit()

            store.migrate()
            store.migrate()

            with closing(sqlite3.connect(database)) as conn:
                version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
                columns = conn.execute("PRAGMA table_info(idempotency_records)").fetchall()
                indexes = conn.execute("PRAGMA index_list(idempotency_records)").fetchall()
                table_sql = conn.execute(
                    "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
                    ("idempotency_records",),
                ).fetchone()[0]

            self.assertEqual(6, version)
            self.assertEqual(
                [
                    ("key_hash", "TEXT", 0, 1),
                    ("request_hash", "TEXT", 1, 0),
                    ("state", "TEXT", 1, 0),
                    ("owner_instance_id", "TEXT", 1, 0),
                    ("response_status", "INTEGER", 0, 0),
                    ("response_json", "TEXT", 0, 0),
                    ("created_at", "TEXT", 1, 0),
                    ("updated_at", "TEXT", 1, 0),
                    ("expires_at", "TEXT", 1, 0),
                ],
                [(row[1], row[2], row[3], row[5]) for row in columns],
            )
            self.assertIn("CHECK (state IN ('in_progress', 'completed'))", table_sql)
            self.assertIn(
                "idx_idempotency_records_expires",
                {row[1] for row in indexes},
            )
            self.assertIsNotNone(store.get_bot("coder"))
            self.assertEqual(2, len(store.list_lifecycle_events("coder", 10, None)))

    def test_state_v3_to_v4_failure_rolls_back_version_and_ddl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "zeus.db"
            store = StateStore(database)
            store.init()
            with closing(sqlite3.connect(database)) as conn:
                conn.execute("DROP TABLE idempotency_records")
                conn.execute("UPDATE schema_version SET version = 3")
                conn.execute("CREATE VIEW idempotency_records AS SELECT 1 AS value")
                conn.commit()

            with self.assertRaises(sqlite3.DatabaseError):
                store.migrate()

            with closing(sqlite3.connect(database)) as conn:
                version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
                object_type = conn.execute(
                    "SELECT type FROM sqlite_master WHERE name = 'idempotency_records'"
                ).fetchone()[0]
            self.assertEqual(3, version)
            self.assertEqual("view", object_type)

    def test_state_rejects_v7_without_mutating_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "zeus.db"
            store = StateStore(database)
            store.init()
            with closing(sqlite3.connect(database)) as conn:
                conn.execute("UPDATE schema_version SET version = 7")
                conn.commit()
                before = list(conn.iterdump())

            with self.assertRaisesRegex(RuntimeError, "newer than supported"):
                store.migrate()

            with closing(sqlite3.connect(database)) as conn:
                self.assertEqual(before, list(conn.iterdump()))

    def test_fresh_v6_reconciliation_schema_matches_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "zeus.db"
            store = StateStore(database)

            store.init()

            with closing(store.connect()) as conn:
                version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
                run_columns = conn.execute("PRAGMA table_info(reconcile_runs)").fetchall()
                result_columns = conn.execute("PRAGMA table_info(reconcile_results)").fetchall()
                foreign_keys = conn.execute("PRAGMA foreign_key_list(reconcile_results)").fetchall()
                run_sql = conn.execute(
                    "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'reconcile_runs'"
                ).fetchone()[0]
                result_sql = conn.execute(
                    """
                    SELECT sql FROM sqlite_master
                    WHERE type = 'table' AND name = 'reconcile_results'
                    """
                ).fetchone()[0]
                foreign_keys_enabled = conn.execute("PRAGMA foreign_keys").fetchone()[0]

            self.assertEqual(6, version)
            self.assertEqual(
                [
                    "run_id",
                    "scope",
                    "requested_bot_id",
                    "source",
                    "force",
                    "reset_restart",
                    "started_at",
                    "finished_at",
                    "outcome",
                    "total",
                    "healthy_count",
                    "changed_count",
                    "pending_count",
                    "action_required_count",
                    "error_count",
                    "skipped_count",
                ],
                [row[1] for row in run_columns],
            )
            self.assertEqual(
                [
                    "run_id",
                    "bot_id",
                    "ordinal",
                    "outcome",
                    "desired_state",
                    "observed_status",
                    "pid",
                    "action",
                    "message",
                    "error_code",
                    "event_id",
                    "started_at",
                    "finished_at",
                ],
                [row[1] for row in result_columns],
            )
            self.assertEqual(
                [("reconcile_runs", "run_id", "run_id")],
                [(row[2], row[3], row[4]) for row in foreign_keys],
            )
            self.assertNotIn("lifecycle_events", {row[2] for row in foreign_keys})
            self.assertIn("total =", run_sql)
            self.assertIn("length(message) <= 2048", result_sql)
            self.assertEqual(1, foreign_keys_enabled)

    def test_v5_to_v6_reconciliation_migration_is_additive_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "zeus.db"
            store = StateStore(database)
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(Path(tmp) / "profiles" / "coder"),
                )
            )
            with closing(sqlite3.connect(database)) as conn:
                conn.execute("DROP TABLE reconcile_results")
                conn.execute("DROP TABLE reconcile_runs")
                conn.execute("UPDATE schema_version SET version = 5")
                conn.commit()

            store.migrate()
            store.migrate()

            with closing(sqlite3.connect(database)) as conn:
                version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
                tables = {
                    row[0]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                }
            self.assertEqual(6, version)
            self.assertIn("reconcile_runs", tables)
            self.assertIn("reconcile_results", tables)
            self.assertIsNotNone(store.get_bot("coder"))

    def test_v6_reconciliation_constraints_reject_invalid_or_orphaned_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "zeus.db")
            store.init()
            with closing(store.connect()) as conn:
                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute(
                        """
                        INSERT INTO reconcile_runs (
                            run_id, scope, source, force, reset_restart, started_at, outcome
                        ) VALUES ('bad-scope', 'all', 'cli', 0, 0, ?, 'running')
                        """,
                        (datetime.fromisoformat("2026-07-12T12:00:00+00:00").isoformat(),),
                    )
                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute(
                        """
                        INSERT INTO reconcile_results (
                            run_id, bot_id, ordinal, outcome, action, message,
                            started_at, finished_at
                        ) VALUES ('missing-run', 'coder', 0, 'healthy', 'none', '', ?, ?)
                        """,
                        (
                            datetime.fromisoformat("2026-07-12T12:00:00+00:00").isoformat(),
                            datetime.fromisoformat("2026-07-12T12:00:01+00:00").isoformat(),
                        ),
                    )

    def test_v5_to_v6_failure_rolls_back_version_and_all_ddl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "zeus.db"
            store = StateStore(database)
            store.init()
            with closing(sqlite3.connect(database)) as conn:
                conn.execute("DROP TABLE reconcile_results")
                conn.execute("DROP TABLE reconcile_runs")
                conn.execute("UPDATE schema_version SET version = 5")
                conn.execute("CREATE VIEW reconcile_results AS SELECT 1 AS value")
                conn.commit()

            with self.assertRaises(sqlite3.DatabaseError):
                store.migrate()

            with closing(sqlite3.connect(database)) as conn:
                version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
                run_object = conn.execute(
                    "SELECT type FROM sqlite_master WHERE name = 'reconcile_runs'"
                ).fetchone()
                result_object = conn.execute(
                    "SELECT type FROM sqlite_master WHERE name = 'reconcile_results'"
                ).fetchone()[0]
            self.assertEqual(5, version)
            self.assertIsNone(run_object)
            self.assertEqual("view", result_object)

    def test_state_records_lifecycle_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(root / "profiles" / "coder"),
                )
            )
            started_at = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
            ready_at = datetime.fromisoformat("2026-01-01T00:00:01+00:00")

            store.update_lifecycle_state(
                "coder",
                BotStatus.starting,
                pid=1234,
                started_at=started_at,
                last_transition_reason="gateway process started",
                clear_ready_at=True,
            )
            store.update_lifecycle_state(
                "coder",
                BotStatus.running,
                pid=1234,
                ready_at=ready_at,
                last_transition_reason="gateway readiness probe passed",
                reset_restart=True,
            )

            loaded = store.get_bot("coder")
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(BotStatus.running, loaded.status)
            self.assertEqual(started_at, loaded.started_at)
            self.assertEqual(ready_at, loaded.ready_at)
            self.assertEqual("gateway readiness probe passed", loaded.last_transition_reason)

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

    def test_renderer_rejects_unknown_env_keys_before_writing_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_root = root / ".zeus" / "hermes"
            template = TemplateStore().get("coding-bot")

            with self.assertRaisesRegex(
                TemplateError,
                "env contains unknown key\\(s\\) for template coding-bot: CUSTOM_FLAG",
            ):
                ProfileRenderer(hermes_root).render(
                    BotCreateRequest(
                        bot_id="coder",
                        template_id="coding-bot",
                        env={
                            "OPENROUTER_API_KEY": "${OPENROUTER_API_KEY}",
                            "CUSTOM_FLAG": "enabled",
                        },
                    ),
                    template,
                )

            self.assertFalse((hermes_root / "profiles" / "coder").exists())

    def test_create_request_validates_and_normalizes_display_name(self) -> None:
        request = BotCreateRequest(
            bot_id="coder",
            template_id="coding-bot",
            display_name="  Coding Bot  ",
        )
        self.assertEqual("Coding Bot", request.display_name)

        for invalid in ("", "   ", "x" * 121, 123):
            with self.subTest(invalid=invalid), self.assertRaises(TemplateError):
                BotCreateRequest(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name=invalid,  # type: ignore[arg-type]
                )

    def test_create_request_rejects_control_characters_in_display_name(self) -> None:
        for invalid in (
            "line\nbreak",
            "\nleading newline",
            "tab\tname",
            "trailing tab\t",
            "nul\0name",
            "escape\x1bname",
            "delete\x7fname",
            "c1-control\x80name",
            "c1-control\x9fname",
        ):
            with (
                self.subTest(invalid=repr(invalid)),
                self.assertRaisesRegex(TemplateError, "display_name must not contain control"),
            ):
                BotCreateRequest(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name=invalid,
                )

    def test_create_request_rejects_invalid_restart_values(self) -> None:
        for invalid in (float("nan"), float("inf"), float("-inf"), True, "1", None):
            with self.subTest(invalid=invalid), self.assertRaises(TemplateError):
                BotCreateRequest(
                    bot_id="coder",
                    template_id="coding-bot",
                    restart_backoff_seconds=invalid,  # type: ignore[arg-type]
                )

        for invalid in (True, 1.5, "1"):
            with self.subTest(invalid=invalid), self.assertRaises(TemplateError):
                BotCreateRequest(
                    bot_id="coder",
                    template_id="coding-bot",
                    restart_max_attempts=invalid,  # type: ignore[arg-type]
                )

    def test_template_rejects_terminal_parent_traversal(self) -> None:
        for invalid_cwd, expected_error in (
            ("workspace/../outside", "must not traverse parent directories"),
            ("..\\outside", "must not traverse parent directories"),
            ("C:\\outside", "must be relative"),
        ):
            with (
                self.subTest(cwd=invalid_cwd),
                self.assertRaisesRegex(TemplateError, expected_error),
            ):
                HermesTemplate.from_dict(
                    {
                        "id": "unsafe-bot",
                        "name": "Unsafe Bot",
                        "description": "Invalid terminal path",
                        "version": "0.1.0",
                        "hermes": {
                            "model": {"provider": "openrouter", "default": "x/y"},
                            "terminal": {"cwd": invalid_cwd},
                        },
                        "soul": "valid soul",
                    }
                )

    def test_template_rejects_nonempty_root_skills(self) -> None:
        with self.assertRaisesRegex(TemplateError, "profile skill rendering is unsupported"):
            HermesTemplate.from_dict(
                {
                    "id": "skills-bot",
                    "name": "Skills Bot",
                    "description": "Unsupported root skills",
                    "version": "0.1.0",
                    "hermes": {
                        "model": {"provider": "openrouter", "default": "x/y"},
                    },
                    "soul": "valid soul",
                    "skills": {"review": {"instructions": "Review code"}},
                }
            )

    def test_renderer_precomputes_content_before_creating_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hermes_root = Path(tmp) / ".zeus" / "hermes"
            template = replace(
                TemplateStore().get("coding-bot"),
                mcp={"not-json-serializable": {"set-value"}},
            )

            with self.assertRaises(TypeError):
                ProfileRenderer(hermes_root).render(
                    BotCreateRequest(bot_id="coder", template_id="coding-bot"),
                    template,
                )

            self.assertFalse(hermes_root.exists())

    def test_renderer_preflight_validates_and_serializes_without_filesystem_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hermes_root = Path(tmp) / ".zeus" / "hermes"
            renderer = ProfileRenderer(hermes_root)
            request = BotCreateRequest(bot_id="coder", template_id="coding-bot")
            template = TemplateStore().get("coding-bot")

            self.assertTrue(hasattr(renderer, "preflight"), "renderer preflight API is missing")
            renderer.preflight(request, template)
            self.assertFalse(hermes_root.exists())

            with self.assertRaisesRegex(TemplateError, "env contains unknown key"):
                renderer.preflight(
                    replace(request, env={"UNDECLARED_ENV": "value"}),
                    template,
                )
            with self.assertRaises(TypeError):
                renderer.preflight(
                    request,
                    replace(template, mcp={"not-json-serializable": {"set-value"}}),
                )
            self.assertFalse(hermes_root.exists())

    def test_renderer_rejects_nul_env_before_mutating_existing_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hermes_root = Path(tmp) / ".zeus" / "hermes"
            renderer = ProfileRenderer(hermes_root)
            template = TemplateStore().get("coding-bot")
            renderer.render(
                BotCreateRequest(bot_id="coder", template_id="coding-bot"),
                template,
            )
            profile = hermes_root / "profiles" / "coder"
            before = {
                path.relative_to(profile): path.read_bytes()
                for path in profile.rglob("*")
                if path.is_file()
            }

            with self.assertRaisesRegex(ValueError, "cannot contain NUL"):
                renderer.render(
                    BotCreateRequest(
                        bot_id="coder",
                        template_id="coding-bot",
                        env={"OPENROUTER_API_KEY": "invalid\0value"},
                    ),
                    replace(template, soul="must not be installed"),
                )

            after = {
                path.relative_to(profile): path.read_bytes()
                for path in profile.rglob("*")
                if path.is_file()
            }
            self.assertEqual(before, after)
            self.assertEqual(["coder"], sorted(path.name for path in profile.parent.iterdir()))

    def test_renderer_atomically_replaces_profile_and_preserves_logs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hermes_root = Path(tmp) / ".zeus" / "hermes"
            renderer = ProfileRenderer(hermes_root)
            template = TemplateStore().get("coding-bot")
            request = BotCreateRequest(bot_id="coder", template_id="coding-bot")
            renderer.render(request, template)
            profile = hermes_root / "profiles" / "coder"
            (profile / "logs" / "gateway.log").write_text("existing log\n", encoding="utf-8")

            renderer.render(request, replace(template, soul="replacement soul"))

            self.assertEqual("replacement soul\n", (profile / "SOUL.md").read_text())
            self.assertEqual("existing log\n", (profile / "logs" / "gateway.log").read_text())
            self.assertEqual(["coder"], sorted(path.name for path in profile.parent.iterdir()))

    def test_renderer_replacement_preserves_complete_existing_profile_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hermes_root = Path(tmp) / ".zeus" / "hermes"
            renderer = ProfileRenderer(hermes_root)
            template = TemplateStore().get("coding-bot")
            request = BotCreateRequest(bot_id="coder", template_id="coding-bot")
            renderer.render(request, template)
            profile = hermes_root / "profiles" / "coder"

            (profile / "skills" / "review").mkdir(parents=True)
            (profile / "skills" / "review" / "SKILL.md").write_text(
                "existing skill\n", encoding="utf-8"
            )
            (profile / "cron" / "operator-job.json").write_text(
                '{"preserve": true}\n', encoding="utf-8"
            )
            (profile / "operator-notes.txt").write_text("keep me\n", encoding="utf-8")
            (profile / "runtime" / "nested").mkdir(parents=True)
            (profile / "runtime" / "nested" / "state.json").write_text(
                '{"state": "preserved"}\n', encoding="utf-8"
            )

            renderer.render(request, replace(template, soul="replacement soul"))

            self.assertEqual("replacement soul\n", (profile / "SOUL.md").read_text())
            self.assertTrue((profile / "skills" / "review" / "SKILL.md").is_file())
            self.assertEqual(
                "existing skill\n",
                (profile / "skills" / "review" / "SKILL.md").read_text(),
            )
            self.assertEqual(
                '{"preserve": true}\n',
                (profile / "cron" / "operator-job.json").read_text(),
            )
            self.assertEqual("keep me\n", (profile / "operator-notes.txt").read_text())
            self.assertEqual(
                '{"state": "preserved"}\n',
                (profile / "runtime" / "nested" / "state.json").read_text(),
            )

    def test_renderer_replacement_preserves_symlinks_without_following_managed_links(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_root = root / ".zeus" / "hermes"
            renderer = ProfileRenderer(hermes_root)
            template = TemplateStore().get("coding-bot")
            request = BotCreateRequest(bot_id="coder", template_id="coding-bot")
            renderer.render(request, template)
            profile = hermes_root / "profiles" / "coder"
            external = root / "external.txt"
            external.write_text("do not overwrite\n", encoding="utf-8")
            external_cron = root / "external-cron"
            external_cron.mkdir()
            (external_cron / "jobs.json").write_text(
                "external cron must not change\n", encoding="utf-8"
            )
            external_skills = root / "external-skills"
            external_skills.mkdir()
            (external_skills / "SKILL.md").write_text("linked skill\n", encoding="utf-8")
            external_logs = root / "external-logs"
            external_logs.mkdir()
            (external_logs / "gateway.log").write_text("linked log\n", encoding="utf-8")

            try:
                (profile / "operator-link").symlink_to(external)
                (profile / "SOUL.md").unlink()
                (profile / "SOUL.md").symlink_to(external)
                (profile / "cron" / "jobs.json").unlink()
                (profile / "cron").rmdir()
                (profile / "cron").symlink_to(external_cron, target_is_directory=True)
                (profile / "skills").rmdir()
                (profile / "skills").symlink_to(external_skills, target_is_directory=True)
                (profile / "logs").rmdir()
                (profile / "logs").symlink_to(external_logs, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlinks are unavailable: {exc}")

            renderer.render(request, replace(template, soul="replacement soul"))

            self.assertTrue((profile / "operator-link").is_symlink())
            self.assertEqual(external.resolve(), (profile / "operator-link").resolve())
            self.assertFalse((profile / "SOUL.md").is_symlink())
            self.assertEqual("replacement soul\n", (profile / "SOUL.md").read_text())
            self.assertEqual("do not overwrite\n", external.read_text())
            self.assertFalse((profile / "cron").is_symlink())
            self.assertTrue((profile / "cron" / "jobs.json").is_file())
            self.assertEqual(
                "external cron must not change\n",
                (external_cron / "jobs.json").read_text(),
            )
            self.assertTrue((profile / "skills").is_symlink())
            self.assertEqual("linked skill\n", (profile / "skills" / "SKILL.md").read_text())
            self.assertTrue((profile / "logs").is_symlink())
            self.assertEqual("linked log\n", (profile / "logs" / "gateway.log").read_text())

    def test_renderer_transaction_commits_replacement_and_cleans_backup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hermes_root = Path(tmp) / ".zeus" / "hermes"
            renderer = ProfileRenderer(hermes_root)
            template = TemplateStore().get("coding-bot")
            request = BotCreateRequest(bot_id="coder", template_id="coding-bot")
            renderer.render(request, template)
            profile = hermes_root / "profiles" / "coder"
            (profile / "logs" / "gateway.log").write_text("existing log\n", encoding="utf-8")

            with renderer.transaction(
                request, replace(template, soul="replacement soul")
            ) as record:
                self.assertEqual("coder", record.bot_id)
                self.assertEqual("replacement soul\n", (profile / "SOUL.md").read_text())
                self.assertTrue(
                    any(path.name.endswith(".previous") for path in profile.parent.iterdir())
                )

            self.assertEqual("replacement soul\n", (profile / "SOUL.md").read_text())
            self.assertEqual("existing log\n", (profile / "logs" / "gateway.log").read_text())
            self.assertEqual(["coder"], sorted(path.name for path in profile.parent.iterdir()))

    def test_renderer_transaction_restores_exact_profile_on_caller_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hermes_root = Path(tmp) / ".zeus" / "hermes"
            renderer = ProfileRenderer(hermes_root)
            template = TemplateStore().get("coding-bot")
            request = BotCreateRequest(bot_id="coder", template_id="coding-bot")
            renderer.render(request, template)
            profile = hermes_root / "profiles" / "coder"
            (profile / "logs" / "gateway.log").write_text("existing log\n", encoding="utf-8")
            original_inode = profile.stat().st_ino
            before = {
                path.relative_to(profile): path.read_bytes()
                for path in profile.rglob("*")
                if path.is_file()
            }

            with (
                self.assertRaisesRegex(RuntimeError, "injected database failure"),
                renderer.transaction(request, replace(template, soul="replacement soul")),
            ):
                self.assertNotEqual(original_inode, profile.stat().st_ino)
                self.assertEqual("replacement soul\n", (profile / "SOUL.md").read_text())
                self.assertEqual("existing log\n", (profile / "logs" / "gateway.log").read_text())
                raise RuntimeError("injected database failure")

            after = {
                path.relative_to(profile): path.read_bytes()
                for path in profile.rglob("*")
                if path.is_file()
            }
            self.assertEqual(original_inode, profile.stat().st_ino)
            self.assertEqual(before, after)
            self.assertEqual(["coder"], sorted(path.name for path in profile.parent.iterdir()))

    def test_renderer_transaction_removes_new_profile_on_caller_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hermes_root = Path(tmp) / ".zeus" / "hermes"
            renderer = ProfileRenderer(hermes_root)
            template = TemplateStore().get("coding-bot")
            request = BotCreateRequest(bot_id="coder", template_id="coding-bot")
            profile = hermes_root / "profiles" / "coder"

            with (
                self.assertRaisesRegex(RuntimeError, "injected database failure"),
                renderer.transaction(request, template),
            ):
                self.assertTrue(profile.is_dir())
                raise RuntimeError("injected database failure")

            self.assertFalse(profile.exists())
            self.assertEqual([], list(profile.parent.iterdir()))

    def test_renderer_restores_previous_profile_when_install_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hermes_root = Path(tmp) / ".zeus" / "hermes"
            renderer = ProfileRenderer(hermes_root)
            template = TemplateStore().get("coding-bot")
            request = BotCreateRequest(bot_id="coder", template_id="coding-bot")
            renderer.render(request, template)
            profile = hermes_root / "profiles" / "coder"
            (profile / "logs" / "gateway.log").write_text("existing log\n", encoding="utf-8")
            before = {
                path.relative_to(profile): path.read_bytes()
                for path in profile.rglob("*")
                if path.is_file()
            }
            real_replace = os.replace
            replace_calls = 0

            def fail_new_profile_install(source: object, destination: object) -> None:
                nonlocal replace_calls
                replace_calls += 1
                if replace_calls == 2:
                    raise OSError("injected profile install failure")
                real_replace(source, destination)  # type: ignore[arg-type]

            with (
                patch("zeus.renderer.os.replace", side_effect=fail_new_profile_install),
                self.assertRaisesRegex(OSError, "injected profile install failure"),
            ):
                renderer.render(request, replace(template, soul="replacement soul"))

            after = {
                path.relative_to(profile): path.read_bytes()
                for path in profile.rglob("*")
                if path.is_file()
            }
            self.assertEqual(3, replace_calls)
            self.assertEqual(before, after)
            self.assertEqual(["coder"], sorted(path.name for path in profile.parent.iterdir()))


if __name__ == "__main__":
    unittest.main()
