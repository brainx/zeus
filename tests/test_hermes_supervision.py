from __future__ import annotations

import inspect
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from zeus.api import make_handler
from zeus.cli import _demo_services, _services
from zeus.config import Settings
from zeus.hermes_adapter import HermesAdapter
from zeus.hermes_profile_environment import (
    HERMES_SUPERVISOR_ENV_KEYS,
    HermesProfileEnvironmentError,
)
from zeus.models import BotCreateRequest, HermesTemplate, TemplateError
from zeus.renderer import ProfileRenderer
from zeus.state import StateStore
from zeus.supervisor import Supervisor


class HermesSupervisionTests(unittest.TestCase):
    def _adapter(self, root: Path, profile_env: str = "") -> HermesAdapter:
        profile = root / "profiles" / "coder"
        profile.mkdir(parents=True)
        (profile / ".env").write_text(profile_env, encoding="utf-8")
        (profile / "config.yaml").write_text("model: test\n", encoding="utf-8")
        binary = root / "hermes"
        binary.write_text("#!/bin/sh\n", encoding="utf-8")
        binary.chmod(0o755)
        return HermesAdapter(str(binary), root)

    def test_supervisor_environment_is_authoritative_with_unchanged_gateway_argv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            adapter = self._adapter(root, "OPENAI_API_KEY=fixture-key\n")
            with patch.dict(
                os.environ,
                {
                    "ZEUS_ENV_PASSTHROUGH": ",".join(HERMES_SUPERVISOR_ENV_KEYS),
                    **dict.fromkeys(HERMES_SUPERVISOR_ENV_KEYS, "0"),
                },
                clear=True,
            ):
                payload = adapter.launcher_payload(
                    "coder", operation_id="a" * 32, desired_revision=1, readiness_probe=None
                )
            expected_argv = [str(root / "hermes"), "-p", "coder", "gateway", "run"]
            self.assertEqual(expected_argv, payload["argv"])
            self.assertEqual(expected_argv, payload["marker"]["argv"])
            for key in HERMES_SUPERVISOR_ENV_KEYS:
                self.assertEqual("1", payload["env"][key])
            self.assertEqual(str(root), payload["env"]["HERMES_HOME"])
            self.assertEqual("fixture-key", payload["env"]["OPENAI_API_KEY"])

    def test_stored_supervisor_overrides_are_rejected_before_launch(self) -> None:
        for key in HERMES_SUPERVISOR_ENV_KEYS:
            for assignment in (f"{key}=0", f"export {key} = 0", f"'{key}'=0", f'"{key}"=0'):
                with self.subTest(assignment=assignment), tempfile.TemporaryDirectory() as tmp:
                    adapter = self._adapter(
                        Path(tmp), assignment + "\nOPENAI_API_KEY=private-fixture-value\n"
                    )
                    with (
                        patch("zeus.hermes_adapter.subprocess.run") as run,
                        self.assertRaises(HermesProfileEnvironmentError) as raised,
                    ):
                        adapter.run("coder", "gateway", "run")
                    run.assert_not_called()
                    self.assertEqual(
                        "Hermes profile environment could not be validated safely",
                        str(raised.exception),
                    )

    def test_renderer_rejects_supervisor_controls_even_if_template_allows_them(self) -> None:
        for key in HERMES_SUPERVISOR_ENV_KEYS:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "hermes"
                template = HermesTemplate.from_dict(
                    {
                        "id": "coding-bot",
                        "name": "Coder",
                        "description": "Fixture",
                        "version": "0.1.0",
                        "hermes": {
                            "model": {"provider": "openrouter", "default": "x/y"},
                            "required_env": [key],
                        },
                        "soul": "Fixture",
                    }
                )
                request = BotCreateRequest(
                    bot_id="coder", template_id="coding-bot", env={key: "private-fixture-value"}
                )
                with self.assertRaises(TemplateError) as raised:
                    ProfileRenderer(root).render(request, template)
                self.assertIn(key, str(raised.exception))
                self.assertNotIn("private-fixture-value", str(raised.exception))
                self.assertFalse(root.exists())


class ShutdownGraceSettingsTests(unittest.TestCase):
    def test_defaults_explicit_overrides_and_invalid_bounds(self) -> None:
        settings = Settings.from_env({}, include_dotenv=False)
        self.assertEqual(60, settings.stop_grace_seconds)
        self.assertEqual(10, settings.api_request_timeout_seconds)
        self.assertEqual(20, settings.api_shutdown_drain_seconds)
        for value in ("0", "15", "32.5", "300"):
            with self.subTest(value=value):
                settings = Settings.from_env(
                    {"ZEUS_STOP_GRACE_SECONDS": value}, include_dotenv=False
                )
                self.assertEqual(float(value), settings.stop_grace_seconds)
        for value in ("-1", "300.1", "nan", "inf", "-inf", "invalid"):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ValueError, "ZEUS_STOP_GRACE_SECONDS"),
            ):
                Settings.from_env({"ZEUS_STOP_GRACE_SECONDS": value}, include_dotenv=False)

    def test_constructor_preserves_explicit_grace_and_rejects_invalid_values(self) -> None:
        grace = inspect.signature(Supervisor.__init__).parameters["stop_grace_seconds"]
        self.assertEqual(60, grace.default)
        self.assertIs(inspect.Parameter.POSITIONAL_OR_KEYWORD, grace.kind)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            for value in (0, 0.01, 15, 60, 300):
                supervisor = Supervisor(store, "hermes", root, stop_grace_seconds=value)
                self.assertEqual(value, supervisor.stop_grace_seconds)
            for value in (-1, 301, float("nan"), float("inf"), True, "15"):
                with (
                    self.subTest(value=value),
                    self.assertRaisesRegex(ValueError, "stop_grace_seconds"),
                ):
                    Supervisor(store, "hermes", root, stop_grace_seconds=value)

    def test_cli_demo_and_api_forward_configured_grace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings.from_env(
                {"ZEUS_STATE_DIR": tmp, "ZEUS_STOP_GRACE_SECONDS": "42.5"}, include_dotenv=False
            )
            with (
                patch("zeus.cli.Supervisor", wraps=Supervisor) as cli_supervisor,
                patch("zeus.cli._demo_hermes_bin", return_value="fake-hermes"),
                patch("zeus.cli._demo_cmdline_reader", return_value=lambda _pid: []),
            ):
                _services(settings)
                _demo_services(settings, "coder")
            self.assertEqual(2, cli_supervisor.call_count)
            for call in cli_supervisor.call_args_list:
                self.assertEqual(42.5, call.kwargs["stop_grace_seconds"])
            with patch("zeus.api.Supervisor", wraps=Supervisor) as api_supervisor:
                make_handler(settings)
            self.assertEqual(42.5, api_supervisor.call_args.kwargs["stop_grace_seconds"])
