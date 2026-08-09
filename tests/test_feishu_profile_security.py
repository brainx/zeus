from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from zeus.audit_config import parse_audit_config
from zeus.audit_profile import (
    AuditProfileError,
    build_audit_profile,
    render_audit_profile_config,
)
from zeus.envfile import dump_env, parse_env_text
from zeus.hermes_adapter import HermesAdapter
from zeus.hermes_profile_config import (
    HERMES_PROFILE_CONFIG_MAX_BYTES,
    HermesProfileConfigError,
)
from zeus.hermes_security import UnsupportedFeishuWebhookModeError
from zeus.models import BotCreateRequest, HermesTemplate, TemplateError
from zeus.renderer import ProfileRenderer


class FeishuProfileSecurityTests(unittest.TestCase):
    def _runtime_adapter(
        self,
        root: Path,
        profile_env: str = "",
        profile_config: str = 'model:\n  provider: "test"\n',
        *,
        hermes_bin: str = "hermes",
        legacy_gateway: str | None = None,
    ) -> HermesAdapter:
        profile = root / "profiles" / "feishu-bot"
        profile.mkdir(parents=True)
        (profile / ".env").write_text(profile_env, encoding="utf-8")
        (profile / "config.yaml").write_text(profile_config, encoding="utf-8")
        if legacy_gateway is not None:
            (profile / "gateway.json").write_text(legacy_gateway, encoding="utf-8")
        return HermesAdapter(hermes_bin, root)

    def _template(self, *, structured_mode: str | None = None) -> HermesTemplate:
        hermes: dict[str, object] = {
            "model": {"provider": "openrouter", "default": "x/y"},
            "required_env": ["FEISHU_CONNECTION_MODE", "PRIVATE_CONTEXT"],
        }
        if structured_mode is not None:
            hermes["platforms"] = {"feishu": {"extra": {"connection_mode": structured_mode}}}
        return HermesTemplate.from_dict(
            {
                "id": "feishu-bot",
                "name": "Feishu Bot",
                "description": "Feishu profile security test",
                "version": "0.1.0",
                "hermes": hermes,
                "soul": "valid soul",
            }
        )

    def test_renderer_rejects_webhook_environment_mode_without_echoing_values(self) -> None:
        sensitive_value = "do-not-print-this-sensitive-value"
        for mode in ("webhook", "  WebHook\t"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                request = BotCreateRequest(
                    bot_id="feishu-bot",
                    template_id="feishu-bot",
                    env={
                        "FEISHU_CONNECTION_MODE": mode,
                        "PRIVATE_CONTEXT": sensitive_value,
                    },
                )

                with self.assertRaises(TemplateError) as raised:
                    ProfileRenderer(Path(tmp) / "hermes").preflight(request, self._template())

                message = str(raised.exception)
                self.assertIn("FEISHU_CONNECTION_MODE", message)
                self.assertIn("WebSocket", message)
                self.assertNotIn(sensitive_value, message)

    def test_renderer_rejects_structured_webhook_mode_after_normalization(self) -> None:
        for mode in ("webhook", "\nWEBHOOK  "):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                request = BotCreateRequest(
                    bot_id="feishu-bot",
                    template_id="feishu-bot",
                    env={"PRIVATE_CONTEXT": "private-value"},
                )

                with self.assertRaises(TemplateError) as raised:
                    ProfileRenderer(Path(tmp) / "hermes").preflight(
                        request,
                        self._template(structured_mode=mode),
                    )

                message = str(raised.exception)
                self.assertIn("platforms.feishu.extra.connection_mode", message)
                self.assertIn("WebSocket", message)
                self.assertNotIn("private-value", message)

    def test_renderer_rejects_interpolated_structured_connection_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            request = BotCreateRequest(
                bot_id="feishu-bot",
                template_id="feishu-bot",
                env={"PRIVATE_CONTEXT": "private-value"},
            )

            with self.assertRaises(TemplateError) as raised:
                ProfileRenderer(Path(tmp) / "hermes").preflight(
                    request,
                    self._template(structured_mode="${FEISHU_MODE}"),
                )

        message = str(raised.exception)
        self.assertIn("platforms.feishu.extra.connection_mode", message)
        self.assertIn("WebSocket", message)
        self.assertNotIn("private-value", message)

    def test_renderer_preserves_websocket_and_absent_environment_modes(self) -> None:
        for mode in ("websocket", "  WebSocket\t"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                request = BotCreateRequest(
                    bot_id="feishu-bot",
                    template_id="feishu-bot",
                    env={"FEISHU_CONNECTION_MODE": mode},
                )
                rendered = ProfileRenderer(Path(tmp) / "hermes").preflight(
                    request,
                    self._template(),
                )

                self.assertEqual(mode, parse_env_text(rendered[".env"])["FEISHU_CONNECTION_MODE"])

        with tempfile.TemporaryDirectory() as tmp:
            rendered = ProfileRenderer(Path(tmp) / "hermes").preflight(
                BotCreateRequest(bot_id="feishu-bot", template_id="feishu-bot"),
                self._template(),
            )
        self.assertNotIn("FEISHU_CONNECTION_MODE", parse_env_text(rendered[".env"]))

    def test_renderer_preserves_websocket_and_absent_structured_modes(self) -> None:
        for mode in ("websocket", "  WebSocket\t"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                rendered = ProfileRenderer(Path(tmp) / "hermes").preflight(
                    BotCreateRequest(bot_id="feishu-bot", template_id="feishu-bot"),
                    self._template(structured_mode=mode),
                )
                self.assertIn(
                    f"connection_mode: {mode!r}".replace("'", '"'), rendered["config.yaml"]
                )

        with tempfile.TemporaryDirectory() as tmp:
            rendered = ProfileRenderer(Path(tmp) / "hermes").preflight(
                BotCreateRequest(bot_id="feishu-bot", template_id="feishu-bot"),
                self._template(),
            )
        self.assertNotIn("platforms:", rendered["config.yaml"])

    def test_sealed_audit_profile_renderer_rejects_structured_webhook_mode(self) -> None:
        profile = build_audit_profile(parse_audit_config({"schema_version": 1}))
        profile = replace(
            profile,
            hermes={
                **profile.hermes,
                "platforms": {"feishu": {"extra": {"connection_mode": "  WEBHOOK\n"}}},
            },
        )

        with self.assertRaisesRegex(
            AuditProfileError,
            "platforms.feishu.extra.connection_mode",
        ):
            render_audit_profile_config(profile)

    def test_runtime_rejects_ambient_passthrough_webhook_without_echoing_values(self) -> None:
        sensitive_value = "ambient-sensitive-value"
        with tempfile.TemporaryDirectory() as tmp:
            adapter = self._runtime_adapter(Path(tmp) / "hermes")
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "ZEUS_ENV_PASSTHROUGH": "FEISHU_CONNECTION_MODE,PRIVATE_CONTEXT",
                        "FEISHU_CONNECTION_MODE": "  WebHook\t",
                        "PRIVATE_CONTEXT": sensitive_value,
                    },
                    clear=True,
                ),
                self.assertRaises(UnsupportedFeishuWebhookModeError) as raised,
            ):
                adapter.command("feishu-bot", "gateway", "run")

        message = str(raised.exception)
        self.assertIn("FEISHU_CONNECTION_MODE", message)
        self.assertIn("WebSocket", message)
        self.assertNotIn(sensitive_value, message)

    def test_runtime_rejects_stored_profile_webhook_without_echoing_values(self) -> None:
        sensitive_value = "stored-sensitive-value"
        profile_env = dump_env(
            ["FEISHU_CONNECTION_MODE", "PRIVATE_CONTEXT"],
            {
                "FEISHU_CONNECTION_MODE": "\nWEBHOOK  ",
                "PRIVATE_CONTEXT": sensitive_value,
            },
        )
        with tempfile.TemporaryDirectory() as tmp:
            adapter = self._runtime_adapter(Path(tmp) / "hermes", profile_env)
            with (
                mock.patch.dict(os.environ, {}, clear=True),
                self.assertRaises(UnsupportedFeishuWebhookModeError) as raised,
            ):
                adapter.command("feishu-bot", "gateway", "run")

        message = str(raised.exception)
        self.assertIn("FEISHU_CONNECTION_MODE", message)
        self.assertIn("WebSocket", message)
        self.assertNotIn(sensitive_value, message)

    def test_runtime_rejects_ambiguous_dotenv_mode_assignments(self) -> None:
        sensitive_value = "dotenv-sensitive-value"
        cases = {
            "inline comment": (
                "FEISHU_CONNECTION_MODE=webhook # comment\n"
                f"PRIVATE_CONTEXT={sensitive_value}\n"
            ),
            "quoted key": (
                "'FEISHU_CONNECTION_MODE'=webhook\n"
                f"PRIVATE_CONTEXT={sensitive_value}\n"
            ),
            "duplicate alternate key": (
                "FEISHU_CONNECTION_MODE=websocket\n"
                "'FEISHU_CONNECTION_MODE'=webhook\n"
                f"PRIVATE_CONTEXT={sensitive_value}\n"
            ),
            "interpolation": (
                "FEISHU_MODE=webhook\n"
                "FEISHU_CONNECTION_MODE=${FEISHU_MODE}\n"
                f"PRIVATE_CONTEXT={sensitive_value}\n"
            ),
            "nul sanitized by Hermes": (
                "\x00FEISHU_CONNECTION_MODE=webhook\n"
                f"PRIVATE_CONTEXT={sensitive_value}\n"
            ),
            "bom sanitized by Hermes": (
                "\ufeffFEISHU_CONNECTION_MODE=webhook\n"
                f"PRIVATE_CONTEXT={sensitive_value}\n"
            ),
        }
        for name, profile_env in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                adapter = self._runtime_adapter(Path(tmp) / "hermes", profile_env)
                with self.assertRaises(ValueError) as raised:
                    adapter.command("feishu-bot", "gateway", "run")

                self.assertEqual(
                    "Hermes profile environment could not be validated safely",
                    str(raised.exception),
                )
                self.assertNotIn(sensitive_value, str(raised.exception))

    def test_runtime_preserves_allowed_websocket_modes(self) -> None:
        ambient_mode = "  WebSocket\t"
        with tempfile.TemporaryDirectory() as tmp:
            adapter = self._runtime_adapter(Path(tmp) / "ambient")
            with mock.patch.dict(
                os.environ,
                {
                    "ZEUS_ENV_PASSTHROUGH": "FEISHU_CONNECTION_MODE",
                    "FEISHU_CONNECTION_MODE": ambient_mode,
                },
                clear=True,
            ):
                _, environment = adapter.command("feishu-bot", "gateway", "run")
        self.assertEqual(ambient_mode, environment["FEISHU_CONNECTION_MODE"])

        stored_mode = "\tWEBSOCKET  "
        with tempfile.TemporaryDirectory() as tmp:
            adapter = self._runtime_adapter(
                Path(tmp) / "stored",
                dump_env(
                    ["FEISHU_CONNECTION_MODE"],
                    {"FEISHU_CONNECTION_MODE": stored_mode},
                ),
            )
            with mock.patch.dict(os.environ, {}, clear=True):
                _, environment = adapter.command("feishu-bot", "gateway", "run")
        self.assertEqual(stored_mode, environment["FEISHU_CONNECTION_MODE"])

    def test_runtime_defaults_missing_mode_to_websocket_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            adapter = self._runtime_adapter(Path(tmp) / "hermes")
            _argv, environment = adapter.command("feishu-bot", "gateway", "run")

        self.assertEqual("websocket", environment["FEISHU_CONNECTION_MODE"])

    def test_command_rejects_webhook_in_persisted_profile_config(self) -> None:
        sensitive_value = "persisted-sensitive-value"
        config = (
            "platforms:\n"
            "  feishu:\n"
            "    extra:\n"
            '      connection_mode: "  WebHook\\t"\n'
            f'private_context: "{sensitive_value}"\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            adapter = self._runtime_adapter(Path(tmp) / "hermes", profile_config=config)
            with self.assertRaises(UnsupportedFeishuWebhookModeError) as raised:
                adapter.command("feishu-bot", "gateway", "run")

        message = str(raised.exception)
        self.assertIn("platforms.feishu.extra.connection_mode", message)
        self.assertIn("WebSocket", message)
        self.assertNotIn(sensitive_value, message)

    def test_command_rejects_root_environment_bridge_webhook_modes(self) -> None:
        cases = {
            "canonical": 'FEISHU_CONNECTION_MODE: "  WebHook\\t"\n',
            "case alias": "feishu_connection_mode: WEBHOOK\n",
            "normalized duplicate": (
                "FEISHU_CONNECTION_MODE: websocket\n"
                "feishu_connection_mode: webhook\n"
            ),
        }
        for name, config in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                adapter = self._runtime_adapter(Path(tmp) / "hermes", profile_config=config)
                with self.assertRaisesRegex(
                    UnsupportedFeishuWebhookModeError,
                    "FEISHU_CONNECTION_MODE",
                ):
                    adapter.command("feishu-bot", "gateway", "run")

    def test_command_rejects_dynamic_root_environment_bridge_modes(self) -> None:
        for expression in ("${FEISHU_MODE}", "${env:FEISHU_MODE}"):
            with self.subTest(expression=expression), tempfile.TemporaryDirectory() as tmp:
                adapter = self._runtime_adapter(
                    Path(tmp) / "hermes",
                    dump_env(["FEISHU_MODE"], {"FEISHU_MODE": "webhook"}),
                    profile_config=f'FEISHU_CONNECTION_MODE: "{expression}"\n',
                )
                with self.assertRaisesRegex(
                    UnsupportedFeishuWebhookModeError,
                    "FEISHU_CONNECTION_MODE",
                ):
                    adapter.command("feishu-bot", "gateway", "run")

    def test_command_allows_safe_root_environment_bridge_modes(self) -> None:
        for mode in ("websocket", '"  WebSocket\\t"'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                adapter = self._runtime_adapter(
                    Path(tmp) / "hermes",
                    profile_config=f"FEISHU_CONNECTION_MODE: {mode}\n",
                )
                argv, environment = adapter.command("feishu-bot", "gateway", "run")

                self.assertEqual(["hermes", "-p", "feishu-bot", "gateway", "run"], argv)
                self.assertEqual("websocket", environment["FEISHU_CONNECTION_MODE"])

    def test_command_rejects_gateway_aliases_for_persisted_feishu_mode(self) -> None:
        cases = {
            "gateway.platforms.feishu.extra.connection_mode": (
                "gateway:\n"
                "  platforms:\n"
                "    feishu:\n"
                "      extra:\n"
                "        connection_mode: webhook\n"
            ),
            "gateway.feishu.extra.connection_mode": (
                "gateway:\n"
                "  feishu:\n"
                "    extra:\n"
                "      connection_mode: WEBHOOK\n"
            ),
            "platforms.feishu.extra.connection_mode case variant": (
                "platforms:\n"
                "  FEISHU:\n"
                "    extra:\n"
                "      connection_mode: webhook\n"
            ),
            "gateway.platforms.feishu.extra.connection_mode case variant": (
                "gateway:\n"
                "  platforms:\n"
                "    FeIsHu:\n"
                "      extra:\n"
                "        connection_mode: webhook\n"
            ),
            "gateway.feishu.extra.connection_mode case variant": (
                "gateway:\n"
                "  FEISHU:\n"
                "    extra:\n"
                "      connection_mode: webhook\n"
            ),
            "platforms.feishu.extra.connection_mode normalized duplicate": (
                "platforms:\n"
                "  feishu:\n"
                "    extra:\n"
                "      connection_mode: websocket\n"
                "  FEISHU:\n"
                "    extra:\n"
                "      connection_mode: webhook\n"
            ),
        }
        for expected_path, config in cases.items():
            with self.subTest(path=expected_path), tempfile.TemporaryDirectory() as tmp:
                adapter = self._runtime_adapter(Path(tmp) / "hermes", profile_config=config)
                with self.assertRaises(UnsupportedFeishuWebhookModeError) as raised:
                    adapter.command("feishu-bot", "gateway", "run")
                self.assertIn(expected_path.split(" ", 1)[0], str(raised.exception))

    def test_command_allows_websocket_in_persisted_gateway_alias(self) -> None:
        config = (
            "gateway:\n"
            "  platforms:\n"
            "    feishu:\n"
            "      extra:\n"
            '        connection_mode: "  WebSocket\\t"\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            adapter = self._runtime_adapter(Path(tmp) / "hermes", profile_config=config)
            argv, _environment = adapter.command("feishu-bot", "gateway", "run")

        self.assertEqual(["hermes", "-p", "feishu-bot", "gateway", "run"], argv)

    def test_command_rejects_webhook_in_legacy_gateway_config(self) -> None:
        legacy = (
            '{"platforms":{"feishu":{"extra":{"connection_mode":" webhook "}}}}'
        )
        with tempfile.TemporaryDirectory() as tmp:
            adapter = self._runtime_adapter(
                Path(tmp) / "hermes",
                legacy_gateway=legacy,
            )
            with self.assertRaisesRegex(
                UnsupportedFeishuWebhookModeError,
                "gateway.platforms.feishu.extra.connection_mode",
            ):
                adapter.command("feishu-bot", "gateway", "run")

    def test_command_allows_unambiguous_legacy_and_yaml_keys(self) -> None:
        config = '"display name": "ok"\ncafé: "ok"\n'
        legacy = '{"platforms":{"feishu":{"extra":{"connection_mode":"websocket"}}}}'
        with tempfile.TemporaryDirectory() as tmp:
            adapter = self._runtime_adapter(
                Path(tmp) / "hermes",
                profile_config=config,
                legacy_gateway=legacy,
            )
            argv, _environment = adapter.command("feishu-bot", "gateway", "run")

        self.assertEqual(["hermes", "-p", "feishu-bot", "gateway", "run"], argv)

    def test_launcher_payload_rejects_webhook_in_persisted_profile_config(self) -> None:
        config = (
            "platforms:\n"
            "  feishu:\n"
            "    extra:\n"
            "      connection_mode: WEBHOOK\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            adapter = self._runtime_adapter(Path(tmp) / "hermes", profile_config=config)
            with self.assertRaisesRegex(
                UnsupportedFeishuWebhookModeError,
                "platforms.feishu.extra.connection_mode",
            ):
                adapter.launcher_payload(
                    "feishu-bot",
                    operation_id="a" * 32,
                    desired_revision=1,
                    readiness_probe=None,
                )

    def test_run_rejects_webhook_in_persisted_profile_config_before_launch(self) -> None:
        config = (
            "platforms:\n"
            "  feishu:\n"
            "    extra:\n"
            "      connection_mode: webhook\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            adapter = self._runtime_adapter(Path(tmp) / "hermes", profile_config=config)
            with (
                mock.patch(
                    "zeus.hermes_adapter.subprocess.run",
                    side_effect=AssertionError("Hermes must not launch"),
                ) as run,
                self.assertRaises(UnsupportedFeishuWebhookModeError),
            ):
                adapter.run("feishu-bot", "gateway", "run")

        run.assert_not_called()

    def test_run_rejects_interpolated_persisted_connection_mode_before_launch(self) -> None:
        sensitive_value = "interpolation-sensitive-value"
        for expression in ("${FEISHU_MODE}", "${env:FEISHU_MODE}"):
            with self.subTest(expression=expression), tempfile.TemporaryDirectory() as tmp:
                config = (
                    "platforms:\n"
                    "  feishu:\n"
                    "    extra:\n"
                    f'      connection_mode: "{expression}"\n'
                    f'private_context: "{sensitive_value}"\n'
                )
                adapter = self._runtime_adapter(
                    Path(tmp) / "hermes",
                    dump_env(["FEISHU_MODE"], {"FEISHU_MODE": "webhook"}),
                    profile_config=config,
                )
                with (
                    mock.patch(
                        "zeus.hermes_adapter.subprocess.run",
                        side_effect=AssertionError("Hermes must not launch"),
                    ) as run,
                    self.assertRaises(UnsupportedFeishuWebhookModeError) as raised,
                ):
                    adapter.run("feishu-bot", "gateway", "run")

                message = str(raised.exception)
                self.assertIn("platforms.feishu.extra.connection_mode", message)
                self.assertIn("WebSocket", message)
                self.assertNotIn(sensitive_value, message)
                run.assert_not_called()

    def test_runtime_entry_points_allow_persisted_websocket_mode(self) -> None:
        mode = "  WebSocket\\t"
        config = (
            "platforms:\n"
            "  feishu:\n"
            "    extra:\n"
            f'      connection_mode: "{mode}"\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            adapter = self._runtime_adapter(
                Path(tmp) / "hermes",
                profile_config=config,
                hermes_bin=sys.executable,
            )
            _, command_env = adapter.command("feishu-bot", "gateway", "run")
            payload = adapter.launcher_payload(
                "feishu-bot",
                operation_id="a" * 32,
                desired_revision=1,
                readiness_probe=None,
            )
            completed = subprocess.CompletedProcess([sys.executable], 0, "", "")
            with mock.patch("zeus.hermes_adapter.subprocess.run", return_value=completed) as run:
                result = adapter.run("feishu-bot", "gateway", "run")

        self.assertEqual(completed, result)
        self.assertEqual("websocket", command_env["FEISHU_CONNECTION_MODE"])
        self.assertEqual("websocket", payload["env"]["FEISHU_CONNECTION_MODE"])
        run.assert_called_once()

    def test_runtime_rejects_missing_or_ambiguous_persisted_config(self) -> None:
        cases = {
            "duplicate key": (
                "platforms:\n"
                "  feishu:\n"
                "    extra:\n"
                "      connection_mode: websocket\n"
                "platforms:\n"
                "  feishu:\n"
                "    extra:\n"
                "      connection_mode: webhook\n"
            ),
            "yaml alias": (
                "unsafe: &unsafe\n"
                "  connection_mode: webhook\n"
                "platforms:\n"
                "  feishu:\n"
                "    extra: *unsafe\n"
            ),
        }
        for name, config in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                adapter = self._runtime_adapter(Path(tmp) / "hermes", profile_config=config)
                with self.assertRaises(HermesProfileConfigError) as raised:
                    adapter.command("feishu-bot", "gateway", "run")
                self.assertEqual(
                    "Hermes profile configuration could not be validated safely",
                    str(raised.exception),
                )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "hermes"
            adapter = self._runtime_adapter(root)
            (root / "profiles" / "feishu-bot" / "config.yaml").unlink()
            with self.assertRaises(HermesProfileConfigError) as raised:
                adapter.command("feishu-bot", "gateway", "run")
            self.assertEqual(
                "Hermes profile configuration could not be validated safely",
                str(raised.exception),
            )

    def test_runtime_rejects_unsafe_persisted_config_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "hermes"
            adapter = self._runtime_adapter(root)
            config_path = root / "profiles" / "feishu-bot" / "config.yaml"
            config_path.write_bytes(b"\xff")
            with self.assertRaises(HermesProfileConfigError):
                adapter.command("feishu-bot", "gateway", "run")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "hermes"
            adapter = self._runtime_adapter(root, profile_config="note: x\x80\n")
            with self.assertRaises(HermesProfileConfigError):
                adapter.command("feishu-bot", "gateway", "run")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "hermes"
            adapter = self._runtime_adapter(root)
            config_path = root / "profiles" / "feishu-bot" / "config.yaml"
            config_path.write_bytes(b"x" * (HERMES_PROFILE_CONFIG_MAX_BYTES + 1))
            with self.assertRaises(HermesProfileConfigError):
                adapter.command("feishu-bot", "gateway", "run")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "hermes"
            adapter = self._runtime_adapter(root)
            config_path = root / "profiles" / "feishu-bot" / "config.yaml"
            target = root / "external-config.yaml"
            target.write_text("model: test\n", encoding="utf-8")
            config_path.unlink()
            config_path.symlink_to(target)
            with self.assertRaises(HermesProfileConfigError):
                adapter.command("feishu-bot", "gateway", "run")


if __name__ == "__main__":
    unittest.main()
