from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from zeus.audit_config import parse_audit_config
from zeus.audit_profile import (
    AuditProfileError,
    build_audit_profile,
    render_audit_profile_config,
)
from zeus.envfile import parse_env_text
from zeus.models import BotCreateRequest, HermesTemplate, TemplateError
from zeus.renderer import ProfileRenderer


class FeishuProfileSecurityTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
