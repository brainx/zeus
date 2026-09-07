from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from zeus.gateway_launcher import _validate_payload
from zeus.gateway_marker import MarkerValidationError, parse_launch_marker, parse_runtime_marker
from zeus.hermes_adapter import HermesAdapter
from zeus.messaging_policy import MessagePolicyError, load_message_policy
from zeus.models import BotCreateRequest, HermesGatewayConfig, TemplateError
from zeus.readiness import ReadinessProbe
from zeus.renderer import ProfileRenderer
from zeus.templates import TemplateStore


class MessagingPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.enterContext(patch("zeus.messaging_policy._MANAGED_DIRECTORY", self.root / "managed"))
        self.env = {
            "OPENROUTER_API_KEY": "fixture-provider-key",
            "API_SERVER_ENABLED": "1",
            "API_SERVER_PORT": "8642",
            "API_SERVER_KEY": "fixture-private-api-key",
            "ZEUS_MESSAGES_ENABLED": "1",
        }
        ProfileRenderer(self.root).render(
            BotCreateRequest("coder", "message-bot", env=self.env),
            TemplateStore().get("message-bot"),
        )
        self.profile = self.root / "profiles" / "coder"
        self.bin = self.root / "hermes"
        self.bin.write_text("#!/bin/sh\n")
        self.bin.chmod(0o755)
        self.adapter = HermesAdapter(str(self.bin), self.root)

    def launch(self) -> dict[str, object]:
        return self.adapter.launcher_payload(
            "coder",
            operation_id="a" * 32,
            desired_revision=1,
            readiness_probe=ReadinessProbe("http://127.0.0.1:8642/health"),
        )["marker"]

    def test_rendered_policy_is_bound_and_round_trips_strict_markers(self) -> None:
        policy = load_message_policy(self.profile)
        marker = self.launch()
        self.assertEqual(policy.fingerprint, marker["messaging_policy_fingerprint"])
        self.assertEqual(marker, parse_launch_marker(marker).to_payload())
        launch_payload = self.adapter.launcher_payload(
            "coder",
            operation_id="a" * 32,
            desired_revision=1,
            readiness_probe=ReadinessProbe("http://127.0.0.1:8642/health"),
        )
        self.assertEqual(marker, _validate_payload(launch_payload)[1])
        runtime = {**marker, "pid": 123, "started_at": 1, "proc_start_fingerprint": "start"}
        self.assertEqual(runtime, parse_runtime_marker(runtime).to_payload())
        for value in (None, "", "x" * 64, 1, "a" * 65):
            with self.subTest(value=value), self.assertRaises(MarkerValidationError):
                parse_launch_marker({**marker, "messaging_policy_fingerprint": value})

    def test_old_marker_and_disabled_profiles_remain_valid(self) -> None:
        env = self.profile / ".env"
        env.write_text(
            env.read_text().replace("ZEUS_MESSAGES_ENABLED=1", "ZEUS_MESSAGES_ENABLED=0")
        )
        marker = self.launch()
        self.assertNotIn("messaging_policy_fingerprint", marker)
        self.assertEqual(marker, parse_launch_marker(marker).to_payload())
        with self.assertRaisesRegex(MessagePolicyError, "messaging_disabled"):
            load_message_policy(self.profile)

    def test_policy_changes_require_a_different_fingerprint(self) -> None:
        original = load_message_policy(self.profile).fingerprint
        for filename, suffix in (
            ("SOUL.md", "\nAdditional operator policy.\n"),
            ("config.yaml", "\nadditional_policy: strict\n"),
        ):
            path = self.profile / filename
            previous = path.read_text()
            path.write_text(previous + suffix)
            self.assertNotEqual(original, load_message_policy(self.profile).fingerprint)
            path.write_text(previous)

    def test_limits_reject_unlimited_boolean_expansion_and_excessive_values(self) -> None:
        path = self.profile / "config.yaml"
        for turns, concurrency in (
            (0, 1),
            (101, 1),
            (True, 1),
            ("${LIMIT}", 1),
            (12, 0),
            (12, True),
            (12, 2),
        ):
            with self.subTest(turns=turns, concurrency=concurrency):
                path.write_text(
                    json.dumps(
                        {
                            "agent": {"max_turns": turns},
                            "gateway": {"api_server": {"max_concurrent_runs": concurrency}},
                        }
                    )
                )
                with self.assertRaisesRegex(MessagePolicyError, "message_limits_required"):
                    load_message_policy(self.profile)

    def test_literal_environment_rejects_duplicates_interpolation_and_overlays(self) -> None:
        path = self.profile / ".env"
        original = path.read_text()
        for suffix in (
            "API_SERVER_KEY=fixture-private-api-key\n",
            'API_SERVER_KEY="${TOKEN}"\n',
            "HERMES_MANAGED_DIR=/missing\n",
        ):
            with self.subTest(suffix=suffix):
                path.write_text(original + suffix)
                with self.assertRaises(MessagePolicyError):
                    load_message_policy(self.profile)
        path.write_text(original)
        (self.root / "managed").mkdir()
        with self.assertRaisesRegex(MessagePolicyError, "managed_policy_unsupported"):
            load_message_policy(self.profile)
        (self.root / "managed").rmdir()
        (self.profile / "gateway.json").write_text("{}")
        with self.assertRaisesRegex(MessagePolicyError, "legacy_policy_unsupported"):
            load_message_policy(self.profile)

    def test_launch_rejects_effective_managed_environment(self) -> None:
        with (
            patch.dict(
                "os.environ",
                {"ZEUS_ENV_PASSTHROUGH": "HERMES_MANAGED_DIR", "HERMES_MANAGED_DIR": "/missing"},
            ),
            self.assertRaisesRegex(MessagePolicyError, "managed_policy_unsupported"),
        ):
            self.launch()

    def test_missing_or_linked_policy_files_fail_closed(self) -> None:
        soul = self.profile / "SOUL.md"
        soul.unlink()
        with self.assertRaisesRegex(MessagePolicyError, "configuration_invalid"):
            load_message_policy(self.profile)
        soul.symlink_to(self.profile / "config.yaml")
        with self.assertRaisesRegex(MessagePolicyError, "configuration_invalid"):
            load_message_policy(self.profile)

    def test_api_server_model_preserves_old_profiles_and_validates_new_limits(self) -> None:
        self.assertEqual({"enabled": True}, HermesGatewayConfig.from_dict({}).to_config())
        for value in (0, True, 33, "1"):
            with self.subTest(value=value), self.assertRaises(TemplateError):
                HermesGatewayConfig.from_dict({"api_server": {"max_concurrent_runs": value}})
        with self.assertRaises(TemplateError):
            HermesGatewayConfig.from_dict({"api_server": {"unknown": 1}})
        self.assertEqual(
            {"enabled": True, "api_server": {"max_concurrent_runs": 1}},
            HermesGatewayConfig.from_dict({"api_server": {}}).to_config(),
        )


if __name__ == "__main__":
    unittest.main()
