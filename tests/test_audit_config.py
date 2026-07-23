from __future__ import annotations

import math
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from zeus.audit_config import (
    DEFAULT_AUDIT_IMAGE,
    AuditConfigError,
    load_audit_config,
    parse_audit_config,
)
from zeus.audit_models import (
    HARD_LIMITS,
    AuditCategory,
    AuditConfig,
    AuditLimits,
    SuggestedCommand,
)

CONFIGURABLE_LIMITS = {
    "overall_seconds": HARD_LIMITS.overall_seconds,
    "terminal_command_seconds": HARD_LIMITS.terminal_command_seconds,
    "findings": HARD_LIMITS.findings,
    "model_output_bytes": HARD_LIMITS.model_output_bytes,
    "artifact_bytes": HARD_LIMITS.artifact_bytes,
    "snapshot_entries": HARD_LIMITS.snapshot_entries,
    "snapshot_blob_bytes": HARD_LIMITS.snapshot_blob_bytes,
}


class AuditConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temp_dir.name).resolve() / "state"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def write_config_bytes(self, data: bytes) -> None:
        audit_dir = self.state_dir / "audit"
        audit_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        path = audit_dir / "config.json"
        path.write_bytes(data)
        path.chmod(0o600)

    def test_missing_config_returns_immutable_release_defaults(self) -> None:
        config = load_audit_config(self.state_dir)

        self.assertEqual(1, config.schema_version)
        self.assertIsNone(config.provider)
        self.assertIsNone(config.model)
        self.assertEqual((), config.provider_env)
        self.assertEqual(DEFAULT_AUDIT_IMAGE, config.image)
        self.assertEqual(frozenset(AuditCategory), config.categories)
        self.assertEqual((), config.exclude_paths)
        self.assertEqual((), config.suggested_commands)
        self.assertEqual(AuditLimits(**vars(HARD_LIMITS)), config.limits)
        with self.assertRaises(FrozenInstanceError):
            config.provider = "changed"  # type: ignore[misc]

    def test_valid_schema_version_one_parses_every_supported_field(self) -> None:
        limits = {name: ceiling - 1 for name, ceiling in CONFIGURABLE_LIMITS.items()}
        config = parse_audit_config(
            {
                "schema_version": 1,
                "provider": "openai",
                "model": "gpt-audit",
                "provider_env": ["OPENAI_API_KEY", "OPENAI_ORG_ID"],
                "image": "registry.example/audit:1@sha256:" + "a" * 64,
                "categories": ["security", "tests"],
                "exclude_paths": ["vendor", "fixtures/generated.json"],
                "suggested_commands": {
                    "lint": ["python3", "-m", "ruff", "check", "."],
                    "literal-argument": ["tool", "value;not-a-shell-command"],
                },
                "limits": limits,
            }
        )

        self.assertEqual("openai", config.provider)
        self.assertEqual("gpt-audit", config.model)
        self.assertEqual(("OPENAI_API_KEY", "OPENAI_ORG_ID"), config.provider_env)
        self.assertEqual(
            frozenset({AuditCategory.security, AuditCategory.tests}), config.categories
        )
        self.assertEqual(("vendor", "fixtures/generated.json"), config.exclude_paths)
        self.assertEqual(
            (
                SuggestedCommand(
                    name="lint",
                    argv=("python3", "-m", "ruff", "check", "."),
                ),
                SuggestedCommand(
                    name="literal-argument",
                    argv=("tool", "value;not-a-shell-command"),
                ),
            ),
            config.suggested_commands,
        )
        for name, value in limits.items():
            self.assertEqual(value, getattr(config.limits, name))
        self.assertEqual(HARD_LIMITS.cpu_count, config.limits.cpu_count)
        self.assertEqual(HARD_LIMITS.terminal_calls, config.limits.terminal_calls)

    def test_top_level_schema_is_exact_and_unknown_fields_are_rejected(self) -> None:
        invalid_values = (
            None,
            [],
            {},
            {"schema_version": True},
            {"schema_version": 1.0},
            {"schema_version": 0},
            {"schema_version": 2},
            {"schema_version": 1, "unknown": "field"},
        )
        for value in invalid_values:
            with self.subTest(value=value), self.assertRaises(AuditConfigError):
                parse_audit_config(value)

    def test_duplicate_json_fields_are_rejected_at_every_depth(self) -> None:
        documents = (
            b'{"schema_version":1,"schema_version":1}',
            b'{"schema_version":1,"limits":{"findings":1,"findings":1}}',
            b'{"schema_version":1,"suggested_commands":{"test":["a"],"test":["b"]}}',
        )
        for document in documents:
            with self.subTest(document=document):
                self.write_config_bytes(document)
                with self.assertRaises(AuditConfigError):
                    load_audit_config(self.state_dir)

    def test_invalid_utf8_and_non_finite_json_numbers_are_rejected(self) -> None:
        for document in (
            b'{"schema_version":1,"provider":"\xff"}',
            b'{"schema_version":1,"limits":{"findings":NaN}}',
            b'{"schema_version":1,"limits":{"findings":Infinity}}',
            b'{"schema_version":1,"limits":{"findings":-Infinity}}',
        ):
            with self.subTest(document=document):
                self.write_config_bytes(document)
                with self.assertRaises(AuditConfigError):
                    load_audit_config(self.state_dir)

        for value in (math.nan, math.inf, -math.inf):
            with self.subTest(value=value), self.assertRaises(AuditConfigError):
                parse_audit_config({"schema_version": 1, "limits": {"findings": value}})

    def test_provider_environment_names_are_unique_valid_and_bounded(self) -> None:
        self.assertEqual(
            ("A1", "B_2", "CREDENTIAL_3", "Z9"),
            parse_audit_config(
                {
                    "schema_version": 1,
                    "provider_env": ["A1", "B_2", "CREDENTIAL_3", "Z9"],
                }
            ).provider_env,
        )

        invalid_lists = (
            "OPENAI_API_KEY",
            ["A"],
            ["lowercase"],
            ["1STARTS_WITH_DIGIT"],
            ["HAS-HYPHEN"],
            ["OPENAI_API_KEY", "OPENAI_API_KEY"],
            ["A1", "B2", "C3", "D4", "E5"],
        )
        for values in invalid_lists:
            with self.subTest(values=values), self.assertRaises(AuditConfigError):
                parse_audit_config({"schema_version": 1, "provider_env": values})

    def test_image_must_be_a_sha256_digest_or_digest_qualified_reference(self) -> None:
        valid_images = (
            "sha256:" + "0" * 64,
            "audit@sha256:" + "1" * 64,
            "registry.example:5000/team/audit:3.11@sha256:" + "a" * 64,
        )
        for image in valid_images:
            with self.subTest(image=image):
                self.assertEqual(
                    image,
                    parse_audit_config({"schema_version": 1, "image": image}).image,
                )

        invalid_images = (
            "audit:latest",
            "audit@sha256:short",
            "audit@sha512:" + "a" * 64,
            "Audit@sha256:" + "a" * 64,
            "audit@sha256:" + "A" * 64,
            "audit @sha256:" + "a" * 64,
        )
        for image in invalid_images:
            with self.subTest(image=image), self.assertRaises(AuditConfigError):
                parse_audit_config({"schema_version": 1, "image": image})

    def test_categories_are_a_non_empty_unique_supported_subset(self) -> None:
        values = [category.value for category in AuditCategory]
        self.assertEqual(
            frozenset(AuditCategory),
            parse_audit_config({"schema_version": 1, "categories": values}).categories,
        )

        for categories in (
            [],
            "security",
            ["security", "security"],
            ["security", "unknown"],
            [True],
        ):
            with self.subTest(categories=categories), self.assertRaises(AuditConfigError):
                parse_audit_config({"schema_version": 1, "categories": categories})

    def test_exclusions_are_unique_confined_relative_posix_paths(self) -> None:
        valid = ["vendor", "nested/generated", "name with spaces"]
        self.assertEqual(
            tuple(valid),
            parse_audit_config({"schema_version": 1, "exclude_paths": valid}).exclude_paths,
        )

        invalid_paths = (
            "",
            ".",
            "..",
            "/absolute",
            "nested/./file",
            "nested/../file",
            "nested\\file",
            "nested/\x00file",
            ".git",
            "nested/.GIT/config",
        )
        for path in invalid_paths:
            with self.subTest(path=path), self.assertRaises(AuditConfigError):
                parse_audit_config({"schema_version": 1, "exclude_paths": [path]})

        with self.assertRaises(AuditConfigError):
            parse_audit_config({"schema_version": 1, "exclude_paths": ["vendor", "vendor"]})

    def test_suggested_commands_are_named_non_shell_argv_arrays(self) -> None:
        commands = {f"command-{index:02d}": ["tool", str(index)] for index in range(64)}
        config = parse_audit_config({"schema_version": 1, "suggested_commands": commands})
        self.assertEqual(64, len(config.suggested_commands))
        self.assertTrue(all(isinstance(item.argv, tuple) for item in config.suggested_commands))

        invalid_commands = (
            ["tool", "arg"],
            {"": ["tool"]},
            {"test": "tool --flag"},
            {"test": []},
            {"test": [1]},
            {"test": [""]},
            {"test": ["tool", "bad\x00arg"]},
            {f"command-{index}": ["tool"] for index in range(65)},
        )
        for commands_value in invalid_commands:
            with self.subTest(commands=commands_value), self.assertRaises(AuditConfigError):
                parse_audit_config({"schema_version": 1, "suggested_commands": commands_value})

    def test_every_configurable_limit_can_only_lower_its_hard_ceiling(self) -> None:
        for name, ceiling in CONFIGURABLE_LIMITS.items():
            with self.subTest(name=name, value=1):
                config = parse_audit_config({"schema_version": 1, "limits": {name: 1}})
                self.assertEqual(1, getattr(config.limits, name))
            with self.subTest(name=name, value=ceiling):
                config = parse_audit_config({"schema_version": 1, "limits": {name: ceiling}})
                self.assertEqual(ceiling, getattr(config.limits, name))
            for invalid in (0, -1, True, 1.0, ceiling + 1):
                with self.subTest(name=name, invalid=invalid), self.assertRaises(AuditConfigError):
                    parse_audit_config({"schema_version": 1, "limits": {name: invalid}})

    def test_non_configurable_and_unknown_limits_are_rejected(self) -> None:
        for name in ("cpu_count", "terminal_calls", "unknown"):
            with self.subTest(name=name), self.assertRaises(AuditConfigError):
                parse_audit_config({"schema_version": 1, "limits": {name: 1}})

    def test_nested_field_types_and_unknown_fields_are_rejected(self) -> None:
        invalid_values = (
            {"provider": 1},
            {"model": False},
            {"provider_env": None},
            {"image": None},
            {"categories": None},
            {"exclude_paths": None},
            {"suggested_commands": None},
            {"limits": None},
        )
        for fields in invalid_values:
            with self.subTest(fields=fields), self.assertRaises(AuditConfigError):
                parse_audit_config({"schema_version": 1, **fields})

    def test_parse_returns_the_declared_configuration_model(self) -> None:
        config = parse_audit_config({"schema_version": 1})
        self.assertIsInstance(config, AuditConfig)


if __name__ == "__main__":
    unittest.main()
