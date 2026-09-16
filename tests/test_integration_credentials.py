from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from typing import Any
from unittest.mock import patch

from zeus.config import Settings, validate_api_exposure
from zeus.integration_auth import (
    INTEGRATION_PERMISSIONS,
    MAX_CONFIG_BYTES,
    IntegrationCredential,
    authenticate_api_key,
    load_integration_credentials,
)
from zeus.private_io import read_private_bytes

_OBSERVER_KEY = "observer-test-key-" + "1" * 32
_OPERATOR_KEY = "operator-test-key-" + "2" * 32
_ADMIN_KEY = "administrator-test-key-" + "3" * 32


class IntegrationCredentialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.path = self.root / "integrations.json"
        self.env = {
            "ZEUS_API_INTEGRATIONS_FILE": str(self.path),
            "ZEUS_API_KEY": _ADMIN_KEY,
            "OBSERVER_KEY": _OBSERVER_KEY,
            "OPERATOR_KEY": _OPERATOR_KEY,
        }

    def write(self, payload: Any) -> None:
        self.path.write_text(json.dumps(payload), encoding="utf-8")
        self.path.chmod(0o600)

    def payload(self, **overrides: Any) -> dict[str, Any]:
        return {
            "version": 1,
            "integrations": [
                {"id": "olymp", "key_env": "OBSERVER_KEY", "permissions": ["observer"], **overrides}
            ],
        }

    def load(self) -> tuple[IntegrationCredential, ...]:
        return load_integration_credentials(self.env, admin_key=_ADMIN_KEY)

    def settings(self) -> Settings:
        return Settings.from_env(self.env, include_dotenv=False)

    def assert_invalid(self, payload: Any) -> None:
        self.write(payload)
        with self.assertRaises(ValueError) as raised:
            self.load()
        self.assertNotIn(_OBSERVER_KEY, str(raised.exception))
        self.assertNotIn(_ADMIN_KEY, str(raised.exception))

    def test_no_file_preserves_legacy_configuration(self) -> None:
        for env in ({}, {"ZEUS_API_INTEGRATIONS_FILE": ""}):
            with self.subTest(env=env):
                settings = Settings.from_env(env, include_dotenv=False)
                self.assertEqual((), settings.api_integrations)
        principal = authenticate_api_key(_ADMIN_KEY, _ADMIN_KEY, ())
        self.assertIsNotNone(principal)
        assert principal is not None
        self.assertEqual("admin", principal.integration_id)
        self.assertTrue(principal.administrator)
        self.assertEqual(INTEGRATION_PERMISSIONS, principal.permissions)

    def test_named_permissions_are_independent_and_identity_comes_from_matching_key(self) -> None:
        payload = self.payload()
        payload["integrations"].append(
            {"id": "controller", "key_env": "OPERATOR_KEY", "permissions": ["operator"]}
        )
        self.write(payload)
        credentials = self.settings().api_integrations
        for key, identifier, permission in (
            (_OBSERVER_KEY, "olymp", "observer"),
            (_OPERATOR_KEY, "controller", "operator"),
        ):
            with self.subTest(identifier=identifier):
                principal = authenticate_api_key(key, _ADMIN_KEY, credentials)
                self.assertIsNotNone(principal)
                assert principal is not None
                self.assertEqual(identifier, principal.integration_id)
                self.assertEqual(frozenset({permission}), principal.permissions)
                self.assertFalse(principal.administrator)
        self.assertIsNone(authenticate_api_key("olymp", _ADMIN_KEY, credentials))

    def test_authentication_checks_all_configured_keys_even_after_matching(self) -> None:
        credentials = (
            IntegrationCredential("olymp", _OBSERVER_KEY, frozenset({"observer"})),
            IntegrationCredential("controller", _OPERATOR_KEY, frozenset({"operator"})),
        )
        import hmac

        with patch(
            "zeus.integration_auth.hmac.compare_digest", wraps=hmac.compare_digest
        ) as compare:
            principal = authenticate_api_key(_OBSERVER_KEY, _ADMIN_KEY, credentials)
        self.assertIsNotNone(principal)
        self.assertEqual(3, compare.call_count)

    def test_invalid_or_missing_keys_never_authenticate(self) -> None:
        self.write(self.payload())
        for provided in ("", "not-a-key", "☃", _OBSERVER_KEY + " "):
            with self.subTest(provided_length=len(provided)):
                self.assertIsNone(authenticate_api_key(provided, _ADMIN_KEY, self.load()))
        self.assertIsNone(authenticate_api_key(_OBSERVER_KEY, None, ()))

    def test_named_credentials_can_be_used_without_a_legacy_key_on_loopback(self) -> None:
        self.write(self.payload())
        self.env.pop("ZEUS_API_KEY")
        settings = self.settings()
        self.assertIsNotNone(authenticate_api_key(_OBSERVER_KEY, None, settings.api_integrations))
        validate_api_exposure("127.0.0.1", settings.api_key, False)
        with self.assertRaisesRegex(ValueError, "requires ZEUS_API_KEY"):
            validate_api_exposure("0.0.0.0", settings.api_key, False)

    def test_secrets_are_excluded_from_credentials_and_settings_repr(self) -> None:
        self.write(self.payload())
        settings = self.settings()
        for value in (settings, settings.api_integrations, settings.api_integrations[0]):
            self.assertNotIn(_OBSERVER_KEY, repr(value))
            self.assertNotIn(_ADMIN_KEY, repr(value))
        with self.assertRaises(FrozenInstanceError):
            settings.api_integrations[0].key = _OPERATOR_KEY  # type: ignore[misc]
        principal = authenticate_api_key(_OBSERVER_KEY, _ADMIN_KEY, settings.api_integrations)
        assert principal is not None
        with self.assertRaises(FrozenInstanceError):
            principal.integration_id = "admin"  # type: ignore[misc]

    def test_environment_values_override_dotenv_in_same_mapping(self) -> None:
        self.write(self.payload())
        dotenv = {**self.env, "OBSERVER_KEY": _OPERATOR_KEY}
        with patch("zeus.config.load_dotenv", return_value=dotenv):
            settings = Settings.from_env({"OBSERVER_KEY": _OBSERVER_KEY})
        self.assertEqual(_OBSERVER_KEY, settings.api_integrations[0].key)

    def test_loaded_credentials_do_not_hot_reload_configuration_or_environment(self) -> None:
        self.write(self.payload())
        settings = self.settings()
        self.write(self.payload(id="replacement", permissions=["operator"]))
        self.env["OBSERVER_KEY"] = _OPERATOR_KEY
        principal = authenticate_api_key(_OBSERVER_KEY, _ADMIN_KEY, settings.api_integrations)
        self.assertIsNotNone(principal)
        assert principal is not None
        self.assertEqual("olymp", principal.integration_id)
        self.assertEqual(frozenset({"observer"}), principal.permissions)

    def test_strict_root_and_entry_fields_and_version(self) -> None:
        for payload in (
            [],
            {},
            {**self.payload(), "extra": _OBSERVER_KEY},
            {**self.payload(), "version": True},
            {**self.payload(), "version": 1.0},
            {**self.payload(), "version": 2},
            {**self.payload(), "integrations": {}},
            {**self.payload(), "integrations": [None]},
            self.payload(key=_OBSERVER_KEY),
            {"version": 1, "integrations": [{"id": "olymp", "permissions": ["observer"]}]},
        ):
            with self.subTest(payload_type=type(payload).__name__):
                self.assert_invalid(payload)

    def test_unknown_empty_duplicate_or_non_string_permissions_are_rejected(self) -> None:
        for permissions in (
            [],
            ["admin"],
            ["observer", "observer"],
            ["observer", None],
            [1],
            "observer",
            None,
        ):
            with self.subTest(permissions=permissions):
                self.assert_invalid(self.payload(permissions=permissions))

    def test_explicit_combined_permissions_are_allowed(self) -> None:
        self.write(self.payload(permissions=sorted(INTEGRATION_PERMISSIONS)))
        self.assertEqual(INTEGRATION_PERMISSIONS, self.load()[0].permissions)

    def test_integration_id_is_bounded_ascii_and_admin_is_reserved(self) -> None:
        for identifier in ("", "admin", "Admin", "OlYmP", "é", "0lymp", "a b", "a" * 65, None):
            with self.subTest(identifier=identifier):
                self.assert_invalid(self.payload(id=identifier))
        self.write(self.payload(id="a" + "_b-" * 21))
        self.assertEqual(64, len(self.load()[0].integration_id))

    def test_missing_empty_and_malformed_key_environment_references_are_rejected(self) -> None:
        for key_env in ("", "MISSING", "lowercase", "BAD-NAME", "A" * 129, None):
            with self.subTest(key_env=key_env):
                self.assert_invalid(self.payload(key_env=key_env))
        self.env["OBSERVER_KEY"] = ""
        self.assert_invalid(self.payload())

    def test_named_key_length_and_printable_non_space_ascii_are_enforced(self) -> None:
        for key in (
            "a" * 31,
            "a" * 513,
            "a" * 31 + " ",
            "a" * 31 + "\n",
            "a" * 31 + "\0",
            "a" * 31 + "\t",
            "a" * 31 + "\x7f",
            "a" * 31 + "é",
        ):
            with self.subTest(length=len(key)):
                self.env["OBSERVER_KEY"] = key
                self.assert_invalid(self.payload())
        for length in (32, 512):
            self.env["OBSERVER_KEY"] = "!" * length
            self.write(self.payload())
            self.assertEqual(length, len(self.load()[0].key))

    def test_duplicate_ids_key_environment_names_and_key_values_are_rejected(self) -> None:
        for entry in (
            {"id": "olymp", "key_env": "OPERATOR_KEY", "permissions": ["operator"]},
            {"id": "other", "key_env": "OBSERVER_KEY", "permissions": ["operator"]},
            {"id": "other", "key_env": "ALIAS_KEY", "permissions": ["operator"]},
        ):
            self.env["ALIAS_KEY"] = _OBSERVER_KEY
            payload = self.payload()
            payload["integrations"].append(entry)
            self.assert_invalid(payload)

    def test_named_key_cannot_alias_the_administrator_key(self) -> None:
        self.env["OBSERVER_KEY"] = _ADMIN_KEY
        self.assert_invalid(self.payload())

    def test_settings_construction_revalidates_integration_collection_and_collisions(self) -> None:
        settings = Settings.from_env({"ZEUS_API_KEY": _ADMIN_KEY}, include_dotenv=False)
        credential = IntegrationCredential("olymp", _OBSERVER_KEY, frozenset({"observer"}))
        for credentials in (
            [credential],
            (None,),
            (credential, credential),
            (credential, replace(credential, integration_id="other")),
            (replace(credential, key=_ADMIN_KEY),),
            (credential,) * 33,
        ):
            with (
                self.subTest(collection_type=type(credentials).__name__),
                self.assertRaises(ValueError),
            ):
                replace(settings, api_integrations=credentials)  # type: ignore[arg-type]

    def test_direct_credentials_reject_mutable_or_unknown_permissions(self) -> None:
        for permissions in ({"observer"}, frozenset(), frozenset({"admin"})):
            with self.subTest(permissions=permissions), self.assertRaises(ValueError):
                IntegrationCredential("olymp", _OBSERVER_KEY, permissions)  # type: ignore[arg-type]

    def test_integration_count_is_bounded_and_explicit_empty_files_are_rejected(self) -> None:
        for count in (0, 32, 33):
            payload: dict[str, Any] = {"version": 1, "integrations": []}
            for index in range(count):
                key_env = f"INTEGRATION_{index}"
                self.env[key_env] = f"test-key-{index:02d}-" + "x" * 32
                payload["integrations"].append(
                    {"id": f"node-{index}", "key_env": key_env, "permissions": ["observer"]}
                )
            self.write(payload)
            if count == 32:
                self.assertEqual(32, len(self.load()))
            else:
                with self.assertRaises(ValueError):
                    self.load()

    def test_duplicate_json_keys_malformed_json_and_non_json_constants_are_rejected(self) -> None:
        for raw in (
            '{"version":1,"version":1,"integrations":[]}',
            '{"version":1,"integrations":[{"id":"one","id":"two"}]}',
            '{"version":NaN,"integrations":[]}',
            '{"version":Infinity,"integrations":[]}',
            '{"version":',
            '["' + _OBSERVER_KEY + '"',
            "[" * 2000,
        ):
            self.path.write_text(raw, encoding="utf-8")
            self.path.chmod(0o600)
            with self.assertRaises(ValueError) as raised:
                self.load()
            self.assertNotIn(_OBSERVER_KEY, str(raised.exception))
            self.assertTrue(raised.exception.__suppress_context__)

    def test_private_read_is_bounded_and_does_not_tighten_permissions(self) -> None:
        self.write(self.payload())
        with patch("zeus.integration_auth.read_private_bytes", wraps=read_private_bytes) as read:
            self.load()
        read.assert_called_once_with(self.path, MAX_CONFIG_BYTES, tighten=False)
        for mode in (0o644, 0o400):
            self.path.chmod(mode)
            with self.assertRaises(ValueError):
                self.load()
            self.assertEqual(mode, stat.S_IMODE(self.path.stat().st_mode))

    def test_configuration_parent_must_be_private_without_permission_changes(self) -> None:
        self.write(self.payload())
        self.root.chmod(0o755)
        with self.assertRaises(ValueError):
            self.load()
        self.assertEqual(0o755, stat.S_IMODE(self.root.stat().st_mode))

    def test_config_file_rejects_symlinks_hardlinks_and_wrong_owner(self) -> None:
        self.write(self.payload())
        link = self.root / "symlink.json"
        link.symlink_to(self.path)
        self.env["ZEUS_API_INTEGRATIONS_FILE"] = str(link)
        with self.assertRaises(ValueError):
            self.load()
        self.env["ZEUS_API_INTEGRATIONS_FILE"] = str(self.path)
        hardlink = self.root / "hardlink.json"
        os.link(self.path, hardlink)
        with self.assertRaises(ValueError):
            self.load()
        hardlink.unlink()
        original_fstat = os.fstat

        def wrong_owner(fd: int) -> os.stat_result:
            snapshot = original_fstat(fd)
            if stat.S_ISREG(snapshot.st_mode):
                fields = list(snapshot)
                fields[4] = snapshot.st_uid + 1
                return os.stat_result(fields)
            return snapshot

        with (
            patch("zeus.private_io_core.os.fstat", side_effect=wrong_owner),
            self.assertRaises(ValueError),
        ):
            self.load()

    def test_config_path_does_not_resolve_parent_symlinks(self) -> None:
        self.write(self.payload())
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        self.env["ZEUS_API_INTEGRATIONS_FILE"] = str(alias / self.path.name)
        with self.assertRaises(ValueError):
            self.load()

    def test_utf8_size_and_missing_file_errors_are_sanitized(self) -> None:
        with self.assertRaises(ValueError) as raised:
            self.load()
        self.assertNotIn(str(self.root), str(raised.exception))
        for raw in (b"\xff", b" " * (MAX_CONFIG_BYTES + 1)):
            self.path.write_bytes(raw)
            self.path.chmod(0o600)
            with self.assertRaises(ValueError):
                self.load()
        raw = json.dumps(self.payload()).encode()
        self.path.write_bytes(raw + b" " * (MAX_CONFIG_BYTES - len(raw)))
        self.assertEqual("olymp", self.load()[0].integration_id)


if __name__ == "__main__":
    unittest.main()
