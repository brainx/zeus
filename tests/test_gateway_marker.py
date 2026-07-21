from __future__ import annotations

import hashlib
import inspect
import json
import math
import unittest
from dataclasses import FrozenInstanceError
from typing import Any

from zeus.gateway_marker import (
    GatewayGeneration,
    GatewayLaunchMarker,
    GatewayRuntimeMarker,
    MarkerValidationError,
    command_fingerprint,
    is_compat_runtime_marker,
    is_owned_runtime_marker,
    parse_launch_marker,
    parse_runtime_marker,
    readiness_probe_from_payload,
    readiness_probe_to_payload,
)
from zeus.readiness import ReadinessProbe


def _probe_payload() -> dict[str, object]:
    return {
        "url": "http://127.0.0.1:4312/health",
        "expected_status": "ok",
        "expected_platform": "hermes",
        "timeout_seconds": 10,
        "interval_seconds": 0.25,
    }


def _launch_payload(*, probe: object = ...) -> dict[str, object]:
    argv = ["/opt/hermes/bin/hermes", "-p", "coder", "gateway", "run"]
    return {
        "schema": 3,
        "bot_id": "coder",
        "component": "gateway",
        "action": "run",
        "operation_id": "a" * 32,
        "desired_revision": 7,
        "argv": argv,
        "resolved_hermes_bin": argv[0],
        "command_fingerprint": command_fingerprint(argv),
        "readiness_probe": _probe_payload() if probe is ... else probe,
    }


def _runtime_payload(*, include_start_fingerprint: bool = True) -> dict[str, object]:
    payload = _launch_payload()
    payload.update({"pid": 4321, "started_at": 1_780_000_000})
    if include_start_fingerprint:
        payload["proc_start_fingerprint"] = "linux:/proc-starttime:987654321"
    return payload


class GatewayMarkerTests(unittest.TestCase):
    def assert_marker_error(self, expected: str, payload: object, *, runtime: bool = False) -> None:
        parser = parse_runtime_marker if runtime else parse_launch_marker
        with self.assertRaisesRegex(MarkerValidationError, f"^{expected}$"):
            parser(payload)

    def test_launch_and_runtime_round_trip_as_immutable_models(self) -> None:
        launch_payload = _launch_payload()
        expected_launch_payload = _launch_payload()
        launch = parse_launch_marker(launch_payload)

        self.assertIsInstance(launch, GatewayLaunchMarker)
        self.assertIs(type(launch.argv), tuple)
        self.assertEqual(launch_payload, launch.to_payload())
        with self.assertRaises(FrozenInstanceError):
            launch.bot_id = "other"  # type: ignore[misc]

        source_argv = launch_payload["argv"]
        source_probe = launch_payload["readiness_probe"]
        assert isinstance(source_argv, list)
        assert isinstance(source_probe, dict)
        source_argv[0] = "/tmp/source-was-mutated"
        source_probe["url"] = "http://localhost:1/source-was-mutated"
        self.assertEqual(expected_launch_payload, launch.to_payload())

        first = launch.to_payload()
        second = launch.to_payload()
        self.assertIsNot(first, second)
        self.assertIsNot(first["argv"], second["argv"])
        self.assertIsNot(first["readiness_probe"], second["readiness_probe"])
        first_argv = first["argv"]
        first_probe = first["readiness_probe"]
        assert isinstance(first_argv, list)
        assert isinstance(first_probe, dict)
        first_argv[0] = "/tmp/replaced"
        first_probe["url"] = "http://localhost:1/replaced"
        self.assertEqual(expected_launch_payload, launch.to_payload())

        runtime_payload = _runtime_payload()
        runtime = parse_runtime_marker(runtime_payload)
        self.assertIsInstance(runtime, GatewayRuntimeMarker)
        self.assertEqual(runtime_payload, runtime.to_payload())
        self.assertEqual(
            GatewayGeneration(
                operation_id="a" * 32,
                desired_revision=7,
                pid=4321,
                command_fingerprint=str(runtime_payload["command_fingerprint"]),
                proc_start_fingerprint="linux:/proc-starttime:987654321",
            ),
            runtime.generation(),
        )

        without_start = _runtime_payload(include_start_fingerprint=False)
        parsed_without_start = parse_runtime_marker(without_start)
        self.assertEqual(without_start, parsed_without_start.to_payload())
        self.assertIsNone(parsed_without_start.generation().proc_start_fingerprint)

    def test_command_fingerprint_uses_canonical_utf8_json(self) -> None:
        argv = ["/opt/hérmes", "-p", "coder", "gateway", "run"]
        expected = hashlib.sha256(
            json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        self.assertEqual(expected, command_fingerprint(argv))

    def test_parsers_require_exact_launch_runtime_and_probe_key_sets(self) -> None:
        self.assert_marker_error("marker must be an object", [])
        with self.assertRaises(MarkerValidationError):
            parse_runtime_marker([])

        launch = _launch_payload()
        for key in tuple(launch):
            invalid = dict(launch)
            del invalid[key]
            with self.subTest(kind="launch-missing", key=key):
                self.assert_marker_error("marker has invalid keys", invalid)
        with_extra = dict(launch, extra=True)
        self.assert_marker_error("marker has invalid keys", with_extra)

        runtime = _runtime_payload()
        for key in tuple(runtime):
            invalid = dict(runtime)
            del invalid[key]
            if key == "proc_start_fingerprint":
                self.assertEqual(
                    _runtime_payload(include_start_fingerprint=False),
                    parse_runtime_marker(invalid).to_payload(),
                )
            else:
                with self.subTest(kind="runtime-missing", key=key):
                    self.assert_marker_error(
                        "runtime marker has invalid keys", invalid, runtime=True
                    )
        self.assert_marker_error(
            "runtime marker has invalid keys", dict(runtime, extra=True), runtime=True
        )

        invalid_probe = _launch_payload()
        probe = _probe_payload()
        del probe["interval_seconds"]
        invalid_probe["readiness_probe"] = probe
        self.assert_marker_error("readiness_probe has invalid keys", invalid_probe)

    def test_launch_parser_rejects_invalid_intent_correlation_and_bool_integers(self) -> None:
        cases: tuple[tuple[str, str, object], ...] = (
            ("schema-bool", "schema", True),
            ("schema-old", "schema", 2),
            ("component", "component", "worker"),
            ("action", "action", "stop"),
            ("operation-uppercase", "operation_id", "A" * 32),
            ("operation-length", "operation_id", "a" * 31),
            ("revision-bool", "desired_revision", True),
            ("revision-zero", "desired_revision", 0),
            ("revision-large", "desired_revision", 2**63),
        )
        expected = {
            "schema-bool": "marker schema is invalid",
            "schema-old": "marker schema is invalid",
            "component": "marker command intent is invalid",
            "action": "marker command intent is invalid",
            "operation-uppercase": "operation_id is invalid",
            "operation-length": "operation_id is invalid",
            "revision-bool": "desired_revision is invalid",
            "revision-zero": "desired_revision is invalid",
            "revision-large": "desired_revision is invalid",
        }
        for name, key, value in cases:
            payload = _launch_payload()
            payload[key] = value
            with self.subTest(name=name):
                self.assert_marker_error(expected[name], payload)

    def test_runtime_parser_rejects_invalid_pid_time_and_start_fingerprint(self) -> None:
        cases: tuple[tuple[str, str, object, str], ...] = (
            ("pid-bool", "pid", True, "marker PID is invalid"),
            ("pid-zero", "pid", 0, "marker PID is invalid"),
            ("started-bool", "started_at", True, "marker started_at is invalid"),
            ("started-zero", "started_at", 0, "marker started_at is invalid"),
            ("started-nan", "started_at", math.nan, "marker started_at is invalid"),
            ("started-inf", "started_at", math.inf, "marker started_at is invalid"),
            (
                "start-null",
                "proc_start_fingerprint",
                None,
                "process start fingerprint is invalid",
            ),
            (
                "start-non-string",
                "proc_start_fingerprint",
                123,
                "process start fingerprint is invalid",
            ),
            (
                "start-empty",
                "proc_start_fingerprint",
                "",
                "process start fingerprint is invalid",
            ),
            (
                "start-long",
                "proc_start_fingerprint",
                "x" * 513,
                "process start fingerprint is invalid",
            ),
        )
        for name, key, value, error in cases:
            payload = _runtime_payload()
            payload[key] = value
            with self.subTest(name=name):
                self.assert_marker_error(error, payload, runtime=True)

    def test_parser_rejects_invalid_argv_path_and_fingerprint(self) -> None:
        cases: list[tuple[str, dict[str, object], str]] = []

        not_a_list = _launch_payload()
        not_a_list["argv"] = tuple(not_a_list["argv"])  # type: ignore[arg-type]
        cases.append(("argv-type", not_a_list, "argv must be a bounded non-empty list"))

        empty_argv = _launch_payload()
        empty_argv["argv"] = []
        cases.append(("argv-empty", empty_argv, "argv must be a bounded non-empty list"))

        too_many_parts = _launch_payload()
        too_many_parts["argv"] = ["x"] * 65
        cases.append(("argv-too-many", too_many_parts, "argv must be a bounded non-empty list"))

        empty_part = _launch_payload()
        empty_part["argv"] = ["/opt/hermes/bin/hermes", "", "coder", "gateway", "run"]
        cases.append(
            ("argv-empty-part", empty_part, "argv item must be a bounded non-empty string")
        )

        nul_part = _launch_payload()
        nul_part["argv"] = ["/opt/hermes/bin/hermes\0", "-p", "coder", "gateway", "run"]
        cases.append(("argv-nul-part", nul_part, "argv item must be a bounded non-empty string"))

        oversized_part = _launch_payload()
        oversized_part["argv"] = ["x" * (16 * 1024 + 1)]
        cases.append(
            (
                "argv-oversized-part",
                oversized_part,
                "argv item must be a bounded non-empty string",
            )
        )

        oversized_argv = _launch_payload()
        oversized_argv["argv"] = ["x" * 14_000] * 5
        cases.append(("argv-total-bytes", oversized_argv, "argv is too large"))

        wrong_command = _launch_payload()
        wrong_command["argv"] = ["/opt/hermes/bin/hermes", "-p", "coder", "gateway", "stop"]
        cases.append(("argv-command", wrong_command, "argv is not a Hermes gateway command"))

        wrong_profile = _launch_payload()
        wrong_profile["argv"] = [
            "/opt/hermes/bin/hermes",
            "-p",
            "other",
            "gateway",
            "run",
        ]
        cases.append(("argv-profile", wrong_profile, "argv is not a Hermes gateway command"))

        non_absolute = _launch_payload()
        non_absolute["resolved_hermes_bin"] = "hermes"
        cases.append(
            (
                "relative-path",
                non_absolute,
                "resolved_hermes_bin must be an absolute path without traversal",
            )
        )

        traversal = _launch_payload()
        traversal["resolved_hermes_bin"] = "/opt/hermes/../bin/hermes"
        cases.append(
            (
                "traversal",
                traversal,
                "resolved_hermes_bin must be an absolute path without traversal",
            )
        )

        mismatched_path = _launch_payload()
        mismatched_path["resolved_hermes_bin"] = "/usr/bin/hermes"
        cases.append(
            (
                "path-mismatch",
                mismatched_path,
                "exec argv does not use the resolved Hermes binary",
            )
        )

        invalid_fingerprint = _launch_payload()
        invalid_fingerprint["command_fingerprint"] = "f" * 64
        cases.append(
            ("fingerprint-mismatch", invalid_fingerprint, "command fingerprint is invalid")
        )

        for name, payload, error in cases:
            with self.subTest(name=name):
                self.assert_marker_error(error, payload)

    def test_resolved_path_comparison_preserves_baseline_lexical_normalization(self) -> None:
        for resolved_path in (
            "/opt//hermes/bin/hermes",
            "/opt/./hermes/bin/hermes",
            "/opt/hermes/bin/hermes/",
        ):
            with self.subTest(kind="canonical-argv", resolved_path=resolved_path):
                payload = _launch_payload()
                payload["resolved_hermes_bin"] = resolved_path
                parsed = parse_launch_marker(payload)
                self.assertEqual(resolved_path, parsed.resolved_hermes_bin)
                self.assertEqual(resolved_path, parsed.to_payload()["resolved_hermes_bin"])

            with self.subTest(kind="noncanonical-argv", resolved_path=resolved_path):
                payload = _launch_payload()
                argv = payload["argv"]
                assert isinstance(argv, list)
                argv[0] = resolved_path
                payload["resolved_hermes_bin"] = resolved_path
                payload["command_fingerprint"] = command_fingerprint(argv)
                self.assert_marker_error(
                    "exec argv does not use the resolved Hermes binary", payload
                )

    def test_readiness_conversion_round_trips_and_validates_the_contract(self) -> None:
        payload = _probe_payload()
        probe = readiness_probe_from_payload(payload)

        self.assertIsInstance(probe, ReadinessProbe)
        self.assertEqual(payload, readiness_probe_to_payload(probe))
        self.assertIsNone(readiness_probe_from_payload(None))
        self.assertIsNone(readiness_probe_to_payload(None))

        invalid_cases: tuple[tuple[str, object], ...] = (
            ("non-object", []),
            ("https", dict(payload, url="https://127.0.0.1:4312/health")),
            ("remote", dict(payload, url="http://example.com/health")),
            ("credentials", dict(payload, url="http://user@localhost:4312/health")),
            ("query", dict(payload, url="http://localhost:4312/health?secret=yes")),
            ("fragment", dict(payload, url="http://localhost:4312/health#fragment")),
            ("empty-status", dict(payload, expected_status="")),
            ("empty-platform", dict(payload, expected_platform="")),
            ("bool-timeout", dict(payload, timeout_seconds=True)),
            ("zero-interval", dict(payload, interval_seconds=0)),
            ("nan-timeout", dict(payload, timeout_seconds=math.nan)),
            ("infinite-timeout", dict(payload, timeout_seconds=math.inf)),
            ("large-timeout", dict(payload, timeout_seconds=3600.1)),
        )
        for name, invalid in invalid_cases:
            with self.subTest(name=name), self.assertRaises(MarkerValidationError):
                readiness_probe_from_payload(invalid)

        strict_cases = (
            ("url-nul", "url", "http://localhost:4312/health\0", "readiness URL"),
            ("url-long", "url", "http://localhost/" + "x" * 2049, "readiness URL"),
            ("status-long", "expected_status", "x" * 129, "expected status"),
            ("platform-nul", "expected_platform", "hermes\0agent", "expected platform"),
        )
        for name, key, value, error_prefix in strict_cases:
            marker_payload = _launch_payload()
            marker_probe = marker_payload["readiness_probe"]
            assert isinstance(marker_probe, dict)
            marker_probe[key] = value
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(
                    MarkerValidationError, f"^{error_prefix} must be a bounded non-empty string$"
                ),
            ):
                parse_launch_marker(marker_payload)

    def test_strict_parsers_reject_compat_markers_while_recognizer_accepts_them(self) -> None:
        schema2 = _runtime_payload()
        schema2["schema"] = 2
        schemaless = _runtime_payload()
        del schemaless["schema"]
        explicit_null = _runtime_payload()
        explicit_null["schema"] = None

        for name, payload in (
            ("schema2", schema2),
            ("schemaless", schemaless),
            ("explicit-null", explicit_null),
        ):
            with self.subTest(name=name):
                with self.assertRaises(MarkerValidationError):
                    parse_runtime_marker(payload)
                self.assertTrue(is_compat_runtime_marker(payload))

        self.assertFalse(is_compat_runtime_marker(_runtime_payload()))
        self.assertFalse(is_compat_runtime_marker([]))
        self.assertFalse(is_compat_runtime_marker({"schema": True}))

    def test_owned_runtime_check_matches_full_schema_and_generation(self) -> None:
        payload = _runtime_payload()
        expected: dict[str, Any] = {
            "bot_id": "coder",
            "operation_id": "a" * 32,
            "desired_revision": 7,
            "pid": 4321,
            "expected_fingerprint": payload["command_fingerprint"],
        }
        self.assertTrue(is_owned_runtime_marker(payload, **expected))

        mismatches = {
            "bot_id": "other",
            "operation_id": "b" * 32,
            "desired_revision": 8,
            "pid": 4322,
            "expected_fingerprint": "f" * 64,
        }
        for key, value in mismatches.items():
            call = dict(expected)
            call[key] = value
            with self.subTest(key=key):
                self.assertFalse(is_owned_runtime_marker(payload, **call))

        malformed = dict(payload, started_at=math.nan)
        self.assertFalse(is_owned_runtime_marker(malformed, **expected))

    def test_gateway_launcher_keeps_fingerprint_and_ownership_compatibility_exports(self) -> None:
        from zeus.gateway_launcher import (
            _is_owned_runtime_marker as launcher_is_owned_runtime_marker,
        )
        from zeus.gateway_launcher import command_fingerprint as launcher_command_fingerprint

        self.assertIs(command_fingerprint, launcher_command_fingerprint)
        self.assertEqual(
            inspect.signature(is_owned_runtime_marker),
            inspect.signature(launcher_is_owned_runtime_marker),
        )
        payload = _runtime_payload()
        arguments: dict[str, Any] = {
            "bot_id": "coder",
            "operation_id": "a" * 32,
            "desired_revision": 7,
            "pid": 4321,
            "expected_fingerprint": str(payload["command_fingerprint"]),
        }
        self.assertEqual(
            is_owned_runtime_marker(payload, **arguments),
            launcher_is_owned_runtime_marker(payload, **arguments),
        )

    def test_launcher_preserves_marker_bytes_and_validation_precedence(self) -> None:
        from zeus.gateway_launcher import LaunchPayloadError, _validate_payload

        marker = _launch_payload()
        marker_argv = marker["argv"]
        assert isinstance(marker_argv, list)
        root_payload: dict[str, object] = {
            "profile_path": "/opt/hermes/profiles/coder",
            "marker_path": "/opt/hermes/profiles/coder/logs/zeus-gateway.pid.json",
            "marker": marker,
            "argv": list(marker_argv),
            "env": {"HERMES_HOME": "/opt/hermes", "PATH": "/usr/bin"},
        }
        _profile, validated_marker, _argv, _env = _validate_payload(root_payload)
        self.assertEqual(marker, validated_marker)
        runtime_marker = dict(validated_marker)
        runtime_marker.update(
            {
                "pid": 4321,
                "started_at": 1_780_000_000,
                "proc_start_fingerprint": "linux:/proc-starttime:123",
            }
        )
        marker_bytes = (
            json.dumps(runtime_marker, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        self.assertEqual(
            b'{"action":"run","argv":["/opt/hermes/bin/hermes","-p","coder",'
            b'"gateway","run"],"bot_id":"coder","command_fingerprint":'
            b'"7d203f8c4831e34eccfed055c8a8b82f9d68601ed15135a68dfde76c32a55321",'
            b'"component":"gateway","desired_revision":7,"operation_id":'
            b'"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pid":4321,"proc_start_fingerprint":'
            b'"linux:/proc-starttime:123","readiness_probe":{"expected_platform":'
            b'"hermes","expected_status":"ok","interval_seconds":0.25,'
            b'"timeout_seconds":10,"url":"http://127.0.0.1:4312/health"},'
            b'"resolved_hermes_bin":"/opt/hermes/bin/hermes","schema":3,'
            b'"started_at":1780000000}\n',
            marker_bytes,
        )
        self.assertNotIn(b"private", marker_bytes)

        boundary_first: Any = json.loads(json.dumps(root_payload))
        boundary_first["profile_path"] = "/opt/hermes/profiles/other"
        boundary_first["marker_path"] = "/opt/hermes/profiles/other/logs/zeus-gateway.pid.json"
        boundary_first["marker"]["schema"] = 2
        with self.assertRaisesRegex(
            LaunchPayloadError, "^profile_path is outside the bot profile boundary$"
        ):
            _validate_payload(boundary_first)

        mismatch_first: Any = json.loads(json.dumps(root_payload))
        mismatch_first["marker"]["argv"][-1] = "stop"
        with self.assertRaisesRegex(LaunchPayloadError, "^marker argv does not match exec argv$"):
            _validate_payload(mismatch_first)

        outer_argv_first: Any = json.loads(json.dumps(root_payload))
        outer_argv_first["argv"] = "not-a-list"
        outer_argv_first["marker"]["argv"][-1] = "stop"
        with self.assertRaisesRegex(LaunchPayloadError, "^argv must be a bounded non-empty list$"):
            _validate_payload(outer_argv_first)

    def test_supervisor_keeps_generation_compatibility_and_loose_readiness_adapter(self) -> None:
        from zeus.supervisor import (
            Supervisor,
            _GatewayGeneration,
            _readiness_probe_from_marker,
            _readiness_probe_marker_payload,
        )

        self.assertIs(GatewayGeneration, _GatewayGeneration)
        self.assertTrue(Supervisor._is_compat_runtime_marker({"schema": 2}))
        self.assertTrue(Supervisor._is_compat_runtime_marker({}))
        compatible_probe = dict(_probe_payload(), legacy_extra="preserved compatibility")
        parsed_probe = _readiness_probe_from_marker(compatible_probe)
        self.assertIsInstance(parsed_probe, ReadinessProbe)
        self.assertEqual(_probe_payload(), _readiness_probe_marker_payload(parsed_probe))


if __name__ == "__main__":
    unittest.main()
