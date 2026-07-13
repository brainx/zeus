from __future__ import annotations

import hashlib
import http.client
import json
import math
import sqlite3
import tempfile
import threading
import time
import unittest
from collections import UserDict
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import IntEnum, StrEnum
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import zeus.api as api_module
from zeus.api import _process_idempotency_owner_id, make_handler
from zeus.config import Settings
from zeus.errors import ZeusConflictError
from zeus.idempotency import (
    IdempotencyClaim,
    canonical_request_hash,
    hash_key,
    validate_idempotency_key,
)
from zeus.models import BotRecord, BotStatus, BotStatusResponse
from zeus.state import StateStore
from zeus.supervisor import Supervisor


@dataclass(frozen=True)
class _ApiResponse:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> dict[str, Any] | list[Any]:
        return json.loads(self.body.decode("utf-8"))


def _api_request(
    port: int,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    key: str | None = None,
    api_key: str = "secret",
) -> _ApiResponse:
    headers = {"x-zeus-api-key": api_key}
    if body is not None:
        headers["content-type"] = "application/json"
    if key is not None:
        headers["idempotency-key"] = key
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        response_body = response.read()
        return _ApiResponse(
            response.status,
            {name.lower(): value for name, value in response.getheaders()},
            response_body,
        )
    finally:
        connection.close()


class _Payload:
    def __init__(self, action: str) -> None:
        self.action = action

    def to_dict(self) -> dict[str, str]:
        return {"action": self.action, "status": "ok"}


def _bot_record(bot_id: str, profile_path: str) -> BotRecord:
    return BotRecord(
        bot_id=bot_id,
        template_id="coding-bot",
        display_name=bot_id,
        profile_path=profile_path,
        status=BotStatus.stopped,
    )


class _LifecycleConflict(ZeusConflictError):
    code = "lifecycle_conflict"


class _RecordingSupervisor:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.failures: dict[str, Exception] = {}
        self.responses: dict[str, Any] = {}
        self.entered = threading.Event()
        self.release = threading.Event()
        self.block_action: str | None = None
        self.reconcile_snapshots: list[object] = []
        self._lock = threading.Lock()

    def _result(self, action: str) -> Any:
        with self._lock:
            self.calls.append(action)
        if self.block_action == action:
            self.entered.set()
            self.release.wait(timeout=5)
        failure = self.failures.get(action)
        if failure is not None:
            raise failure
        return self.responses.get(action, _Payload(action))

    def create_bot(self, *_args: object, **_kwargs: object) -> _Payload:
        return self._result("create")

    def start(self, *_args: object, **_kwargs: object) -> _Payload:
        return self._result("start")

    def stop(self, *_args: object, **_kwargs: object) -> _Payload:
        return self._result("stop")

    def restart(self, *_args: object, **_kwargs: object) -> _Payload:
        return self._result("restart")

    def reconcile(self, *args: object, **kwargs: object) -> list[_Payload]:
        action = "bot_reconcile" if args else "global_reconcile"
        if not args:
            self.reconcile_snapshots.append(kwargs.get("bot_snapshot"))
        return [self._result(action)]


@contextmanager
def _idempotent_api_server(
    supervisor: _RecordingSupervisor,
    *,
    state_dir: Path | None = None,
    log_enabled: bool = False,
) -> Iterator[tuple[int, Path, type[Any]]]:
    temporary_directory: tempfile.TemporaryDirectory[str] | None = None
    if state_dir is None:
        temporary_directory = tempfile.TemporaryDirectory()
        state_dir = Path(temporary_directory.name) / "state"
    settings = Settings.from_env(
        {
            "ZEUS_STATE_DIR": str(state_dir),
            "ZEUS_HOST": "127.0.0.1",
            "ZEUS_PORT": "0",
            "ZEUS_API_KEY": "secret",
            "ZEUS_API_LOG_ENABLED": "1" if log_enabled else "0",
        }
    )
    with patch("zeus.api.Supervisor", return_value=supervisor):
        handler = make_handler(settings)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, state_dir, handler
    finally:
        supervisor.release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        if temporary_directory is not None:
            temporary_directory.cleanup()


class IdempotencyIdentityTests(unittest.TestCase):
    def test_process_owner_is_stable_per_pid_and_rotates_for_a_new_pid(self) -> None:
        first = _process_idempotency_owner_id(pid=20_001)

        self.assertEqual(first, _process_idempotency_owner_id(pid=20_001))
        second = _process_idempotency_owner_id(pid=20_002)
        self.assertNotEqual(first, second)
        self.assertEqual(second, _process_idempotency_owner_id(pid=20_002))

    def test_key_validation_accepts_exact_grammar_boundaries(self) -> None:
        valid_values = (
            "a",
            "9",
            "deploy.2026:01_re-run",
            "a" + "." * 127,
        )

        for value in valid_values:
            with self.subTest(value=value):
                self.assertEqual(value, validate_idempotency_key(value))

    def test_key_validation_rejects_invalid_values_without_echoing_them(self) -> None:
        invalid_values: tuple[object, ...] = (
            "",
            "a" * 129,
            ".leading",
            "_leading",
            ":leading",
            "-leading",
            "has space",
            "has\ttab",
            "has\nnewline",
            "has\x00control",
            "non-ascii-é",
            None,
            123,
            object(),
        )

        for value in invalid_values:
            with self.subTest(value=type(value).__name__):
                with self.assertRaises((TypeError, ValueError)) as caught:
                    validate_idempotency_key(value)  # type: ignore[arg-type]
                if isinstance(value, str) and value:
                    self.assertNotIn(value, str(caught.exception))

    def test_key_hash_is_lowercase_sha256_and_never_returns_raw_key(self) -> None:
        key = validate_idempotency_key("deploy.2026:01")

        digest = hash_key(key)

        self.assertEqual(hashlib.sha256(key.encode("utf-8")).hexdigest(), digest)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertNotIn(key, digest)

    def test_alias_json_and_query_order_canonicalize_identically(self) -> None:
        left = canonical_request_hash(
            "post",
            "/v1/bots",
            {"stop": ["1"], "replace": ["1"]},
            {"b": 2, "nested": {"z": 3, "a": 1}, "a": 1},
        )
        right = canonical_request_hash(
            "POST",
            "/bots",
            {"replace": ["1"], "stop": ["1"]},
            {"a": 1, "nested": {"a": 1, "z": 3}, "b": 2},
        )

        self.assertEqual(left, right)
        self.assertRegex(left, r"^[0-9a-f]{64}$")

    def test_query_value_order_remains_significant(self) -> None:
        first = canonical_request_hash("POST", "/bots", {"tag": ["a", "b"]}, None)
        second = canonical_request_hash("POST", "/bots", {"tag": ["b", "a"]}, None)

        self.assertNotEqual(first, second)

    def test_only_a_leading_v1_alias_is_normalized(self) -> None:
        aliased = canonical_request_hash("POST", "/v1/bots", {}, {})
        canonical = canonical_request_hash("POST", "/bots", {}, {})
        embedded = canonical_request_hash("POST", "/proxy/v1/bots", {}, {})

        self.assertEqual(aliased, canonical)
        self.assertNotEqual(embedded, canonical)

    def test_non_json_and_non_finite_bodies_are_rejected_without_content(self) -> None:
        class SecretValue:
            def __repr__(self) -> str:
                return "raw-body-secret"

        invalid_bodies = (SecretValue(), math.nan, math.inf, -math.inf, {"value": math.nan})

        for body in invalid_bodies:
            with self.subTest(body_type=type(body).__name__):
                with self.assertRaises((TypeError, ValueError)) as caught:
                    canonical_request_hash("POST", "/bots", {}, body)
                self.assertNotIn("raw-body-secret", str(caught.exception))

    def test_only_exact_recursive_json_types_are_accepted(self) -> None:
        class IntegerSubclass(int):
            pass

        class FloatSubclass(float):
            pass

        class StringSubclass(str):
            pass

        class ListSubclass(list[object]):
            pass

        class DictSubclass(dict[str, object]):
            pass

        class IntegerEnum(IntEnum):
            VALUE = 1

        class StringEnum(StrEnum):
            VALUE = "raw-enum-secret"

        @dataclass
        class BodyRecord:
            value: str = "raw-dataclass-secret"

        invalid_bodies: tuple[object, ...] = (
            IntegerSubclass(1),
            FloatSubclass(1.0),
            StringSubclass("raw-string-secret"),
            ListSubclass([1]),
            DictSubclass(value=1),
            IntegerEnum.VALUE,
            StringEnum.VALUE,
            BodyRecord(),
            (1, 2),
            {1, 2},
            b"raw-bytes-secret",
            {1: "raw-non-string-key-secret"},
            {"nested": [1, {"value": IntegerSubclass(2)}]},
            {"nested": [1, {"value": math.nan}]},
        )

        for body in invalid_bodies:
            with self.subTest(body_type=type(body).__name__):
                with self.assertRaises(ValueError) as caught:
                    canonical_request_hash("POST", "/bots", {}, body)
                self.assertEqual(
                    "request must contain canonical JSON values", str(caught.exception)
                )

    def test_exact_json_scalars_and_nested_containers_are_accepted(self) -> None:
        body = {
            "null": None,
            "bool": True,
            "int": 1,
            "float": 1.25,
            "str": "value",
            "nested": [False, {"items": [0, 2.5, "three"]}],
        }

        digest = canonical_request_hash("POST", "/bots", {"tag": ["a", "b"]}, body)

        self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_query_requires_exact_dict_string_keys_and_string_lists(self) -> None:
        class QueryDict(dict[str, list[str]]):
            pass

        class QueryList(list[str]):
            pass

        class QueryString(str):
            pass

        invalid_queries: tuple[object, ...] = (
            UserDict({"tag": ["a"]}),
            QueryDict(tag=["a"]),
            {QueryString("raw-key-secret"): ["a"]},
            {"tag": QueryList(["a"])},
            {"tag": [QueryString("raw-value-secret")]},
            {"tag": ("a",)},
            {"tag": [1]},
        )

        for query in invalid_queries:
            with self.subTest(query_type=type(query).__name__):
                with self.assertRaises(ValueError) as caught:
                    canonical_request_hash("POST", "/bots", query, None)  # type: ignore[arg-type]
                self.assertEqual(
                    "request must contain canonical JSON values", str(caught.exception)
                )

    def test_fleet_ceiling_stops_consuming_large_snapshot_after_cap(self) -> None:
        consumed = 0

        def snapshot() -> Iterator[tuple[str, str]]:
            nonlocal consumed
            for index in range(10_000):
                consumed += 1
                yield f"bot-{index}", f"/profiles/bot-{index}"

        with (
            patch.object(api_module, "MAX_IDEMPOTENCY_RESPONSE_BYTES", 128),
            patch.object(api_module, "MAX_IDEMPOTENCY_MESSAGE_JSON_BYTES", 64),
        ):
            ceiling = api_module._fleet_reconcile_response_ceiling(snapshot())

        self.assertGreater(ceiling, 128)
        self.assertLess(consumed, 10_000)


class IdempotentApiTests(unittest.TestCase):
    def test_replay_handler_rejects_informational_status_without_writing(self) -> None:
        supervisor = _RecordingSupervisor()
        with _idempotent_api_server(supervisor) as (_port, _state_dir, handler):
            for response_status in (100, 199):
                with self.subTest(response_status=response_status):
                    request_handler = object.__new__(handler)
                    request_handler._request_context = SimpleNamespace(idempotency_outcome="")

                    with (
                        patch.object(handler, "_json_error_response") as error_response,
                        patch.object(handler, "_write_serialized_json") as serialized_write,
                    ):
                        handled = request_handler._handle_idempotency_outcome(
                            IdempotencyClaim("replay", response_status, "{}")
                        )

                    self.assertTrue(handled)
                    self.assertEqual(
                        "unavailable",
                        request_handler._request_context.idempotency_outcome,
                    )
                    error_response.assert_called_once()
                    self.assertEqual(503, int(error_response.call_args.args[0]))
                    self.assertEqual(
                        "idempotency_store_unavailable",
                        error_response.call_args.args[1],
                    )
                    serialized_write.assert_not_called()

    def test_malformed_mutation_routes_never_execute_or_create_claims(self) -> None:
        supervisor = _RecordingSupervisor()
        paths = (
            "/bots//coder/start",
            "/bots/coder//start",
            "/bots/coder/start/",
            "/bots/coder/start/extra",
            "/v1//bots/coder/start",
            "/v1/bots/coder/start/",
            "/v1/v1/bots/coder/start",
        )

        with _idempotent_api_server(supervisor) as (port, state_dir, _handler):
            responses = [
                _api_request(port, "POST", path, key=f"malformed-{index}")
                for index, path in enumerate(paths)
            ]
            with closing(sqlite3.connect(state_dir / "zeus.db")) as connection:
                count = connection.execute("SELECT COUNT(*) FROM idempotency_records").fetchone()[0]

        self.assertEqual([404] * len(paths), [response.status for response in responses])
        self.assertEqual([], supervisor.calls)
        self.assertEqual(0, count)

    def test_every_mutating_route_replays_across_v1_alias_without_second_call(self) -> None:
        cases = (
            (
                "create",
                "/bots?replace=false&stop=false",
                "/v1/bots?stop=0&replace=0",
                json.dumps({"bot_id": "coder", "template_id": "coding-bot"}).encode(),
            ),
            ("global_reconcile", "/bots/reconcile", "/v1/bots/reconcile", None),
            (
                "start",
                "/bots/coder/start?wait=true&timeout=1",
                "/v1/bots/coder/start?timeout=1&wait=1",
                None,
            ),
            (
                "stop",
                "/bots/coder/stop?kill_after_timeout=false",
                "/v1/bots/coder/stop?kill_after_timeout=0",
                None,
            ),
            ("restart", "/bots/coder/restart", "/v1/bots/coder/restart", None),
            ("bot_reconcile", "/bots/coder/reconcile", "/v1/bots/coder/reconcile", None),
        )

        for action, first_path, replay_path, body in cases:
            with self.subTest(action=action):
                supervisor = _RecordingSupervisor()
                with _idempotent_api_server(supervisor) as (port, _state_dir, _handler):
                    first = _api_request(port, "POST", first_path, body=body, key=f"key-{action}")
                    replay = _api_request(port, "POST", replay_path, body=body, key=f"key-{action}")

                self.assertEqual(200, first.status)
                self.assertEqual(first.status, replay.status)
                self.assertEqual(first.body, replay.body)
                self.assertEqual("true", replay.headers.get("idempotency-replayed"))
                self.assertNotEqual(
                    first.headers.get("x-request-id"), replay.headers.get("x-request-id")
                )
                self.assertEqual([action], supervisor.calls)

    def test_no_header_preserves_normal_execution_and_creates_no_records(self) -> None:
        supervisor = _RecordingSupervisor()
        with _idempotent_api_server(supervisor) as (port, state_dir, _handler):
            first = _api_request(port, "POST", "/bots/coder/start")
            second = _api_request(port, "POST", "/bots/coder/start")
            with closing(sqlite3.connect(state_dir / "zeus.db")) as connection:
                count = connection.execute("SELECT COUNT(*) FROM idempotency_records").fetchone()[0]

        self.assertEqual(200, first.status)
        self.assertEqual(first.status, second.status)
        self.assertEqual(first.body, second.body)
        self.assertIsNone(first.headers.get("idempotency-replayed"))
        self.assertIsNone(second.headers.get("idempotency-replayed"))
        self.assertEqual(["start", "start"], supervisor.calls)
        self.assertEqual(0, count)

    def test_keyed_fleet_reconcile_rejects_over_budget_before_claim_for_both_aliases(
        self,
    ) -> None:
        supervisor = _RecordingSupervisor()
        profile_path = "/profiles/coder"
        snapshot = (("coder", profile_path),)
        worst_message = "x" * (4_096 - len(json.dumps("")))
        ceiling = len(
            json.dumps(
                [
                    {
                        "bot_id": "coder",
                        "message": worst_message,
                        "pid": -(2**63),
                        "profile_path": profile_path,
                        "status": "starting",
                    }
                ],
                sort_keys=True,
            ).encode("utf-8")
        )
        with _idempotent_api_server(supervisor) as (port, state_dir, _handler):
            store = StateStore(state_dir / "zeus.db")
            store.upsert_bot(_bot_record("coder", profile_path))
            with patch.object(
                api_module,
                "MAX_IDEMPOTENCY_RESPONSE_BYTES",
                ceiling,
                create=True,
            ):
                accepted = _api_request(port, "POST", "/bots/reconcile", key="fleet-at-ceiling")
            with patch.object(
                api_module,
                "MAX_IDEMPOTENCY_RESPONSE_BYTES",
                ceiling - 1,
                create=True,
            ):
                rejected = [
                    _api_request(port, "POST", path, key=f"fleet-over-{index}")
                    for index, path in enumerate(("/bots/reconcile", "/v1/bots/reconcile"))
                ]
            with closing(sqlite3.connect(state_dir / "zeus.db")) as connection:
                rows = connection.execute("SELECT key_hash FROM idempotency_records").fetchall()

        self.assertEqual(200, accepted.status)
        self.assertEqual(snapshot, supervisor.reconcile_snapshots[0])
        self.assertEqual([422, 422], [response.status for response in rejected])
        self.assertEqual(
            ["idempotency_response_too_large"] * 2,
            [response.json()["error"]["code"] for response in rejected],
        )
        self.assertEqual(["global_reconcile"], supervisor.calls)
        self.assertEqual(1, len(rows))

    def test_keyed_fleet_reconcile_executes_the_preclaim_snapshot_when_registry_grows(
        self,
    ) -> None:
        supervisor = _RecordingSupervisor()
        original_claim = StateStore.claim_idempotency
        grew = False

        def claim_after_growth(store: StateStore, **kwargs: object) -> IdempotencyClaim:
            nonlocal grew
            if not grew:
                grew = True
                store.upsert_bot(_bot_record("new-bot", "/profiles/new-bot"))
            return original_claim(store, **kwargs)  # type: ignore[arg-type]

        with _idempotent_api_server(supervisor) as (port, state_dir, _handler):
            StateStore(state_dir / "zeus.db").upsert_bot(_bot_record("coder", "/profiles/coder"))
            with patch.object(StateStore, "claim_idempotency", claim_after_growth):
                response = _api_request(
                    port, "POST", "/bots/reconcile", key="fleet-stable-snapshot"
                )

        self.assertEqual(200, response.status)
        self.assertEqual([(("coder", "/profiles/coder"),)], supervisor.reconcile_snapshots)
        self.assertEqual(["global_reconcile"], supervisor.calls)

    def test_completed_fleet_replay_wins_over_growth_budget_for_v1_alias(self) -> None:
        supervisor = _RecordingSupervisor()
        with (
            patch.object(api_module, "MAX_IDEMPOTENCY_RESPONSE_BYTES", 256),
            _idempotent_api_server(supervisor) as (port, state_dir, _handler),
        ):
            first = _api_request(port, "POST", "/bots/reconcile", key="fleet-replay-growth")
            StateStore(state_dir / "zeus.db").upsert_bot(
                _bot_record("new-bot", "/profiles/" + ("x" * 512))
            )
            replay = _api_request(port, "POST", "/v1/bots/reconcile", key="fleet-replay-growth")

        self.assertEqual(200, first.status)
        self.assertEqual(first.body, replay.body)
        self.assertEqual("true", replay.headers.get("idempotency-replayed"))
        self.assertEqual(["global_reconcile"], supervisor.calls)

    def test_conflict_and_in_progress_win_over_fleet_budget_preflight(self) -> None:
        conflict_supervisor = _RecordingSupervisor()
        with (
            patch.object(api_module, "MAX_IDEMPOTENCY_RESPONSE_BYTES", 256),
            _idempotent_api_server(conflict_supervisor) as (port, state_dir, _handler),
        ):
            first = _api_request(port, "POST", "/bots/coder/start", key="fleet-precedence-conflict")
            StateStore(state_dir / "zeus.db").upsert_bot(
                _bot_record("new-bot", "/profiles/" + ("x" * 512))
            )
            conflict = _api_request(
                port, "POST", "/bots/reconcile", key="fleet-precedence-conflict"
            )

        self.assertEqual(200, first.status)
        self.assertEqual(409, conflict.status)
        self.assertEqual("idempotency_key_conflict", conflict.json()["error"]["code"])
        self.assertEqual(["start"], conflict_supervisor.calls)

        progress_supervisor = _RecordingSupervisor()
        with (
            patch.object(api_module, "MAX_IDEMPOTENCY_RESPONSE_BYTES", 256),
            _idempotent_api_server(progress_supervisor) as (port, state_dir, _handler),
        ):
            store = StateStore(state_dir / "zeus.db")
            store.upsert_bot(_bot_record("new-bot", "/profiles/" + ("x" * 512)))
            claim = store.claim_idempotency(
                key_hash=hash_key("fleet-precedence-progress"),
                request_hash=canonical_request_hash("POST", "/bots/reconcile", {}, None),
                owner_instance_id=_process_idempotency_owner_id(),
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
            response = _api_request(
                port, "POST", "/bots/reconcile", key="fleet-precedence-progress"
            )

        self.assertEqual("claimed", claim.kind)
        self.assertEqual(409, response.status)
        self.assertEqual("idempotency_in_progress", response.json()["error"]["code"])
        self.assertEqual([], progress_supervisor.calls)

    def test_fleet_sizing_database_failure_returns_store_unavailable_without_claim(self) -> None:
        supervisor = _RecordingSupervisor()
        with (
            _idempotent_api_server(supervisor) as (port, state_dir, _handler),
            patch.object(
                StateStore,
                "list_bots",
                side_effect=sqlite3.DatabaseError("private sizing failure"),
            ),
        ):
            response = _api_request(port, "POST", "/bots/reconcile", key="fleet-sizing-failure")
            with closing(sqlite3.connect(state_dir / "zeus.db")) as connection:
                count = connection.execute("SELECT COUNT(*) FROM idempotency_records").fetchone()[0]

        self.assertEqual(503, response.status)
        self.assertEqual("idempotency_store_unavailable", response.json()["error"]["code"])
        self.assertEqual([], supervisor.calls)
        self.assertEqual(0, count)

    def test_corrupt_idempotency_metadata_returns_503_instead_of_conflict(self) -> None:
        supervisor = _RecordingSupervisor()
        corruptions = (
            ("request-hash", "request_hash = ?", ("bad",)),
            ("owner", "owner_instance_id = ?", ("bad owner",)),
            ("state", "state = ?", ("broken",)),
            ("created", "created_at = ?", ("not-a-timestamp",)),
            ("updated", "updated_at = ?", ("not-a-timestamp",)),
            ("expiry", "expires_at = ?", ("not-a-timestamp",)),
            (
                "in-progress-response",
                "response_status = ?, response_json = ?",
                (200, "{}"),
            ),
            (
                "completed-informational-100",
                "state = 'completed', response_status = ?, response_json = ?",
                (100, "{}"),
            ),
            (
                "completed-informational-199",
                "state = 'completed', response_status = ?, response_json = ?",
                (199, "{}"),
            ),
        )
        with _idempotent_api_server(supervisor) as (port, state_dir, _handler):
            store = StateStore(state_dir / "zeus.db")
            for label, assignment, values in corruptions:
                with self.subTest(label=label):
                    key = f"corrupt-api-{label}"
                    claim = store.claim_idempotency(
                        key_hash=hash_key(key),
                        request_hash=canonical_request_hash("POST", "/bots/reconcile", {}, None),
                        owner_instance_id=_process_idempotency_owner_id(),
                        expires_at=datetime.now(UTC) + timedelta(hours=1),
                    )
                    with closing(sqlite3.connect(state_dir / "zeus.db")) as connection:
                        connection.execute("PRAGMA ignore_check_constraints = ON")
                        connection.execute(
                            f"UPDATE idempotency_records SET {assignment} WHERE key_hash = ?",
                            (*values, hash_key(key)),
                        )
                        connection.commit()
                    response = _api_request(port, "POST", "/bots/reconcile", key=key)

                    self.assertEqual("claimed", claim.kind)
                    self.assertEqual(503, response.status)
                    self.assertEqual(
                        "idempotency_store_unavailable", response.json()["error"]["code"]
                    )

        self.assertEqual([], supervisor.calls)

    def test_unkeyed_fleet_reconcile_keeps_live_inventory_behavior(self) -> None:
        supervisor = _RecordingSupervisor()
        with _idempotent_api_server(supervisor) as (port, state_dir, _handler):
            StateStore(state_dir / "zeus.db").upsert_bot(_bot_record("coder", "/profiles/coder"))
            response = _api_request(port, "POST", "/bots/reconcile")
            with closing(sqlite3.connect(state_dir / "zeus.db")) as connection:
                count = connection.execute("SELECT COUNT(*) FROM idempotency_records").fetchone()[0]

        self.assertEqual(200, response.status)
        self.assertEqual([None], supervisor.reconcile_snapshots)
        self.assertEqual(["global_reconcile"], supervisor.calls)
        self.assertEqual(0, count)

    def test_same_key_different_request_conflicts_without_second_call(self) -> None:
        supervisor = _RecordingSupervisor()
        with _idempotent_api_server(supervisor) as (port, _state_dir, _handler):
            first = _api_request(port, "POST", "/bots/coder/start", key="conflict-key")
            conflict = _api_request(port, "POST", "/bots/coder/stop", key="conflict-key")

        self.assertEqual(200, first.status)
        self.assertEqual(409, conflict.status)
        self.assertEqual("idempotency_key_conflict", conflict.json()["error"]["code"])
        self.assertEqual(["start"], supervisor.calls)

    def test_concurrent_duplicate_is_in_progress_and_executes_once(self) -> None:
        supervisor = _RecordingSupervisor()
        supervisor.block_action = "start"
        first_result: list[_ApiResponse] = []
        with _idempotent_api_server(supervisor) as (port, _state_dir, _handler):
            first_thread = threading.Thread(
                target=lambda: first_result.append(
                    _api_request(port, "POST", "/bots/coder/start", key="concurrent-key")
                )
            )
            first_thread.start()
            self.assertTrue(supervisor.entered.wait(timeout=2))
            duplicate = _api_request(port, "POST", "/v1/bots/coder/start", key="concurrent-key")
            supervisor.release.set()
            first_thread.join(timeout=3)

        self.assertFalse(first_thread.is_alive())
        self.assertEqual(200, first_result[0].status)
        self.assertEqual(409, duplicate.status)
        self.assertEqual("1", duplicate.headers.get("retry-after"))
        self.assertEqual("idempotency_in_progress", duplicate.json()["error"]["code"])
        self.assertEqual(["start"], supervisor.calls)

    def test_same_process_handler_owners_report_active_claim_in_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            first_supervisor = _RecordingSupervisor()
            first_supervisor.block_action = "start"
            first_result: list[_ApiResponse] = []
            with _idempotent_api_server(first_supervisor, state_dir=state_dir) as (
                first_port,
                _state_dir,
                _handler,
            ):
                first_thread = threading.Thread(
                    target=lambda: first_result.append(
                        _api_request(
                            first_port,
                            "POST",
                            "/bots/coder/start",
                            key="prior-owner-key",
                        )
                    )
                )
                first_thread.start()
                self.assertTrue(first_supervisor.entered.wait(timeout=2))
                second_supervisor = _RecordingSupervisor()
                with _idempotent_api_server(second_supervisor, state_dir=state_dir) as (
                    second_port,
                    _second_state,
                    _second_handler,
                ):
                    response = _api_request(
                        second_port,
                        "POST",
                        "/v1/bots/coder/start",
                        key="prior-owner-key",
                    )
                first_supervisor.release.set()
                first_thread.join(timeout=3)

        self.assertEqual(409, response.status)
        self.assertEqual("idempotency_in_progress", response.json()["error"]["code"])
        self.assertEqual([], second_supervisor.calls)

    def test_new_process_owner_reports_active_claim_indeterminate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            first_supervisor = _RecordingSupervisor()
            first_supervisor.block_action = "start"
            first_result: list[_ApiResponse] = []
            with (
                patch("zeus.api.os.getpid", return_value=10_001),
                _idempotent_api_server(first_supervisor, state_dir=state_dir) as (
                    first_port,
                    _state_dir,
                    _handler,
                ),
            ):
                first_thread = threading.Thread(
                    target=lambda: first_result.append(
                        _api_request(
                            first_port,
                            "POST",
                            "/bots/coder/start",
                            key="new-process-key",
                        )
                    )
                )
                first_thread.start()
                self.assertTrue(first_supervisor.entered.wait(timeout=2))
                second_supervisor = _RecordingSupervisor()
                with (
                    patch("zeus.api.os.getpid", return_value=10_002),
                    _idempotent_api_server(second_supervisor, state_dir=state_dir) as (
                        second_port,
                        _second_state,
                        _second_handler,
                    ),
                ):
                    response = _api_request(
                        second_port,
                        "POST",
                        "/v1/bots/coder/start",
                        key="new-process-key",
                    )
                first_supervisor.release.set()
                first_thread.join(timeout=3)

        self.assertEqual(409, response.status)
        self.assertEqual("idempotency_indeterminate", response.json()["error"]["code"])
        self.assertEqual([], second_supervisor.calls)

    def test_completed_request_replays_after_handler_restart_and_json_reordering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            first_supervisor = _RecordingSupervisor()
            with _idempotent_api_server(first_supervisor, state_dir=state_dir) as (
                first_port,
                _first_state,
                _first_handler,
            ):
                first = _api_request(
                    first_port,
                    "POST",
                    "/bots",
                    body=b'{"bot_id":"coder","template_id":"coding-bot"}',
                    key="restart-replay-key",
                )

            second_supervisor = _RecordingSupervisor()
            with _idempotent_api_server(second_supervisor, state_dir=state_dir) as (
                second_port,
                _second_state,
                _second_handler,
            ):
                replay = _api_request(
                    second_port,
                    "POST",
                    "/v1/bots",
                    body=b'{"template_id":"coding-bot","bot_id":"coder"}',
                    key="restart-replay-key",
                )

        self.assertEqual(200, first.status)
        self.assertEqual(first.body, replay.body)
        self.assertEqual("true", replay.headers.get("idempotency-replayed"))
        self.assertEqual(["create"], first_supervisor.calls)
        self.assertEqual([], second_supervisor.calls)

    def test_terminal_conflict_and_internal_error_are_stored_and_replayed(self) -> None:
        cases = (
            (
                "stored-conflict",
                _LifecycleConflict("already active"),
                409,
                "lifecycle_conflict",
            ),
            ("stored-error", RuntimeError("private traceback detail"), 500, "internal_error"),
        )
        for key, failure, expected_status, expected_code in cases:
            with self.subTest(key=key):
                supervisor = _RecordingSupervisor()
                supervisor.failures["start"] = failure
                with _idempotent_api_server(supervisor) as (port, _state_dir, _handler):
                    first = _api_request(port, "POST", "/bots/coder/start", key=key)
                    replay = _api_request(port, "POST", "/bots/coder/start", key=key)

                self.assertEqual(expected_status, first.status)
                self.assertEqual(expected_code, first.json()["error"]["code"])
                self.assertEqual(first.body, replay.body)
                self.assertEqual("true", replay.headers.get("idempotency-replayed"))
                self.assertEqual(["start"], supervisor.calls)
                self.assertNotIn(b"private traceback detail", replay.body)

    def test_unserializable_handler_result_becomes_a_stored_generic_500(self) -> None:
        supervisor = _RecordingSupervisor()
        supervisor.responses["start"] = SimpleNamespace(to_dict=lambda: {"unsafe": object()})
        with _idempotent_api_server(supervisor) as (port, _state_dir, _handler):
            first = _api_request(port, "POST", "/bots/coder/start", key="serialization-key")
            replay = _api_request(port, "POST", "/bots/coder/start", key="serialization-key")

        self.assertEqual(500, first.status)
        self.assertEqual("internal_error", first.json()["error"]["code"])
        self.assertEqual(first.body, replay.body)
        self.assertEqual("true", replay.headers.get("idempotency-replayed"))
        self.assertEqual(["start"], supervisor.calls)

    def test_oversized_success_and_value_error_become_stored_generic_500_responses(
        self,
    ) -> None:
        cases = (
            ("success", SimpleNamespace(to_dict=lambda: {"payload": "x" * 500}), None),
            ("value-error", None, ValueError("x" * 500)),
        )
        for label, result, failure in cases:
            with self.subTest(label=label):
                supervisor = _RecordingSupervisor()
                if result is not None:
                    supervisor.responses["start"] = result
                if failure is not None:
                    supervisor.failures["start"] = failure
                with (
                    patch.object(
                        api_module,
                        "MAX_IDEMPOTENCY_RESPONSE_BYTES",
                        256,
                        create=True,
                    ),
                    _idempotent_api_server(supervisor) as (port, _state_dir, _handler),
                ):
                    first = _api_request(
                        port, "POST", "/bots/coder/start", key=f"oversized-{label}"
                    )
                    replay = _api_request(
                        port, "POST", "/bots/coder/start", key=f"oversized-{label}"
                    )

                self.assertEqual(500, first.status)
                self.assertEqual("internal_error", first.json()["error"]["code"])
                self.assertEqual(first.body, replay.body)
                self.assertEqual("true", replay.headers.get("idempotency-replayed"))
                self.assertEqual(["start"], supervisor.calls)

    def test_dynamic_error_message_is_bounded_by_encoded_json_size(self) -> None:
        supervisor = _RecordingSupervisor()
        private_message = (("\x00\n\t" + chr(0x1F600)) * 2_000) + "private-tail"
        supervisor.failures["start"] = ValueError(private_message)
        with _idempotent_api_server(supervisor) as (port, _state_dir, _handler):
            first = _api_request(port, "POST", "/bots/coder/start", key="encoded-message")
            replay = _api_request(port, "POST", "/bots/coder/start", key="encoded-message")

        payload = first.json()
        self.assertEqual(400, first.status)
        self.assertEqual("invalid_request", payload["error"]["code"])
        self.assertEqual(400, payload["error"]["status"])
        self.assertLessEqual(
            len(json.dumps(payload["error"]["message"]).encode("utf-8")),
            4_096,
        )
        self.assertNotIn("private-tail", payload["error"]["message"])
        self.assertEqual(first.body, replay.body)

    def test_nonfinite_handler_results_become_stored_generic_500_responses(self) -> None:
        supervisor = _RecordingSupervisor()
        payloads = (
            {"value": math.nan},
            {"nested": {"value": math.inf}},
            {"nested": [{"deeper": [-math.inf]}]},
        )
        with _idempotent_api_server(supervisor, log_enabled=True) as (port, state_dir, _handler):
            for index, payload in enumerate(payloads):
                with self.subTest(index=index):
                    supervisor.responses["start"] = SimpleNamespace(
                        to_dict=lambda payload=payload: payload
                    )
                    key = f"nonfinite-{index}"
                    first = _api_request(port, "POST", "/bots/coder/start", key=key)
                    replay = _api_request(port, "POST", "/bots/coder/start", key=key)

                    self.assertEqual(500, first.status)
                    self.assertEqual("internal_error", first.json()["error"]["code"])
                    self.assertEqual(first.body, replay.body)
                    self.assertEqual("true", replay.headers.get("idempotency-replayed"))
                    self.assertNotIn(b"NaN", first.body)
                    self.assertNotIn(b"Infinity", first.body)

            log_rows = [
                json.loads(line)
                for line in (state_dir / "logs" / "api.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]

        self.assertEqual(["start"] * len(payloads), supervisor.calls)
        self.assertEqual(
            len(payloads),
            sum(row.get("event") == "api.error" for row in log_rows),
        )

    def test_supervisor_value_error_remains_a_stored_client_error(self) -> None:
        supervisor = _RecordingSupervisor()
        supervisor.failures["start"] = ValueError("invalid lifecycle option")
        with _idempotent_api_server(supervisor) as (port, _state_dir, _handler):
            first = _api_request(port, "POST", "/bots/coder/start", key="value-error-key")
            replay = _api_request(port, "POST", "/bots/coder/start", key="value-error-key")

        self.assertEqual(400, first.status)
        self.assertEqual("invalid_request", first.json()["error"]["code"])
        self.assertEqual(first.body, replay.body)
        self.assertEqual("true", replay.headers.get("idempotency-replayed"))
        self.assertEqual(["start"], supervisor.calls)

    def test_completed_response_replays_after_socket_write_failure(self) -> None:
        supervisor = _RecordingSupervisor()
        with _idempotent_api_server(supervisor) as (port, _state_dir, handler):
            with (
                patch.object(handler, "_write_serialized_json", side_effect=OSError("closed")),
                self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError)),
            ):
                _api_request(port, "POST", "/bots/coder/start", key="socket-key")
            replay = _api_request(port, "POST", "/bots/coder/start", key="socket-key")

        self.assertEqual(200, replay.status)
        self.assertEqual("true", replay.headers.get("idempotency-replayed"))
        self.assertEqual(["start"], supervisor.calls)

    def test_completion_failure_sends_generic_503_and_leaves_unresolved(self) -> None:
        supervisor = _RecordingSupervisor()
        with _idempotent_api_server(supervisor) as (port, state_dir, _handler):
            with patch.object(
                StateStore,
                "complete_idempotency",
                side_effect=sqlite3.DatabaseError("private completion failure"),
            ):
                response = _api_request(port, "POST", "/bots/coder/start", key="completion-failure")
            with closing(sqlite3.connect(state_dir / "zeus.db")) as connection:
                row = connection.execute(
                    "SELECT state, response_status, response_json FROM idempotency_records"
                ).fetchone()

        self.assertEqual(503, response.status)
        self.assertEqual("idempotency_store_unavailable", response.json()["error"]["code"])
        self.assertEqual(("in_progress", None, None), row)
        self.assertEqual(["start"], supervisor.calls)
        self.assertNotIn(b'"status": "ok"', response.body)

    def test_corruption_between_execution_and_completion_returns_503_without_overwrite(
        self,
    ) -> None:
        supervisor = _RecordingSupervisor()
        original_complete = StateStore.complete_idempotency

        def corrupt_then_complete(store: StateStore, **kwargs: object) -> None:
            with closing(sqlite3.connect(store.database_path)) as connection:
                connection.execute(
                    "UPDATE idempotency_records SET expires_at = ? WHERE key_hash = ?",
                    ("2000-01-01T00:00:00+00:00", kwargs["key_hash"]),
                )
                connection.commit()
            original_complete(store, **kwargs)  # type: ignore[arg-type]

        with (
            _idempotent_api_server(supervisor) as (port, state_dir, _handler),
            patch.object(StateStore, "complete_idempotency", corrupt_then_complete),
        ):
            response = _api_request(port, "POST", "/bots/coder/start", key="completion-corruption")
            with closing(sqlite3.connect(state_dir / "zeus.db")) as connection:
                row = connection.execute(
                    "SELECT state, response_status, response_json, expires_at "
                    "FROM idempotency_records"
                ).fetchone()

        self.assertEqual(503, response.status)
        self.assertEqual("idempotency_store_unavailable", response.json()["error"]["code"])
        self.assertEqual(("in_progress", None, None, "2000-01-01T00:00:00+00:00"), row)
        self.assertEqual(["start"], supervisor.calls)

    def test_claim_unavailable_returns_503_without_execution(self) -> None:
        supervisor = _RecordingSupervisor()
        with (
            _idempotent_api_server(supervisor) as (port, _state_dir, _handler),
            patch.object(
                StateStore,
                "claim_idempotency",
                return_value=IdempotencyClaim("unavailable"),
            ),
        ):
            response = _api_request(port, "POST", "/bots/coder/start", key="unavailable-key")

        self.assertEqual(503, response.status)
        self.assertEqual("idempotency_store_unavailable", response.json()["error"]["code"])
        self.assertEqual([], supervisor.calls)

    def test_unexpected_claim_failure_returns_503_without_execution(self) -> None:
        supervisor = _RecordingSupervisor()
        with (
            _idempotent_api_server(supervisor) as (port, _state_dir, _handler),
            patch.object(
                StateStore,
                "claim_idempotency",
                side_effect=sqlite3.DatabaseError("private claim failure"),
            ),
        ):
            response = _api_request(port, "POST", "/bots/coder/start", key="claim-failure")

        self.assertEqual(503, response.status)
        self.assertEqual("idempotency_store_unavailable", response.json()["error"]["code"])
        self.assertEqual([], supervisor.calls)

    def test_invalid_requests_and_non_mutations_create_no_records(self) -> None:
        supervisor = _RecordingSupervisor()
        valid_create = json.dumps({"bot_id": "coder", "template_id": "coding-bot"}).encode()
        cases = (
            ("POST", "/bots/coder/start", None, "valid-key", "wrong"),
            ("POST", "/not-a-route", None, "valid-key", "secret"),
            ("POST", "/bots/coder/start?unknown=1", None, "valid-key", "secret"),
            ("POST", "/bots", b"{", "valid-key", "secret"),
            ("POST", "/bots", valid_create, "has space", "secret"),
            ("GET", "/bots", None, "valid-key", "secret"),
            ("PUT", "/bots/coder/start", None, "valid-key", "secret"),
        )
        with _idempotent_api_server(supervisor) as (port, state_dir, _handler):
            for method, path, body, key, api_key in cases:
                with self.subTest(method=method, path=path):
                    _api_request(port, method, path, body=body, key=key, api_key=api_key)
            with closing(sqlite3.connect(state_dir / "zeus.db")) as connection:
                count = connection.execute("SELECT COUNT(*) FROM idempotency_records").fetchone()[0]

        self.assertEqual(0, count)
        self.assertEqual([], supervisor.calls)

    def test_api_persistence_contains_no_raw_key_body_or_key_header(self) -> None:
        supervisor = _RecordingSupervisor()
        raw_key = "private-idempotency-key"
        body = b'{"bot_id":"coder","template_id":"coding-bot","display_name":"raw-body-private"}'
        with _idempotent_api_server(supervisor) as (port, state_dir, _handler):
            response = _api_request(port, "POST", "/bots", body=body, key=raw_key)
            database_bytes = (state_dir / "zeus.db").read_bytes()

        self.assertEqual(200, response.status)
        self.assertNotIn(raw_key.encode(), database_bytes)
        self.assertNotIn(body, database_bytes)
        self.assertNotIn(b"raw-body-private", database_bytes)
        self.assertNotIn(b"Idempotency-Key", database_bytes)

    def test_access_logs_use_only_safe_idempotency_outcomes(self) -> None:
        supervisor = _RecordingSupervisor()
        with _idempotent_api_server(supervisor, log_enabled=True) as (
            port,
            state_dir,
            _handler,
        ):
            first = _api_request(port, "POST", "/bots/coder/start", key="logged-key")
            replay = _api_request(port, "POST", "/bots/coder/start", key="logged-key")
            log_path = state_dir / "logs" / "api.jsonl"
            deadline = time.monotonic() + 2
            rows: list[dict[str, object]] = []
            while time.monotonic() < deadline:
                if log_path.exists():
                    rows = [
                        json.loads(line)
                        for line in log_path.read_text(encoding="utf-8").splitlines()
                    ]
                    if len(rows) >= 2:
                        break
                threading.Event().wait(0.01)
        self.assertEqual(200, first.status)
        self.assertEqual(200, replay.status)
        self.assertEqual(["claimed", "replayed"], [row["idempotency_outcome"] for row in rows])
        serialized = json.dumps(rows)
        self.assertNotIn("logged-key", serialized)
        self.assertNotIn("coder", serialized)


class ReconcileSnapshotTests(unittest.TestCase):
    def test_supervisor_snapshot_skips_vanished_ids_and_ignores_growth(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            store = StateStore(root / "zeus.db")
            store.init()
            existing = _bot_record("coder", str(root / "profiles" / "coder"))
            store.upsert_bot(existing)
            store.upsert_bot(_bot_record("new-bot", str(root / "profiles" / "new-bot")))
            supervisor = Supervisor(store, "/bin/true", root)
            result = BotStatusResponse(
                bot_id="coder",
                status=BotStatus.stopped,
                pid=None,
                profile_path=existing.profile_path,
            )
            snapshot = (
                ("coder", existing.profile_path),
                ("vanished", str(root / "profiles" / "vanished")),
            )
            with patch.object(supervisor, "_reconcile_record", return_value=result) as effect:
                responses = supervisor.reconcile(bot_snapshot=snapshot)

        self.assertEqual([result], responses)
        self.assertEqual(["coder"], [call.args[0].bot_id for call in effect.call_args_list])


class IdempotencyPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.database = Path(self.temporary_directory.name) / "zeus.db"
        self.store = StateStore(self.database)
        self.store.init()
        self.now = datetime.now(UTC)
        self.future = self.now + timedelta(hours=1)
        self.past = self.now - timedelta(hours=1)
        self.key_hash = "a" * 64
        self.request_hash = "b" * 64

    def claim(
        self,
        *,
        key_hash: str | None = None,
        request_hash: str | None = None,
        owner_instance_id: str = "owner-a",
        expires_at: datetime | None = None,
        max_records: int = 10_000,
    ) -> IdempotencyClaim:
        return self.store.claim_idempotency(
            key_hash=key_hash or self.key_hash,
            request_hash=request_hash or self.request_hash,
            owner_instance_id=owner_instance_id,
            expires_at=expires_at or self.future,
            max_records=max_records,
        )

    def complete(
        self,
        *,
        owner_instance_id: str = "owner-a",
        request_hash: str | None = None,
        response_status: int = 202,
        response_json: str = '{"ok":true}',
        completed_at: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> None:
        self.store.complete_idempotency(
            key_hash=self.key_hash,
            request_hash=request_hash or self.request_hash,
            owner_instance_id=owner_instance_id,
            response_status=response_status,
            response_json=response_json,
            completed_at=completed_at or datetime.now(UTC),
            expires_at=expires_at or self.future,
        )

    def test_new_claim_completion_and_matching_replay(self) -> None:
        first = self.claim()
        self.assertEqual("claimed", first.kind)

        self.complete()
        replay = self.claim()

        self.assertEqual("replay", replay.kind)
        self.assertEqual(202, replay.response_status)
        self.assertEqual('{"ok":true}', replay.response_json)

    def test_conflict_same_owner_progress_and_prior_owner_uncertainty(self) -> None:
        self.assertEqual("claimed", self.claim().kind)
        self.assertEqual("in_progress", self.claim().kind)
        self.assertEqual(
            "conflict",
            self.claim(request_hash="c" * 64).kind,
        )
        self.assertEqual(
            "indeterminate",
            self.claim(owner_instance_id="owner-b").kind,
        )

    def test_two_concurrent_claims_have_one_owner(self) -> None:
        def claim_once() -> IdempotencyClaim:
            return self.claim()

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(lambda _index: claim_once(), range(2)))

        self.assertEqual(1, sum(result.kind == "claimed" for result in outcomes))
        self.assertEqual(1, sum(result.kind == "in_progress" for result in outcomes))

    def test_only_allowed_expired_rows_are_reclaimed(self) -> None:
        created = self.past - timedelta(hours=1)
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                "INSERT INTO idempotency_records VALUES (?, ?, 'in_progress', ?, NULL, NULL, "
                "?, ?, ?)",
                (
                    self.key_hash,
                    self.request_hash,
                    "owner-a",
                    created.isoformat(),
                    created.isoformat(),
                    self.past.isoformat(),
                ),
            )
            connection.commit()
        self.assertEqual("in_progress", self.claim(expires_at=self.future).kind)
        self.assertEqual(
            "claimed",
            self.claim(
                request_hash="c" * 64,
                owner_instance_id="owner-b",
                expires_at=self.future,
            ).kind,
        )

        other_key = "d" * 64
        self.assertEqual("claimed", self.claim(key_hash=other_key, expires_at=self.future).kind)
        completed = datetime.now(UTC)
        self.store.complete_idempotency(
            key_hash=other_key,
            request_hash=self.request_hash,
            owner_instance_id="owner-a",
            response_status=200,
            response_json="{}",
            completed_at=completed,
            expires_at=completed,
        )
        self.assertEqual(
            "claimed",
            self.claim(
                key_hash=other_key,
                request_hash="e" * 64,
                owner_instance_id="owner-a",
            ).kind,
        )

    def test_capacity_is_enforced_after_expiry_cleanup(self) -> None:
        self.assertEqual("claimed", self.claim(max_records=1).kind)
        unavailable = self.claim(key_hash="c" * 64, max_records=1)
        self.assertEqual("unavailable", unavailable.kind)

        with closing(sqlite3.connect(self.database)) as conn:
            count = conn.execute("SELECT COUNT(*) FROM idempotency_records").fetchone()[0]
        self.assertEqual(1, count)

        completed = datetime.now(UTC)
        self.complete(completed_at=completed, expires_at=completed)
        reclaimed = self.claim(key_hash="c" * 64, max_records=1)
        self.assertEqual("claimed", reclaimed.kind)

    def test_claim_storage_failure_returns_unavailable_without_partial_row(self) -> None:
        with closing(sqlite3.connect(self.database)) as conn:
            conn.execute(
                """
                CREATE TRIGGER reject_idempotency_claim
                BEFORE INSERT ON idempotency_records
                BEGIN
                    SELECT RAISE(ABORT, 'injected claim failure');
                END
                """
            )
            conn.commit()

        self.assertEqual("unavailable", self.claim().kind)
        with closing(sqlite3.connect(self.database)) as conn:
            count = conn.execute("SELECT COUNT(*) FROM idempotency_records").fetchone()[0]
        self.assertEqual(0, count)

    def test_completion_storage_failure_keeps_claim_unresolved(self) -> None:
        self.assertEqual("claimed", self.claim().kind)
        with closing(sqlite3.connect(self.database)) as conn:
            conn.execute(
                """
                CREATE TRIGGER reject_idempotency_completion
                BEFORE UPDATE ON idempotency_records
                WHEN NEW.state = 'completed'
                BEGIN
                    SELECT RAISE(ABORT, 'injected completion failure');
                END
                """
            )
            conn.commit()

        with self.assertRaisesRegex(sqlite3.DatabaseError, "injected completion failure"):
            self.complete()
        self.assertEqual("in_progress", self.claim().kind)

    def test_completion_rejects_informational_status_without_overwriting_claim(self) -> None:
        for index, response_status in enumerate((100, 199), start=1):
            with self.subTest(response_status=response_status):
                key_hash = f"{index:064x}"
                claimed = self.store.claim_idempotency(
                    key_hash=key_hash,
                    request_hash=self.request_hash,
                    owner_instance_id="owner-a",
                    expires_at=self.future,
                )

                with self.assertRaisesRegex(ValueError, "response status is invalid"):
                    self.store.complete_idempotency(
                        key_hash=key_hash,
                        request_hash=self.request_hash,
                        owner_instance_id="owner-a",
                        response_status=response_status,
                        response_json="{}",
                        completed_at=datetime.now(UTC),
                        expires_at=self.future,
                    )
                with closing(sqlite3.connect(self.database)) as connection:
                    stored = connection.execute(
                        "SELECT state, response_status, response_json "
                        "FROM idempotency_records WHERE key_hash = ?",
                        (key_hash,),
                    ).fetchone()

                self.assertEqual("claimed", claimed.kind)
                self.assertEqual(("in_progress", None, None), stored)

    def test_completion_requires_exact_in_progress_owner_and_request(self) -> None:
        self.assertEqual("claimed", self.claim().kind)

        for owner, request in (("owner-b", self.request_hash), ("owner-a", "c" * 64)):
            with (
                self.subTest(owner=owner, request=request),
                self.assertRaisesRegex(RuntimeError, "idempotency completion failed"),
            ):
                self.store.complete_idempotency(
                    key_hash=self.key_hash,
                    request_hash=request,
                    owner_instance_id=owner,
                    response_status=200,
                    response_json="{}",
                    completed_at=self.now,
                    expires_at=self.future,
                )

        self.complete()
        with self.assertRaisesRegex(RuntimeError, "idempotency completion failed"):
            self.complete()

    def test_completion_validates_locked_stored_row_before_update(self) -> None:
        corruptions = (
            ("request-hash", "request_hash = ?", ("bad",)),
            ("owner", "owner_instance_id = ?", ("bad owner",)),
            ("key-hash", "key_hash = ?", ("f" * 64,)),
            ("state", "state = ?", ("broken",)),
            ("created", "created_at = ?", ("not-a-timestamp",)),
            ("updated", "updated_at = ?", ("not-a-timestamp",)),
            ("expiry", "expires_at = ?", ("not-a-timestamp",)),
            ("ordered-expiry", "expires_at = ?", ("2000-01-01T00:00:00+00:00",)),
            ("response-status", "response_status = ?", (200,)),
            ("response-json", "response_json = ?", ("{}",)),
        )
        for index, (label, assignment, values) in enumerate(corruptions):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary_directory:
                store = StateStore(Path(temporary_directory) / "zeus.db")
                store.init()
                key_hash = f"{index + 1:064x}"
                request_hash = "b" * 64
                claimed = store.claim_idempotency(
                    key_hash=key_hash,
                    request_hash=request_hash,
                    owner_instance_id="owner-a",
                    expires_at=datetime.now(UTC) + timedelta(hours=1),
                )
                with closing(sqlite3.connect(store.database_path)) as connection:
                    connection.execute("PRAGMA ignore_check_constraints = ON")
                    connection.execute(
                        f"UPDATE idempotency_records SET {assignment} WHERE key_hash = ?",
                        (*values, key_hash),
                    )
                    connection.commit()

                with self.assertRaises((RuntimeError, ValueError, TypeError)):
                    store.complete_idempotency(
                        key_hash=key_hash,
                        request_hash=request_hash,
                        owner_instance_id="owner-a",
                        response_status=200,
                        response_json="{}",
                        completed_at=datetime.now(UTC),
                        expires_at=datetime.now(UTC) + timedelta(hours=1),
                    )
                with closing(sqlite3.connect(store.database_path)) as connection:
                    stored = connection.execute(
                        "SELECT state, response_status, response_json FROM idempotency_records"
                    ).fetchone()

                self.assertEqual("claimed", claimed.kind)
                self.assertNotEqual(("completed", 200, "{}"), stored)

    def test_claim_rejects_expiry_before_creation_without_inserting(self) -> None:
        with self.assertRaisesRegex(ValueError, "expiry timestamp"):
            self.store.claim_idempotency(
                key_hash=self.key_hash,
                request_hash=self.request_hash,
                owner_instance_id="owner-a",
                expires_at=datetime.now(UTC) - timedelta(microseconds=1),
            )
        with closing(sqlite3.connect(self.database)) as connection:
            count = connection.execute("SELECT COUNT(*) FROM idempotency_records").fetchone()[0]
        self.assertEqual(0, count)

    def test_completed_timestamp_order_and_canonical_utc_compatibility(self) -> None:
        compatible = (
            (
                "2099-01-01T00:00:00+00:00",
                "2099-01-01T00:00:01.123456+00:00",
                "2099-01-01T00:00:02+00:00",
            ),
            (
                "2099-01-01T00:00:00.000001+00:00",
                "2099-01-01T00:00:01+00:00",
                "2099-01-01T00:00:02.999999+00:00",
            ),
        )
        for index, timestamps in enumerate(compatible):
            with self.subTest(kind="compatible", index=index):
                key_hash = f"{index + 100:064x}"
                self.assertEqual(
                    "claimed",
                    self.store.claim_idempotency(
                        key_hash=key_hash,
                        request_hash=self.request_hash,
                        owner_instance_id="owner-a",
                        expires_at=self.future,
                    ).kind,
                )
                with closing(sqlite3.connect(self.database)) as connection:
                    connection.execute(
                        "UPDATE idempotency_records SET state = 'completed', "
                        "response_status = 200, response_json = '{}', "
                        "created_at = ?, updated_at = ?, expires_at = ? WHERE key_hash = ?",
                        (*timestamps, key_hash),
                    )
                    connection.commit()
                replay = self.store.lookup_idempotency(
                    key_hash=key_hash,
                    request_hash=self.request_hash,
                    owner_instance_id="owner-a",
                )
                self.assertIsNotNone(replay)
                self.assertEqual("replay", replay.kind if replay else None)

        reverse_orders = (
            (
                "2099-01-01T00:00:02+00:00",
                "2099-01-01T00:00:01+00:00",
                "2099-01-01T00:00:03+00:00",
            ),
            (
                "2099-01-01T00:00:00+00:00",
                "2099-01-01T00:00:02+00:00",
                "2099-01-01T00:00:01+00:00",
            ),
        )
        for index, timestamps in enumerate(reverse_orders):
            with self.subTest(kind="reverse", index=index), tempfile.TemporaryDirectory() as tmp:
                store = StateStore(Path(tmp) / "zeus.db")
                store.init()
                store.claim_idempotency(
                    key_hash=self.key_hash,
                    request_hash=self.request_hash,
                    owner_instance_id="owner-a",
                    expires_at=self.future,
                )
                with closing(sqlite3.connect(store.database_path)) as connection:
                    connection.execute(
                        "UPDATE idempotency_records SET state = 'completed', "
                        "response_status = 200, response_json = '{}', "
                        "created_at = ?, updated_at = ?, expires_at = ?",
                        timestamps,
                    )
                    connection.commit()
                lookup = store.lookup_idempotency(
                    key_hash=self.key_hash,
                    request_hash=self.request_hash,
                    owner_instance_id="owner-a",
                )
                self.assertIsNotNone(lookup)
                self.assertEqual("unavailable", lookup.kind if lookup else None)

    def test_corrupt_metadata_is_unavailable_for_lookup_and_atomic_claim(self) -> None:
        corruptions = (
            ("request-hash", "request_hash = ?", ("bad",)),
            ("owner", "owner_instance_id = ?", ("bad owner",)),
            ("state", "state = ?", ("broken",)),
            ("created", "created_at = ?", ("not-a-timestamp",)),
            ("updated", "updated_at = ?", ("not-a-timestamp",)),
            ("expiry", "expires_at = ?", ("not-a-timestamp",)),
            ("naive-expiry", "expires_at = ?", ("2026-01-01T00:00:00",)),
            ("updated-before-created", "updated_at = ?", ("2000-01-01T00:00:00+00:00",)),
            (
                "completed-expiry-before-updated",
                "state = 'completed', response_status = 200, response_json = '{}', expires_at = ?",
                ("2000-01-01T00:00:00+00:00",),
            ),
            (
                "in-progress-response",
                "response_status = ?, response_json = ?",
                (200, "{}"),
            ),
            (
                "completed-missing-response",
                "state = 'completed', response_status = NULL, response_json = NULL",
                (),
            ),
            (
                "completed-invalid-status",
                "state = 'completed', response_status = ?, response_json = ?",
                (99, "{}"),
            ),
            (
                "completed-informational-100",
                "state = 'completed', response_status = ?, response_json = ?",
                (100, "{}"),
            ),
            (
                "completed-informational-199",
                "state = 'completed', response_status = ?, response_json = ?",
                (199, "{}"),
            ),
            (
                "completed-invalid-json",
                "state = 'completed', response_status = ?, response_json = ?",
                (200, "not-json"),
            ),
        )
        for index, (label, assignment, values) in enumerate(corruptions):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary_directory:
                store = StateStore(Path(temporary_directory) / "zeus.db")
                store.init()
                key_hash = f"{index + 1:064x}"
                request_hash = "b" * 64
                claimed = store.claim_idempotency(
                    key_hash=key_hash,
                    request_hash=request_hash,
                    owner_instance_id="owner-a",
                    expires_at=datetime.now(UTC) + timedelta(hours=1),
                )
                with closing(sqlite3.connect(store.database_path)) as connection:
                    connection.execute("PRAGMA ignore_check_constraints = ON")
                    connection.execute(
                        f"UPDATE idempotency_records SET {assignment} WHERE key_hash = ?",
                        (*values, key_hash),
                    )
                    connection.commit()

                lookup = store.lookup_idempotency(
                    key_hash=key_hash,
                    request_hash=request_hash,
                    owner_instance_id="owner-b",
                )
                reclaimed = store.claim_idempotency(
                    key_hash=key_hash,
                    request_hash=request_hash,
                    owner_instance_id="owner-b",
                    expires_at=datetime.now(UTC) + timedelta(hours=1),
                )

                self.assertEqual("claimed", claimed.kind)
                self.assertIsNotNone(lookup)
                self.assertEqual("unavailable", lookup.kind if lookup else None)
                self.assertEqual("unavailable", reclaimed.kind)

    def test_inputs_are_validated_without_echoing_sensitive_values(self) -> None:
        bad_values = (
            {"key_hash": "RAW-KEY-secret"},
            {"request_hash": "RAW-BODY-secret"},
            {"owner_instance_id": "owner secret"},
            {"expires_at": datetime.now()},
            {"max_records": 0},
        )
        for override in bad_values:
            with self.subTest(field=next(iter(override))):
                with self.assertRaises((TypeError, ValueError)) as caught:
                    self.claim(**override)  # type: ignore[arg-type]
                self.assertNotIn(str(next(iter(override.values()))), str(caught.exception))

        self.assertEqual("claimed", self.claim().kind)
        invalid_completions = (
            {"response_status": 99},
            {"response_status": 100},
            {"response_status": 199},
            {"response_status": 600},
            {"response_status": True},
            {"response_json": "not-json-secret"},
            {"response_json": json.dumps({"value": math.nan})},
            {"response_json": json.dumps({"value": "x" * 1_000_001})},
        )
        for override in invalid_completions:
            with self.subTest(field=next(iter(override))):
                with self.assertRaises((TypeError, ValueError)) as caught:
                    self.complete(**override)  # type: ignore[arg-type]
                self.assertNotIn("not-json-secret", str(caught.exception))

    def test_database_contains_hashes_but_no_raw_key_or_body(self) -> None:
        raw_key = "deploy.secret-key"
        raw_body = '{"private":"raw-body-secret"}'
        key_hash = hash_key(raw_key)
        request_hash = canonical_request_hash("POST", "/bots", {}, json.loads(raw_body))

        claimed = self.store.claim_idempotency(
            key_hash=key_hash,
            request_hash=request_hash,
            owner_instance_id="owner-a",
            expires_at=self.future,
        )
        self.assertEqual("claimed", claimed.kind)

        database_bytes = self.database.read_bytes()
        self.assertNotIn(raw_key.encode(), database_bytes)
        self.assertNotIn(raw_body.encode(), database_bytes)
        self.assertNotIn(b"raw-body-secret", database_bytes)
        self.assertIn(key_hash.encode(), database_bytes)
        self.assertIn(request_hash.encode(), database_bytes)

    def test_settings_defaults_and_exact_bounds(self) -> None:
        defaults = Settings.from_env({})
        self.assertEqual(86_400, defaults.api_idempotency_retention_seconds)
        self.assertEqual(10_000, defaults.api_idempotency_max_records)

        minimums = Settings.from_env(
            {
                "ZEUS_API_IDEMPOTENCY_RETENTION_SECONDS": "60",
                "ZEUS_API_IDEMPOTENCY_MAX_RECORDS": "100",
            }
        )
        maximums = Settings.from_env(
            {
                "ZEUS_API_IDEMPOTENCY_RETENTION_SECONDS": "604800",
                "ZEUS_API_IDEMPOTENCY_MAX_RECORDS": "1000000",
            }
        )
        self.assertEqual(
            (60, 100),
            (
                minimums.api_idempotency_retention_seconds,
                minimums.api_idempotency_max_records,
            ),
        )
        self.assertEqual(
            (604_800, 1_000_000),
            (
                maximums.api_idempotency_retention_seconds,
                maximums.api_idempotency_max_records,
            ),
        )

        for name, value in (
            ("ZEUS_API_IDEMPOTENCY_RETENTION_SECONDS", "59"),
            ("ZEUS_API_IDEMPOTENCY_RETENTION_SECONDS", "604801"),
            ("ZEUS_API_IDEMPOTENCY_MAX_RECORDS", "99"),
            ("ZEUS_API_IDEMPOTENCY_MAX_RECORDS", "1000001"),
        ):
            with self.subTest(name=name, value=value), self.assertRaisesRegex(ValueError, name):
                Settings.from_env({name: value})


if __name__ == "__main__":
    unittest.main()
