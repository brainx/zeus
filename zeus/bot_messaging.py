"""Explicit operator submissions to one verified Hermes gateway."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from zeus import hermes_runs_client as client
from zeus.bot_diagnostics import _pending, _read_record, _record_identity
from zeus.gateway_marker import GatewayGeneration, parse_runtime_marker
from zeus.hermes_diagnostics import probe_gateway_health
from zeus.hermes_profile_environment import load_hermes_profile_environment
from zeus.message_store import MessageReceipt, MessageStore
from zeus.messaging_policy import MessagePolicyError, load_message_policy
from zeus.models import BotRecord, BotStatus, DesiredState, validate_id
from zeus.supervisor import Supervisor

MAX_INPUT_CHARACTERS = 16_000
MAX_INPUT_BYTES = 64 * 1024


class MessagingError(ValueError):
    """A fixed safe operator error; never includes remote text or credentials."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _hash(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _input_hash(input_text: str) -> str:
    if not isinstance(input_text, str) or not input_text.strip():
        raise MessagingError("invalid_input")
    try:
        encoded = input_text.encode("utf-8")
    except UnicodeError as exc:
        raise MessagingError("invalid_input") from exc
    if len(input_text) > MAX_INPUT_CHARACTERS or len(encoded) > MAX_INPUT_BYTES:
        raise MessagingError("input_too_large")
    # Hash the exact submitted JSON value. Whitespace is meaningful; retries
    # never silently normalize or substitute the operator's message.
    return _hash({"input": input_text})


def _request_hash(request_key: str | None) -> str | None:
    if request_key is None:
        return None
    if (
        not isinstance(request_key, str)
        or not 1 <= len(request_key) <= 255
        or any(not 33 <= ord(char) <= 126 for char in request_key)
    ):
        raise MessagingError("invalid_request_key")
    return _hash(request_key)


@dataclass(frozen=True)
class _Target:
    record: BotRecord
    generation: GatewayGeneration
    endpoint: str
    api_key: str
    credential_fingerprint: str
    policy_fingerprint: str | None
    fingerprint: str

    def identity(self) -> tuple[object, ...]:
        return (
            _record_identity(self.record),
            self.generation,
            self.endpoint,
            self.credential_fingerprint,
            self.policy_fingerprint,
        )


def _public(receipt: MessageReceipt) -> dict[str, object]:
    return {
        "message_id": receipt.message_id,
        "bot_id": receipt.target_bot_id,
        "dispatch_state": receipt.dispatch_state,
        "run_id": receipt.run_id,
        "run_status": receipt.run_status,
        "created_at": receipt.created_at.isoformat(),
        "updated_at": receipt.updated_at.isoformat(),
        "retry_before": receipt.retry_before.isoformat(),
        "last_checked_at": (
            receipt.last_checked_at.isoformat() if receipt.last_checked_at else None
        ),
        "cancel_requested_at": (
            receipt.cancel_requested_at.isoformat() if receipt.cancel_requested_at else None
        ),
        "error_code": receipt.error_code,
    }


class BotMessaging:
    def __init__(
        self,
        supervisor: Supervisor,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.supervisor = supervisor
        self.store = MessageStore(supervisor.store.database_path)
        self.clock = clock or (lambda: datetime.now(UTC))

    def _target(self, bot_id: str, *, sending: bool) -> _Target:
        validate_id(bot_id, "bot_id")
        record = _read_record(self.supervisor, bot_id)
        if record is None:
            raise MessagingError("unknown_bot")
        if _pending(record):
            raise MessagingError("operation_pending")
        if type(record.pid) is not int or record.pid <= 0:
            raise MessagingError("process_unverified")
        if sending and (
            record.status is not BotStatus.running
            or record.desired_state is not DesiredState.running
        ):
            raise MessagingError("bot_not_running")
        runtime = self.supervisor._runtime
        try:
            observed = runtime.read_strict_runtime_marker(bot_id, record.profile_path)
            payload = observed.payload
            if observed.kind != "present" or payload is None:
                raise MessagingError("process_unverified")
            classified = runtime.classify_schema3_runtime_marker(
                record,
                payload,
                expected_pid=record.pid,
                expected_revision=record.desired_revision,
                require_live_command=True,
            )
            if classified.kind != "live":
                raise MessagingError("process_unverified")
            marker = parse_runtime_marker(payload)
            if marker.readiness_probe is None:
                raise MessagingError("endpoint_unavailable")
            profile = Path(record.profile_path)
            policy_fingerprint = None
            if sending:
                policy = load_message_policy(profile)
                policy_fingerprint = policy.fingerprint
                if payload.get("messaging_policy_fingerprint") != policy_fingerprint:
                    raise MessagingError("policy_restart_required")
                api_key = policy.api_key
                credential_fingerprint = policy.credential_fingerprint
            else:
                environment = load_hermes_profile_environment(profile / ".env")
                api_key = environment.get("API_SERVER_KEY", "")
                credential_fingerprint = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
            if not 16 <= len(api_key) <= 4096 or any(
                not 33 <= ord(char) <= 126 for char in api_key
            ):
                raise MessagingError("credentials_unavailable")
        except MessagePolicyError as exc:
            raise MessagingError(exc.code) from exc
        except MessagingError:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise MessagingError("configuration_invalid") from exc
        endpoint = marker.readiness_probe.url
        fingerprint = _hash(
            [
                record.bot_id,
                record.created_at.isoformat(),
                record.profile_path,
                endpoint,
                credential_fingerprint,
                policy_fingerprint,
            ]
        )
        return _Target(
            record,
            marker.generation(),
            endpoint,
            api_key,
            credential_fingerprint,
            policy_fingerprint,
            fingerprint,
        )

    def _unchanged(self, target: _Target, *, sending: bool) -> bool:
        try:
            return (
                self._target(target.record.bot_id, sending=sending).identity() == target.identity()
            )
        except (OSError, RuntimeError, TypeError, ValueError):
            return False

    def _verified_target(self, bot_id: str, *, sending: bool) -> _Target:
        target = self._target(bot_id, sending=sending)
        return self._verify_health(target, sending=sending)

    def _verify_health(self, target: _Target, *, sending: bool) -> _Target:
        reason, health = probe_gateway_health(
            target.endpoint, api_key=target.api_key, expected_pid=target.generation.pid
        )
        if (
            reason not in ({"ok"} if sending else {"ok", "degraded"})
            or health is None
            or health.get("pid") != target.generation.pid
            or health.get("version") != "0.21.0"
        ):
            raise MessagingError("health_unavailable")
        if not self._unchanged(target, sending=sending):
            raise MessagingError("runtime_changed")
        return target

    def _receipt(self, message_id: str) -> MessageReceipt:
        receipt = self.store.get(message_id)
        if receipt is None:
            raise MessagingError("unknown_message")
        if self.clock() < receipt.updated_at:
            raise MessagingError("clock_rollback")
        return receipt

    def _receipt_target(self, receipt: MessageReceipt, *, sending: bool) -> _Target:
        target = self._target(receipt.target_bot_id, sending=sending)
        if (
            target.record.created_at != receipt.target_created_at
            or target.endpoint != receipt.endpoint
            or target.credential_fingerprint != receipt.credential_fingerprint
            or (sending and target.fingerprint != receipt.target_fingerprint)
        ):
            raise MessagingError("target_changed")
        return self._verify_health(target, sending=sending)

    @staticmethod
    def _retry_seconds(advertised: dict[str, object]) -> float:
        features = cast(dict[str, object], advertised["features"])
        idempotency = cast(dict[str, object], features["runs_idempotency"])
        retention = idempotency["retention_seconds"]
        if (
            isinstance(retention, bool)
            or not isinstance(retention, int | float)
            or not math.isfinite(retention)
            or retention <= 60
        ):
            raise MessagingError("idempotency_unavailable")
        return min(retention / 2, 3600)

    def send(
        self, bot_id: str, input_text: str, *, request_key: str | None = None
    ) -> dict[str, object]:
        input_fingerprint = _input_hash(input_text)
        key_fingerprint = _request_hash(request_key)
        target = self._verified_target(bot_id, sending=True)
        advertised = client.capabilities(target.endpoint, target.api_key)
        retry_seconds = self._retry_seconds(advertised)
        if not self._unchanged(target, sending=True):
            raise MessagingError("runtime_changed")
        now = self.clock()
        receipt, created = self.store.prepare(
            bot_id=bot_id,
            incarnation=target.record.created_at,
            target_fingerprint=target.fingerprint,
            endpoint=target.endpoint,
            credential_fingerprint=target.credential_fingerprint,
            input_fingerprint=input_fingerprint,
            request_key_fingerprint=key_fingerprint,
            now=now,
            retry_before=now + timedelta(seconds=retry_seconds),
        )
        if not created:
            return _public(receipt)
        return self._submit(receipt, target, input_text, retrying=False)

    def retry(self, message_id: str, input_text: str) -> dict[str, object]:
        input_fingerprint = _input_hash(input_text)
        receipt = self._receipt(message_id)
        if input_fingerprint != receipt.request_hash:
            raise MessagingError("request_conflict")
        if receipt.dispatch_state == "accepted":
            return _public(receipt)
        target = self._receipt_target(receipt, sending=True)
        advertised = client.capabilities(target.endpoint, target.api_key)
        retry_seconds = self._retry_seconds(advertised)
        now = self.clock()
        if now >= receipt.created_at + timedelta(seconds=retry_seconds):
            raise MessagingError("retry_expired")
        if not self._unchanged(target, sending=True):
            raise MessagingError("runtime_changed")
        claimed = self.store.claim_retry(
            receipt.message_id, expected_version=receipt.version, now=now
        )
        return self._submit(claimed, target, input_text, retrying=True)

    def _submit(
        self, receipt: MessageReceipt, target: _Target, input_text: str, *, retrying: bool
    ) -> dict[str, object]:
        current = self.store.get(receipt.message_id)
        if (
            current is None
            or current.version != receipt.version
            or current.dispatch_state != "unknown"
            or current.lease_until is None
        ):
            raise MessagingError("receipt_changed")
        # Reserving the receipt can wait for SQLite. Recheck immediately after
        # that wait, before using any captured credential or dispatch endpoint.
        if not self._unchanged(target, sending=True):
            return _public(
                self.store.finish_attempt(
                    receipt.message_id,
                    expected_version=receipt.version,
                    dispatch_state="unknown",
                    error_code="runtime_changed",
                    now=self.clock(),
                )
            )
        # Re-read ownership above and leave the complete transport budget inside
        # both time bounds. A suspended or superseded caller gets no new POST.
        now = self.clock()
        if now < current.updated_at:
            raise MessagingError("clock_rollback")
        if now + timedelta(seconds=2) >= current.retry_before:
            raise MessagingError("retry_expired")
        if now + timedelta(seconds=2) >= current.lease_until:
            raise MessagingError("attempt_expired")
        error_code = None
        dispatch_state = "unknown"
        run_id = run_status = None
        try:
            response = client.submit(
                target.endpoint, target.api_key, input_text, receipt.upstream_key
            )
            run_id = cast(str, response["run_id"])
            run_status = cast(str, response["status"])
            if run_status == "started":
                run_status = "running"
            dispatch_state = "accepted"
        except client.HermesRunsClientError as exc:
            error_code = exc.code
            # A definite failure of a retry cannot disprove the earlier,
            # unacknowledged attempt. Keep that receipt blocking new sends.
            if not exc.uncertain and not retrying:
                dispatch_state = "rejected"
        except BaseException:
            self.store.finish_attempt(
                receipt.message_id,
                expected_version=receipt.version,
                dispatch_state="unknown",
                error_code="interrupted",
                now=self.clock(),
            )
            raise
        if not self._unchanged(target, sending=True):
            dispatch_state, error_code = "unknown", "runtime_changed"
            run_id = run_status = None
        updated = self.store.finish_attempt(
            receipt.message_id,
            expected_version=receipt.version,
            dispatch_state=dispatch_state,
            run_id=run_id,
            run_status=run_status,
            error_code=error_code,
            now=self.clock(),
        )
        return _public(updated)

    def status(self, message_id: str) -> dict[str, object]:
        receipt = self._receipt(message_id)
        if receipt.run_id is None:
            return _public(receipt)
        target = self._receipt_target(receipt, sending=False)
        result = client.status(target.endpoint, target.api_key, receipt.run_id, include_output=True)
        if not self._unchanged(target, sending=False):
            raise MessagingError("runtime_changed")
        updated = self.store.update_run(
            receipt.message_id,
            expected_version=receipt.version,
            run_status=cast(str, result["status"]),
            now=self.clock(),
        )
        payload = _public(updated)
        payload["run"] = result
        return payload

    def cancel(self, message_id: str) -> dict[str, object]:
        receipt = self._receipt(message_id)
        if receipt.run_id is None:
            raise MessagingError("run_unacknowledged")
        target = self._receipt_target(receipt, sending=False)
        receipt = self.store.update_run(
            receipt.message_id,
            expected_version=receipt.version,
            run_status=cast(str, receipt.run_status),
            now=self.clock(),
            cancel_requested=True,
        )
        if not self._unchanged(target, sending=False):
            raise MessagingError("runtime_changed")
        result = client.stop(target.endpoint, target.api_key, cast(str, receipt.run_id))
        if not self._unchanged(target, sending=False):
            raise MessagingError("runtime_changed")
        updated = self.store.update_run(
            receipt.message_id,
            expected_version=receipt.version,
            run_status=cast(str, result["status"]),
            now=self.clock(),
        )
        return _public(updated)

    def list(
        self, *, bot_id: str | None = None, limit: int = 50, before: str | None = None
    ) -> dict[str, object]:
        result = self.store.list(bot_id=bot_id, limit=limit, before=before)
        return {
            "items": [_public(receipt) for receipt in cast(list[MessageReceipt], result["items"])],
            "next_before": result["next_before"],
        }
