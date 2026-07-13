from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Protocol

from zeus.models import BotRecord, BotStatus, BotStatusResponse, DesiredState
from zeus.process_lock import BotProcessLock, LockTimeoutError

MAX_RECONCILE_ID_LENGTH = 128
MAX_RECONCILE_TEXT_LENGTH = 2048

_RECONCILE_SCOPES = frozenset({"bot", "fleet"})
_SUMMARY_OUTCOMES = frozenset({"succeeded", "completed_with_errors"})
_PERSISTED_RUN_OUTCOMES = frozenset(
    {"running", "succeeded", "completed_with_errors", "interrupted"}
)


class ReconcileOutcome(StrEnum):
    healthy = "healthy"
    changed = "changed"
    pending = "pending"
    action_required = "action_required"
    error = "error"
    skipped = "skipped"


class ReconcileSnapshotDriftError(RuntimeError):
    """The bot captured by a run snapshot was deleted or replaced before execution."""


class ReconcileLockTimeoutError(LockTimeoutError):
    """The global reconciliation coordinator lock could not be acquired."""


def _validate_required_text(value: str, name: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{name} must be a non-empty string of at most {maximum} characters")
    if any(ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F for character in value):
        raise ValueError(f"{name} must not contain control characters")
    return value


def _bound_text(value: str, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value[:MAX_RECONCILE_TEXT_LENGTH]


def _bound_optional_text(value: str | None, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string when provided")
    return value[:MAX_RECONCILE_TEXT_LENGTH]


def _validate_timestamp(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime")
    return value


def _validate_positive_optional_int(value: int | None, name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer when provided")
    return value


def _validate_run_metadata(
    *,
    scope: str,
    requested_bot_id: str | None,
    source: str,
    force: bool,
    reset_restart: bool,
) -> None:
    if scope not in _RECONCILE_SCOPES:
        raise ValueError("scope must be bot or fleet")
    if scope == "fleet" and requested_bot_id is not None:
        raise ValueError("fleet reconciliation must not specify requested_bot_id")
    if scope == "bot" and requested_bot_id is None:
        raise ValueError("bot reconciliation requires requested_bot_id")
    if requested_bot_id is not None:
        _validate_required_text(
            requested_bot_id,
            "requested_bot_id",
            maximum=MAX_RECONCILE_ID_LENGTH,
        )
    _validate_required_text(source, "source", maximum=MAX_RECONCILE_ID_LENGTH)
    if type(force) is not bool:
        raise ValueError("force must be a boolean")
    if type(reset_restart) is not bool:
        raise ValueError("reset_restart must be a boolean")


@dataclass(frozen=True)
class BotReconcileResult:
    bot_id: str
    outcome: ReconcileOutcome
    desired_state: str | None
    observed_status: str | None
    pid: int | None
    action: str
    message: str
    error_code: str | None
    event_id: int | None
    started_at: datetime
    finished_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "bot_id",
            _validate_required_text(
                self.bot_id,
                "bot_id",
                maximum=MAX_RECONCILE_ID_LENGTH,
            ),
        )
        try:
            object.__setattr__(self, "outcome", ReconcileOutcome(self.outcome))
        except (TypeError, ValueError) as error:
            raise ValueError("outcome must be a recognized reconciliation outcome") from error
        if self.desired_state is not None:
            try:
                desired_state = DesiredState(self.desired_state).value
            except (TypeError, ValueError) as error:
                raise ValueError("desired_state must be running or stopped") from error
            object.__setattr__(self, "desired_state", desired_state)
        if self.observed_status is not None:
            try:
                observed_status = BotStatus(self.observed_status).value
            except (TypeError, ValueError) as error:
                raise ValueError("observed_status must be a recognized bot status") from error
            object.__setattr__(self, "observed_status", observed_status)
        object.__setattr__(self, "pid", _validate_positive_optional_int(self.pid, "pid"))
        object.__setattr__(self, "action", _bound_text(self.action, "action"))
        object.__setattr__(self, "message", _bound_text(self.message, "message"))
        object.__setattr__(
            self,
            "error_code",
            _bound_optional_text(self.error_code, "error_code"),
        )
        object.__setattr__(
            self,
            "event_id",
            _validate_positive_optional_int(self.event_id, "event_id"),
        )
        started_at = _validate_timestamp(self.started_at, "started_at")
        finished_at = _validate_timestamp(self.finished_at, "finished_at")
        if finished_at < started_at:
            raise ValueError("finished_at must not be earlier than started_at")

    def to_dict(self) -> dict[str, object]:
        return {
            "bot_id": self.bot_id,
            "outcome": self.outcome.value,
            "desired_state": self.desired_state,
            "observed_status": self.observed_status,
            "pid": self.pid,
            "action": self.action,
            "message": self.message,
            "error_code": self.error_code,
            "event_id": self.event_id,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
        }


@dataclass(frozen=True)
class ReconcileRunStart:
    """Immutable run metadata persisted before any per-bot result exists."""

    run_id: str
    scope: str
    requested_bot_id: str | None
    source: str
    force: bool
    reset_restart: bool
    started_at: datetime

    def __post_init__(self) -> None:
        _validate_required_text(
            self.run_id,
            "run_id",
            maximum=MAX_RECONCILE_ID_LENGTH,
        )
        _validate_run_metadata(
            scope=self.scope,
            requested_bot_id=self.requested_bot_id,
            source=self.source,
            force=self.force,
            reset_restart=self.reset_restart,
        )
        _validate_timestamp(self.started_at, "started_at")


@dataclass(frozen=True)
class PersistedReconcileRun:
    """Immutable loaded form that can represent running and interrupted runs."""

    run_id: str
    scope: str
    requested_bot_id: str | None
    source: str
    force: bool
    reset_restart: bool
    started_at: datetime
    finished_at: datetime | None
    outcome: str
    total: int
    counts: Mapping[str, int]
    results: tuple[BotReconcileResult, ...]

    def __post_init__(self) -> None:
        _validate_required_text(
            self.run_id,
            "run_id",
            maximum=MAX_RECONCILE_ID_LENGTH,
        )
        _validate_run_metadata(
            scope=self.scope,
            requested_bot_id=self.requested_bot_id,
            source=self.source,
            force=self.force,
            reset_restart=self.reset_restart,
        )
        started_at = _validate_timestamp(self.started_at, "started_at")
        if self.outcome not in _PERSISTED_RUN_OUTCOMES:
            raise ValueError("invalid persisted reconciliation outcome")
        if self.outcome == "running":
            if self.finished_at is not None:
                raise ValueError("running reconciliation must not have finished_at")
        else:
            if self.finished_at is None:
                raise ValueError("finished reconciliation requires finished_at")
            finished_at = _validate_timestamp(self.finished_at, "finished_at")
            if finished_at < started_at:
                raise ValueError("finished_at must not be earlier than started_at")
        results = tuple(self.results)
        if any(not isinstance(result, BotReconcileResult) for result in results):
            raise ValueError("results must contain only BotReconcileResult values")
        bot_ids = [result.bot_id for result in results]
        if len(set(bot_ids)) != len(bot_ids):
            raise ValueError("results must contain at most one result per bot")
        if self.scope == "bot" and any(
            result.bot_id != self.requested_bot_id for result in results
        ):
            raise ValueError("bot reconciliation result must match the requested bot")
        for result in results:
            if result.started_at < started_at:
                raise ValueError("reconciliation result starts before its run")
            if self.finished_at is not None and result.finished_at > self.finished_at:
                raise ValueError("reconciliation result finishes after its run")
        if isinstance(self.total, bool) or not isinstance(self.total, int) or self.total < 0:
            raise ValueError("total must be a non-negative integer")
        if self.total != len(results):
            raise ValueError("total must equal the number of results")
        expected_keys = tuple(outcome.value for outcome in ReconcileOutcome)
        if set(self.counts) != set(expected_keys):
            raise ValueError("counts must contain exactly one counter for every result outcome")
        counts: dict[str, int] = {}
        for key in expected_keys:
            value = self.counts[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("reconciliation counters must be non-negative integers")
            counts[key] = value
        observed_counts = {key: 0 for key in expected_keys}
        for result in results:
            observed_counts[result.outcome.value] += 1
        if counts != observed_counts or sum(counts.values()) != self.total:
            raise ValueError("counts must exactly match persisted result outcomes")
        if self.outcome == "succeeded" and (
            counts[ReconcileOutcome.action_required.value] > 0
            or counts[ReconcileOutcome.error.value] > 0
        ):
            raise ValueError("succeeded reconciliation cannot contain unsuccessful results")
        if self.outcome == "completed_with_errors" and (
            counts[ReconcileOutcome.action_required.value] == 0
            and counts[ReconcileOutcome.error.value] == 0
        ):
            raise ValueError("completed_with_errors requires an unsuccessful result")
        object.__setattr__(self, "counts", MappingProxyType(counts))
        object.__setattr__(self, "results", results)


@dataclass(frozen=True)
class ReconcileRunSummary:
    run_id: str
    scope: str
    started_at: datetime
    finished_at: datetime
    outcome: str
    total: int
    counts: Mapping[str, int]
    results: tuple[BotReconcileResult, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "run_id",
            _validate_required_text(
                self.run_id,
                "run_id",
                maximum=MAX_RECONCILE_ID_LENGTH,
            ),
        )
        if self.scope not in _RECONCILE_SCOPES:
            raise ValueError("scope must be bot or fleet")
        started_at = _validate_timestamp(self.started_at, "started_at")
        finished_at = _validate_timestamp(self.finished_at, "finished_at")
        if finished_at < started_at:
            raise ValueError("finished_at must not be earlier than started_at")
        if self.outcome not in _SUMMARY_OUTCOMES:
            raise ValueError("outcome must be succeeded or completed_with_errors")
        results = tuple(self.results)
        if any(not isinstance(result, BotReconcileResult) for result in results):
            raise ValueError("results must contain only BotReconcileResult values")
        bot_ids = [result.bot_id for result in results]
        if len(set(bot_ids)) != len(bot_ids):
            raise ValueError("results must contain at most one result per bot")
        for result in results:
            if result.started_at < started_at:
                raise ValueError("reconciliation result starts before its run")
            if result.finished_at > finished_at:
                raise ValueError("reconciliation result finishes after its run")
        if isinstance(self.total, bool) or not isinstance(self.total, int) or self.total < 0:
            raise ValueError("total must be a non-negative integer")
        if self.total != len(results):
            raise ValueError("total must equal the number of results")
        expected_keys = tuple(outcome.value for outcome in ReconcileOutcome)
        if set(self.counts) != set(expected_keys):
            raise ValueError("counts must contain exactly one counter for every result outcome")
        counts: dict[str, int] = {}
        for key in expected_keys:
            value = self.counts[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("reconciliation counters must be non-negative integers")
            counts[key] = value
        if sum(counts.values()) != self.total:
            raise ValueError("the sum of reconciliation counters must equal total")
        observed_counts = {key: 0 for key in expected_keys}
        for result in results:
            observed_counts[result.outcome.value] += 1
        if counts != observed_counts:
            raise ValueError("counts must exactly match result outcomes")
        expected_outcome = (
            "completed_with_errors"
            if counts[ReconcileOutcome.action_required.value] > 0
            or counts[ReconcileOutcome.error.value] > 0
            else "succeeded"
        )
        if self.outcome != expected_outcome:
            raise ValueError("outcome must match the aggregate result counters")
        object.__setattr__(self, "counts", MappingProxyType(counts))
        object.__setattr__(self, "results", results)

    @property
    def ok(self) -> bool:
        return (
            self.counts[ReconcileOutcome.action_required.value] == 0
            and self.counts[ReconcileOutcome.error.value] == 0
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "scope": self.scope,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "outcome": self.outcome,
            "ok": self.ok,
            "counts": {outcome.value: self.counts[outcome.value] for outcome in ReconcileOutcome},
            "total": self.total,
            "results": [result.to_dict() for result in self.results],
        }


@dataclass(frozen=True)
class ReconcileExecution:
    summary: ReconcileRunSummary
    legacy_responses: tuple[BotStatusResponse, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.summary, ReconcileRunSummary):
            raise TypeError("summary must be a ReconcileRunSummary")
        responses = tuple(self.legacy_responses)
        if any(not isinstance(response, BotStatusResponse) for response in responses):
            raise TypeError("legacy_responses must contain BotStatusResponse values")
        object.__setattr__(self, "legacy_responses", responses)


def summarize_results(
    run_id: str,
    scope: str,
    results: Iterable[BotReconcileResult],
    *,
    started_at: datetime,
    finished_at: datetime,
) -> ReconcileRunSummary:
    ordered_results = tuple(results)
    counts = {outcome.value: 0 for outcome in ReconcileOutcome}
    for result in ordered_results:
        if not isinstance(result, BotReconcileResult):
            raise ValueError("results must contain only BotReconcileResult values")
        counts[result.outcome.value] += 1
    outcome = (
        "completed_with_errors"
        if counts[ReconcileOutcome.action_required.value] > 0
        or counts[ReconcileOutcome.error.value] > 0
        else "succeeded"
    )
    return ReconcileRunSummary(
        run_id=run_id,
        scope=scope,
        started_at=started_at,
        finished_at=finished_at,
        outcome=outcome,
        total=len(ordered_results),
        counts=counts,
        results=ordered_results,
    )


class _ReconciliationStore(Protocol):
    database_path: Path

    def list_bots(self) -> list[BotRecord]: ...

    def get_bot(self, bot_id: str) -> BotRecord | None: ...

    def interrupt_stale_reconcile_runs(self, *, interrupted_at: datetime) -> int: ...

    def begin_reconcile_run(self, run: ReconcileRunStart) -> None: ...

    def append_reconcile_result(self, run_id: str, result: BotReconcileResult) -> None: ...

    def finish_reconcile_run(self, summary: ReconcileRunSummary) -> PersistedReconcileRun: ...


class _ReconciliationSupervisor(Protocol):
    lock_timeout_seconds: float

    def validate_reconcile_request(self, source: str, request_id: str | None) -> None: ...

    def validate_reconcile_target(
        self,
        bot_id: str,
        *,
        expected_profile_path: str | None = None,
    ) -> str: ...

    def reconcile_one_execution(
        self,
        bot_id: str,
        *,
        now: datetime | None = None,
        force: bool = False,
        reset_restart: bool = False,
        source: str = "reconcile",
        request_id: str | None = None,
        expected_profile_path: str | None = None,
    ) -> tuple[BotReconcileResult, BotStatusResponse]: ...


class FleetReconciler:
    """Persist one serialized, fault-isolated reconciliation run."""

    def __init__(
        self,
        store: _ReconciliationStore,
        supervisor: _ReconciliationSupervisor,
        *,
        lock_timeout_seconds: float | None = None,
    ) -> None:
        self.store = store
        self.supervisor = supervisor
        self.lock_timeout_seconds = (
            supervisor.lock_timeout_seconds
            if lock_timeout_seconds is None
            else lock_timeout_seconds
        )
        self.legacy_responses: tuple[BotStatusResponse, ...] = ()

    def run(
        self,
        bot_id: str | None = None,
        *,
        now: datetime | None = None,
        force: bool = False,
        reset_restart: bool = False,
        source: str = "reconcile",
        request_id: str | None = None,
        bot_snapshot: Iterable[tuple[str, str]] | None = None,
    ) -> ReconcileRunSummary:
        return self.execute(
            bot_id,
            now=now,
            force=force,
            reset_restart=reset_restart,
            source=source,
            request_id=request_id,
            bot_snapshot=bot_snapshot,
        ).summary

    def execute(
        self,
        bot_id: str | None = None,
        *,
        now: datetime | None = None,
        force: bool = False,
        reset_restart: bool = False,
        source: str = "reconcile",
        request_id: str | None = None,
        bot_snapshot: Iterable[tuple[str, str]] | None = None,
    ) -> ReconcileExecution:
        if bot_id is not None and bot_snapshot is not None:
            raise ValueError("bot_snapshot is only valid for fleet reconciliation")
        self.supervisor.validate_reconcile_request(source, request_id)
        self.legacy_responses = ()
        lock_path = self.store.database_path.parent / "locks" / "reconcile.lock"
        coordinator_lock = BotProcessLock(
            lock_path,
            timeout_seconds=self.lock_timeout_seconds,
        )
        try:
            coordinator_lock.__enter__()
        except LockTimeoutError as error:
            raise ReconcileLockTimeoutError(lock_path, self.lock_timeout_seconds) from error
        try:
            return self._execute_locked(
                bot_id,
                now=now,
                force=force,
                reset_restart=reset_restart,
                source=source,
                request_id=request_id,
                bot_snapshot=bot_snapshot,
            )
        finally:
            coordinator_lock.__exit__(None, None, None)

    def _execute_locked(
        self,
        bot_id: str | None,
        *,
        now: datetime | None,
        force: bool,
        reset_restart: bool,
        source: str,
        request_id: str | None,
        bot_snapshot: Iterable[tuple[str, str]] | None,
    ) -> ReconcileExecution:
        started_at = datetime.now(UTC)
        self.store.interrupt_stale_reconcile_runs(interrupted_at=started_at)
        if bot_id is not None:
            explicit_profile_path = self.supervisor.validate_reconcile_target(bot_id)
            snapshot: tuple[tuple[str, str | None], ...] = ((bot_id, explicit_profile_path),)
            scope = "bot"
        else:
            snapshot = self._fleet_snapshot(bot_snapshot)
            scope = "fleet"
        run = ReconcileRunStart(
            run_id=uuid.uuid4().hex,
            scope=scope,
            requested_bot_id=bot_id,
            source=source,
            force=force,
            reset_restart=reset_restart,
            started_at=started_at,
        )
        self.store.begin_reconcile_run(run)
        results: list[BotReconcileResult] = []
        legacy_responses: list[BotStatusResponse] = []
        for current_bot_id, expected_profile_path in snapshot:
            result_started_at = datetime.now(UTC)
            legacy_response: BotStatusResponse | None = None
            try:
                result, legacy_response = self.supervisor.reconcile_one_execution(
                    current_bot_id,
                    now=now,
                    force=force,
                    reset_restart=reset_restart,
                    source=source,
                    request_id=request_id,
                    expected_profile_path=expected_profile_path,
                )
            except ReconcileSnapshotDriftError:
                result, legacy_response = self._snapshot_drift_outcome(
                    scope,
                    current_bot_id,
                    expected_profile_path,
                    result_started_at,
                )
            except Exception as exc:
                try:
                    result = self._error_result(
                        current_bot_id,
                        result_started_at,
                        exc,
                        expected_profile_path=expected_profile_path,
                    )
                except ReconcileSnapshotDriftError:
                    result, legacy_response = self._snapshot_drift_outcome(
                        scope,
                        current_bot_id,
                        expected_profile_path,
                        result_started_at,
                    )
                else:
                    legacy_response = self._error_legacy_response(
                        result,
                        expected_profile_path=expected_profile_path,
                    )
            self.store.append_reconcile_result(run.run_id, result)
            results.append(result)
            if legacy_response is not None:
                legacy_responses.append(legacy_response)
        summary = summarize_results(
            run.run_id,
            scope,
            results,
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )
        self.store.finish_reconcile_run(summary)
        execution = ReconcileExecution(summary, tuple(legacy_responses))
        self.legacy_responses = execution.legacy_responses
        return execution

    def _fleet_snapshot(
        self,
        supplied: Iterable[tuple[str, str]] | None,
    ) -> tuple[tuple[str, str], ...]:
        if supplied is not None:
            snapshot = tuple(supplied)
            bot_ids = [bot_id for bot_id, _profile_path in snapshot]
            if len(set(bot_ids)) != len(bot_ids):
                raise ValueError("bot_snapshot must not contain duplicate bot IDs")
            return snapshot
        records = self.store.list_bots()
        return tuple(
            sorted(
                ((record.bot_id, record.profile_path) for record in records),
                key=lambda item: item[0],
            )
        )

    def _skipped_result(self, bot_id: str, started_at: datetime) -> BotReconcileResult:
        return BotReconcileResult(
            bot_id=bot_id,
            outcome=ReconcileOutcome.skipped,
            desired_state=None,
            observed_status=None,
            pid=None,
            action="skip",
            message="bot was deleted or replaced after the reconciliation snapshot",
            error_code="bot_missing",
            event_id=None,
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )

    def _snapshot_drift_outcome(
        self,
        scope: str,
        bot_id: str,
        expected_profile_path: str | None,
        started_at: datetime,
    ) -> tuple[BotReconcileResult, BotStatusResponse | None]:
        if scope == "fleet":
            return self._skipped_result(bot_id, started_at), None
        result = BotReconcileResult(
            bot_id=bot_id,
            outcome=ReconcileOutcome.error,
            desired_state=None,
            observed_status=None,
            pid=None,
            action="reconcile",
            message="bot changed during reconciliation",
            error_code="snapshot_drift",
            event_id=None,
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )
        return result, BotStatusResponse(
            bot_id=bot_id,
            status=BotStatus.failed,
            pid=None,
            profile_path=expected_profile_path or "",
            message=result.message,
        )

    def _error_legacy_response(
        self,
        result: BotReconcileResult,
        *,
        expected_profile_path: str | None,
    ) -> BotStatusResponse | None:
        profile_path = expected_profile_path
        if profile_path is None:
            record = self.store.get_bot(result.bot_id)
            if record is None:
                return None
            profile_path = record.profile_path
        return BotStatusResponse(
            bot_id=result.bot_id,
            status=BotStatus.failed,
            pid=result.pid,
            profile_path=profile_path,
            message=result.message,
        )

    def _error_result(
        self,
        bot_id: str,
        started_at: datetime,
        error: Exception,
        *,
        expected_profile_path: str | None,
    ) -> BotReconcileResult:
        record = self.store.get_bot(bot_id)
        if expected_profile_path is not None and (
            record is None or record.profile_path != expected_profile_path
        ):
            raise ReconcileSnapshotDriftError(bot_id)
        desired_state = record.desired_state.value if record is not None else None
        observed_status = record.status.value if record is not None else None
        pid = record.pid if record is not None else None
        lock_timeout = isinstance(error, LockTimeoutError)
        return BotReconcileResult(
            bot_id=bot_id,
            outcome=ReconcileOutcome.error,
            desired_state=desired_state,
            observed_status=observed_status,
            pid=pid if type(pid) is int and pid > 0 else None,
            action="reconcile",
            message=(
                "bot reconciliation lock timed out" if lock_timeout else "bot reconciliation failed"
            ),
            error_code="lock_timeout" if lock_timeout else "reconcile_error",
            event_id=None,
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )
