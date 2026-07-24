"""Bounded single-query Hermes execution for repository audits."""

from __future__ import annotations

import math
import os
import re
import selectors
import stat
import subprocess  # nosec B404
import time
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from threading import Event
from typing import BinaryIO, NoReturn, Protocol, cast

from zeus.audit_config import AuditConfigError, validate_provider_selection
from zeus.audit_docker_broker import (
    AuditDockerBrokerState,
    BrokerCommandResult,
    cleanup_audit_docker_broker,
    read_audit_docker_broker_state,
)
from zeus.audit_models import HARD_LIMITS, AuditConfig
from zeus.audit_process import (
    AuditProcessError,
    observe_process_exit,
    stop_process_group,
)
from zeus.private_io import (
    UnsafeFileError,
    inspect_private_directory,
    pin_private_directory,
)
from zeus.sanitization import sanitize_text

_PROCESS_CHUNK = 64 * 1024
_POLL_SECONDS = 0.05
_TERM_GRACE_SECONDS = 0.2
_KILL_GRACE_SECONDS = 0.2
_DIAGNOSTIC_BYTES = 4096
_SYSTEM_PATH = "/usr/bin:/bin"
_PROFILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_SAFE_CALLER_ENV = (
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
)
_FORBIDDEN_PROVIDER_ENV = frozenset(
    {
        "HOME",
        "HERMES_HOME",
        "HERMES_DOCKER_BINARY",
        "PATH",
        "ALL_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
    }
)


class AuditRunnerError(RuntimeError):
    """Raised when the audit query cannot be launched safely."""


class AuditRunnerOutcome(StrEnum):
    completed = "completed"
    launch_failed = "launch_failed"
    process_failed = "process_failed"
    timed_out = "timed_out"
    cancelled = "cancelled"
    model_output_limit = "model_output_limit"
    stderr_output_limit = "stderr_output_limit"
    broker_breach = "broker_breach"
    invalid_output = "invalid_output"
    cleanup_failed = "cleanup_failed"


@dataclass(frozen=True)
class AuditRunnerResult:
    outcome: AuditRunnerOutcome
    model_result: object | None
    diagnostic: str | None
    returncode: int | None
    cleanup_complete: bool
    process_group_stopped: bool


class _BrokerStateReader(Protocol):
    def __call__(self, state_path: Path) -> AuditDockerBrokerState: ...


class _BrokerCleanup(Protocol):
    def __call__(self, state_path: Path) -> BrokerCommandResult: ...


@dataclass(frozen=True)
class _CapturedProcess:
    outcome: AuditRunnerOutcome
    stdout: bytes
    stderr: bytes
    returncode: int | None
    detail: str | None = None


def _error(message: str) -> NoReturn:
    raise AuditRunnerError(message)


def _validate_deadline(deadline: float) -> float:
    if (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(deadline)
    ):
        _error("audit runner deadline must be a finite monotonic timestamp")
    result = float(deadline)
    if result <= time.monotonic():
        _error("audit runner deadline has expired")
    return result


def _reject_path_separator(path: Path, description: str) -> None:
    if os.pathsep in os.fspath(path):
        _error(f"{description} contains the path separator")


def _validate_private_file(
    path: Path,
    *,
    parent: Path,
    name: str,
    mode: int,
    description: str,
) -> None:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or path.parent != parent
        or path.name != name
    ):
        _error(f"{description} path is invalid")
    try:
        result = path.lstat()
    except OSError as exc:
        raise AuditRunnerError(f"{description} is unavailable") from exc
    if (
        not stat.S_ISREG(result.st_mode)
        or stat.S_IMODE(result.st_mode) != mode
        or result.st_uid != os.geteuid()
    ):
        _error(f"{description} metadata is unsafe")


def _validate_hermes_executable(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        _error("Hermes executable must be an absolute pathlib.Path")
    _reject_path_separator(path, "Hermes executable path")
    try:
        result = path.lstat()
    except OSError as exc:
        raise AuditRunnerError("Hermes executable is unavailable") from exc
    if not stat.S_ISREG(result.st_mode) or result.st_mode & 0o111 == 0 or result.st_mode & 0o022:
        _error("Hermes executable metadata is unsafe")
    return path


def _validate_limits(config: AuditConfig) -> None:
    if not isinstance(config, AuditConfig):
        _error("audit runner configuration is invalid")
    limits = config.limits
    for name in (
        "model_output_bytes",
        "hermes_stderr_bytes",
        "provider_value_bytes",
    ):
        value = getattr(limits, name)
        hard = getattr(HARD_LIMITS, name)
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= hard:
            _error(f"audit runner {name} is outside its hard limit")
    if limits.model_iterations != HARD_LIMITS.model_iterations:
        _error("audit runner model iteration limit cannot be configured")


def _validated_environment(
    *,
    source_env: Mapping[str, str],
    config: AuditConfig,
    control_dir: Path,
    broker_dir: Path,
) -> tuple[dict[str, str], tuple[str, ...]]:
    if not isinstance(source_env, Mapping):
        _error("audit runner source environment is invalid")
    try:
        validate_provider_selection(config)
    except AuditConfigError as exc:
        raise AuditRunnerError("audit runner provider selection is invalid") from exc
    environment = {
        "PATH": f"{broker_dir}{os.pathsep}{_SYSTEM_PATH}",
        "HOME": str(control_dir / "home"),
        "HERMES_HOME": str(control_dir / "hermes"),
    }
    for name in _SAFE_CALLER_ENV:
        value = source_env.get(name)
        if value is None or value == "":
            continue
        if not isinstance(value, str) or "\x00" in value:
            _error("audit runner safe environment is invalid")
        environment[name] = value
    secrets: list[str] = []
    for name in config.provider_env:
        if (
            name in _FORBIDDEN_PROVIDER_ENV
            or name.startswith(("DOCKER_", "TERMINAL_", "GIT_", "SSH_"))
            or "ASKPASS" in name
        ):
            _error("audit runner provider environment contains a forbidden variable")
        value = source_env.get(name)
        if (
            not isinstance(value, str)
            or not value
            or "\x00" in value
            or len(value.encode("utf-8", errors="strict")) > config.limits.provider_value_bytes
        ):
            _error("audit runner provider environment is unavailable or exceeds its limit")
        if name in environment:
            _error("audit runner provider environment conflicts with a reserved variable")
        environment[name] = value
        secrets.append(value)
    return environment, tuple(secrets)


def _query_arguments(
    *,
    executable: Path,
    profile_name: str,
    prompt: str,
    config: AuditConfig,
) -> list[str]:
    if not isinstance(profile_name, str) or _PROFILE_RE.fullmatch(profile_name) is None:
        _error("audit runner profile name is invalid")
    if (
        not isinstance(prompt, str)
        or not prompt
        or "\x00" in prompt
        or len(prompt.encode("utf-8", errors="strict")) > 32 * 1024
    ):
        _error("audit runner prompt is invalid")
    arguments = [
        str(executable),
        "-p",
        profile_name,
        "chat",
        "-q",
        prompt,
        "--quiet",
        "--ignore-rules",
        "--max-turns",
        str(config.limits.model_iterations),
        "-t",
        "terminal",
    ]
    if config.provider is not None:
        arguments.extend(("--provider", config.provider))
    if config.model is not None:
        arguments.extend(("-m", config.model))
    return arguments


def _broker_breach(
    state_path: Path,
    reader: _BrokerStateReader,
    *,
    final: bool,
) -> str | None:
    try:
        state = reader(state_path)
    except (OSError, TypeError, ValueError, RuntimeError):
        return "audit Docker broker state became unavailable"
    if state.limit_breach or state.phase == "breached" or state.cleanup_state == "failed":
        return state.breach_reason or "audit Docker broker reported a policy breach"
    if final and (state.phase != "closed" or state.cleanup_state != "complete"):
        return "audit Docker broker protocol did not close completely"
    return None


def _read_process_stream(
    stream: object,
    *,
    buffer: bytearray,
    limit: int,
) -> tuple[bool, bool]:
    file_object = cast(BinaryIO, stream)
    descriptor = file_object.fileno()
    chunk = os.read(descriptor, _PROCESS_CHUNK)
    if not chunk:
        return True, False
    remaining = max(0, limit - len(buffer))
    buffer.extend(chunk[:remaining])
    return False, len(chunk) > remaining


def _capture_process(
    process: subprocess.Popen[bytes],
    *,
    deadline: float,
    stdout_limit: int,
    stderr_limit: int,
    cancel_event: Event | None,
    state_path: Path,
    state_reader: _BrokerStateReader,
) -> _CapturedProcess:
    if process.stdout is None or process.stderr is None:
        _error("audit runner process pipes are unavailable")
    stdout = bytearray()
    stderr = bytearray()
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    try:
        while selector.get_map():
            if cancel_event is not None and cancel_event.is_set():
                return _CapturedProcess(
                    AuditRunnerOutcome.cancelled,
                    bytes(stdout),
                    bytes(stderr),
                    _observed_returncode(process),
                )
            now = time.monotonic()
            if now >= deadline:
                return _CapturedProcess(
                    AuditRunnerOutcome.timed_out,
                    bytes(stdout),
                    bytes(stderr),
                    _observed_returncode(process),
                )
            breach = _broker_breach(state_path, state_reader, final=False)
            if breach is not None:
                return _CapturedProcess(
                    AuditRunnerOutcome.broker_breach,
                    bytes(stdout),
                    bytes(stderr),
                    _observed_returncode(process),
                    breach,
                )
            events = selector.select(min(_POLL_SECONDS, deadline - now))
            for key, _mask in events:
                stream = key.fileobj
                if key.data == "stdout":
                    eof, exceeded = _read_process_stream(
                        stream,
                        buffer=stdout,
                        limit=stdout_limit,
                    )
                    if exceeded:
                        return _CapturedProcess(
                            AuditRunnerOutcome.model_output_limit,
                            b"",
                            bytes(stderr),
                            _observed_returncode(process),
                        )
                else:
                    eof, exceeded = _read_process_stream(
                        stream,
                        buffer=stderr,
                        limit=stderr_limit,
                    )
                    if exceeded:
                        return _CapturedProcess(
                            AuditRunnerOutcome.stderr_output_limit,
                            b"",
                            bytes(stderr),
                            _observed_returncode(process),
                        )
                if eof:
                    selector.unregister(stream)
        returncode = _observed_returncode(process)
        while returncode is None:
            if cancel_event is not None and cancel_event.is_set():
                return _CapturedProcess(
                    AuditRunnerOutcome.cancelled,
                    bytes(stdout),
                    bytes(stderr),
                    None,
                )
            now = time.monotonic()
            if now >= deadline:
                return _CapturedProcess(
                    AuditRunnerOutcome.timed_out,
                    bytes(stdout),
                    bytes(stderr),
                    None,
                )
            breach = _broker_breach(state_path, state_reader, final=False)
            if breach is not None:
                return _CapturedProcess(
                    AuditRunnerOutcome.broker_breach,
                    bytes(stdout),
                    bytes(stderr),
                    None,
                    breach,
                )
            time.sleep(min(_POLL_SECONDS, deadline - now))
            returncode = _observed_returncode(process)
        breach = _broker_breach(state_path, state_reader, final=True)
        if breach is not None:
            return _CapturedProcess(
                AuditRunnerOutcome.broker_breach,
                b"",
                bytes(stderr),
                returncode,
                breach,
            )
        if returncode != 0:
            return _CapturedProcess(
                AuditRunnerOutcome.process_failed,
                b"",
                bytes(stderr),
                returncode,
            )
        return _CapturedProcess(
            AuditRunnerOutcome.completed,
            bytes(stdout),
            bytes(stderr),
            returncode,
        )
    finally:
        selector.close()


def _observed_returncode(process: subprocess.Popen[bytes]) -> int | None:
    try:
        return observe_process_exit(process)
    except AuditProcessError as exc:
        raise AuditRunnerError("audit process group ownership became unavailable") from exc


def _stop_process_group(process: subprocess.Popen[bytes]) -> bool:
    return stop_process_group(
        process,
        term_seconds=_TERM_GRACE_SECONDS,
        kill_seconds=_KILL_GRACE_SECONDS,
    )


def _bounded_diagnostic(
    stderr: bytes,
    *,
    secrets: tuple[str, ...],
    detail: str | None = None,
) -> str | None:
    text = stderr.decode("utf-8", errors="replace")
    if detail:
        text = f"{detail}\n{text}" if text else detail
    for secret in sorted((value for value in secrets if value), key=len, reverse=True):
        text = text.replace(secret, "[redacted]")
    if not text:
        return None
    text = text.encode("utf-8")[: _DIAGNOSTIC_BYTES * 2].decode(
        "utf-8",
        errors="ignore",
    )
    sanitized: str = sanitize_text(text, max_length=len(text))
    encoded = sanitized.encode("utf-8")[:_DIAGNOSTIC_BYTES]
    return encoded.decode("utf-8", errors="ignore")


class AuditRunner:
    """Launch one fresh Hermes query under the sealed audit broker contract."""

    def __init__(
        self,
        hermes_executable: Path,
        *,
        broker_state_reader: _BrokerStateReader = read_audit_docker_broker_state,
        broker_cleanup: _BrokerCleanup = cleanup_audit_docker_broker,
    ) -> None:
        self._hermes = _validate_hermes_executable(hermes_executable)
        self._broker_state_reader = broker_state_reader
        self._broker_cleanup = broker_cleanup

    def run(
        self,
        *,
        profile_name: str,
        prompt: str,
        config: AuditConfig,
        control_dir: Path,
        broker_executable: Path,
        broker_state_path: Path,
        deadline: float,
        source_env: Mapping[str, str],
        validate_output: Callable[[bytes], object],
        cancel_event: Event | None = None,
    ) -> AuditRunnerResult:
        process: subprocess.Popen[bytes] | None = None
        captured: _CapturedProcess | None = None
        model_result: object | None = None
        secrets: tuple[str, ...] = ()
        pending_error: AuditRunnerError | None = None
        cleanup_complete = False
        process_group_stopped = True
        teardown_interrupted = False
        streams_closed = True
        try:
            active_deadline = _validate_deadline(deadline)
            _validate_limits(config)
            if not isinstance(control_dir, Path) or not control_dir.is_absolute():
                _error("audit runner control directory must be absolute")
            for path, description in (
                (control_dir, "audit runner control directory"),
                (broker_executable, "audit Docker broker executable path"),
                (broker_state_path, "audit Docker broker state path"),
            ):
                if not isinstance(path, Path):
                    _error(f"{description} is invalid")
                _reject_path_separator(path, description)
            home_dir = control_dir / "home"
            hermes_home = control_dir / "hermes"
            launch_dir = control_dir / "launch"
            broker_dir = control_dir / "broker"
            try:
                for directory in (
                    control_dir,
                    home_dir,
                    hermes_home,
                    launch_dir,
                    broker_dir,
                ):
                    if not inspect_private_directory(directory):
                        _error("audit runner private directory is unsafe")
            except (OSError, TypeError, ValueError, UnsafeFileError) as exc:
                raise AuditRunnerError("audit runner private directory is unsafe") from exc
            try:
                if os.listdir(launch_dir):
                    _error("audit runner launch directory must be empty")
            except OSError as exc:
                raise AuditRunnerError("audit runner launch directory is unavailable") from exc
            _validate_private_file(
                broker_executable,
                parent=broker_dir,
                name="docker",
                mode=0o500,
                description="audit Docker broker executable",
            )
            _validate_private_file(
                broker_state_path,
                parent=broker_dir,
                name="state.json",
                mode=0o600,
                description="audit Docker broker state",
            )
            environment, secrets = _validated_environment(
                source_env=source_env,
                config=config,
                control_dir=control_dir,
                broker_dir=broker_dir,
            )
            arguments = _query_arguments(
                executable=self._hermes,
                profile_name=profile_name,
                prompt=prompt,
                config=config,
            )
            if not callable(validate_output):
                _error("audit runner output validator is invalid")
            try:
                with ExitStack() as stack:
                    pins = [
                        stack.enter_context(pin_private_directory(directory, tighten=False))
                        for directory in (
                            control_dir,
                            home_dir,
                            hermes_home,
                            launch_dir,
                            broker_dir,
                        )
                    ]
                    try:
                        process = subprocess.Popen(  # nosec B603
                            arguments,
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            cwd=str(launch_dir),
                            env=environment,
                            shell=False,
                            close_fds=True,
                            start_new_session=True,
                            bufsize=0,
                        )
                    except OSError:
                        captured = _CapturedProcess(
                            AuditRunnerOutcome.launch_failed,
                            b"",
                            b"",
                            None,
                            "Hermes process could not be started",
                        )
                    else:
                        for pin, directory in zip(
                            pins,
                            (
                                control_dir,
                                home_dir,
                                hermes_home,
                                launch_dir,
                                broker_dir,
                            ),
                            strict=True,
                        ):
                            pin.validate_at(directory)
                        try:
                            captured = _capture_process(
                                process,
                                deadline=active_deadline,
                                stdout_limit=config.limits.model_output_bytes,
                                stderr_limit=config.limits.hermes_stderr_bytes,
                                cancel_event=cancel_event,
                                state_path=broker_state_path,
                                state_reader=self._broker_state_reader,
                            )
                        except KeyboardInterrupt:
                            try:
                                interrupted_returncode = _observed_returncode(process)
                            except AuditRunnerError:
                                interrupted_returncode = None
                            captured = _CapturedProcess(
                                AuditRunnerOutcome.cancelled,
                                b"",
                                b"",
                                interrupted_returncode,
                                "audit query was interrupted",
                            )
            except (OSError, TypeError, ValueError, UnsafeFileError) as exc:
                raise AuditRunnerError("audit runner private directory binding changed") from exc
            if captured is None:
                _error("audit runner did not produce a process result")
            if captured.outcome is AuditRunnerOutcome.completed:
                try:
                    model_result = validate_output(captured.stdout)
                except Exception:
                    captured = _CapturedProcess(
                        AuditRunnerOutcome.invalid_output,
                        b"",
                        captured.stderr,
                        captured.returncode,
                        "Hermes final response was not valid JSON",
                    )
        except AuditRunnerError as exc:
            pending_error = exc
        finally:
            if process is not None:
                try:
                    process_group_stopped = _stop_process_group(process)
                except KeyboardInterrupt:
                    teardown_interrupted = True
                    try:
                        process_group_stopped = _stop_process_group(process)
                    except (KeyboardInterrupt, OSError, TypeError, ValueError):
                        process_group_stopped = False
                except (OSError, TypeError, ValueError):
                    process_group_stopped = False
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        try:
                            stream.close()
                        except KeyboardInterrupt:
                            teardown_interrupted = True
                            try:
                                stream.close()
                            except (KeyboardInterrupt, OSError):
                                streams_closed = False
                        except OSError:
                            streams_closed = False
            try:
                cleanup = self._broker_cleanup(broker_state_path)
                broker_cleanup_complete = cleanup.returncode == 0
            except KeyboardInterrupt:
                teardown_interrupted = True
                try:
                    cleanup = self._broker_cleanup(broker_state_path)
                    broker_cleanup_complete = cleanup.returncode == 0
                except (
                    KeyboardInterrupt,
                    OSError,
                    TypeError,
                    ValueError,
                    RuntimeError,
                ):
                    broker_cleanup_complete = False
            except (OSError, TypeError, ValueError, RuntimeError):
                broker_cleanup_complete = False
            cleanup_complete = process_group_stopped and streams_closed and broker_cleanup_complete
        if pending_error is not None:
            raise pending_error
        if captured is None:
            _error("audit runner did not produce a process result")
        if teardown_interrupted:
            captured = _CapturedProcess(
                AuditRunnerOutcome.cancelled,
                b"",
                captured.stderr,
                captured.returncode,
                "audit query was interrupted during process cleanup",
            )
            model_result = None
        outcome = captured.outcome
        if outcome is AuditRunnerOutcome.completed and not cleanup_complete:
            outcome = AuditRunnerOutcome.cleanup_failed
        cleanup_detail: str | None = None
        if not process_group_stopped:
            cleanup_detail = "audit process group cleanup could not be verified"
        elif outcome is AuditRunnerOutcome.cleanup_failed:
            cleanup_detail = "audit Docker broker cleanup failed"
        if captured.detail and cleanup_detail:
            cleanup_detail = f"{captured.detail}\n{cleanup_detail}"
        elif captured.detail:
            cleanup_detail = captured.detail
        diagnostic = (
            None
            if outcome is AuditRunnerOutcome.completed
            else _bounded_diagnostic(
                captured.stderr,
                secrets=secrets,
                detail=cleanup_detail,
            )
        )
        return AuditRunnerResult(
            outcome=outcome,
            model_result=model_result,
            diagnostic=diagnostic,
            returncode=captured.returncode,
            cleanup_complete=cleanup_complete,
            process_group_stopped=process_group_stopped,
        )
