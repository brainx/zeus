from __future__ import annotations

import ast
import dataclasses
import inspect
import json
import os
import signal
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from zeus.gateway_marker import GatewayGeneration
from zeus.gateway_runtime import (
    GatewayRuntime,
    KillFn,
    LaunchEffect,
    MarkerObservation,
    OwnershipCheck,
    PopenFactory,
    PopenLike,
    SignalResult,
    StopEffect,
)
from zeus.hermes_adapter import HermesAdapter
from zeus.models import BotRecord, BotStatus, DesiredState
from zeus.profile_manager import ProfileManager
from zeus.state import StateStore
from zeus.supervisor import Supervisor


class _NeverExits:
    def __init__(self, pid: int) -> None:
        self.pid = pid

    def poll(self) -> int | None:
        return None

    def wait(self, *, timeout: float) -> None:
        del timeout
        raise TimeoutError


class GatewayRuntimeTests(unittest.TestCase):
    bot_id = "coder"
    pid = 4321
    operation_id = "a" * 32

    def _fake_hermes(self, root: Path) -> str:
        hermes = root / "bin" / "hermes"
        hermes.parent.mkdir(parents=True, exist_ok=True)
        hermes.write_text("#!/bin/sh\n", encoding="utf-8")
        hermes.chmod(0o755)
        return str(hermes.resolve())

    def _fixture(
        self,
        root: Path,
        *,
        fingerprints: list[str | None] | None = None,
        signals: list[tuple[int, signal.Signals]] | None = None,
        popen_factory=None,
        stop_grace_seconds: float = 0.0,
        kill_after_timeout: bool = False,
    ) -> tuple[GatewayRuntime, BotRecord, Path, str]:
        root = root.resolve()
        hermes_root = root / "hermes"
        profile = hermes_root / "profiles" / self.bot_id
        profile.mkdir(parents=True)
        (profile / ".env").write_text("", encoding="utf-8")
        hermes = self._fake_hermes(root)
        adapter = HermesAdapter(hermes, hermes_root)
        manager = ProfileManager(hermes_root, root / "archive")
        fingerprint_values = list(fingerprints or ["same"])

        def read_fingerprint(pid: int) -> str | None:
            self.assertEqual(self.pid, pid)
            if len(fingerprint_values) > 1:
                return fingerprint_values.pop(0)
            return fingerprint_values[0]

        observed_signals = signals if signals is not None else []
        runtime = GatewayRuntime(
            adapter,
            manager,
            hermes_root / "profiles",
            popen_factory=popen_factory or (lambda *args, **kwargs: _NeverExits(self.pid)),
            kill_fn=lambda pid, sig: observed_signals.append((pid, sig)),
            pid_alive_fn=lambda pid: True,
            cmdline_reader=lambda pid: [hermes, "-p", self.bot_id, "gateway", "run"],
            proc_start_fingerprint_reader=read_fingerprint,
            startup_grace_seconds=0,
            stop_grace_seconds=stop_grace_seconds,
            kill_after_timeout=kill_after_timeout,
            cleanup_process_group=False,
        )
        record = BotRecord(
            bot_id=self.bot_id,
            template_id="coding-bot",
            display_name="Coder",
            profile_path=str(profile),
            status=BotStatus.running,
            pid=self.pid,
            desired_state=DesiredState.stopped,
            desired_revision=2,
            pending_operation_id="b" * 32,
            pending_action="stop",
        )
        return runtime, record, profile, hermes

    def _schema3_marker(
        self,
        runtime: GatewayRuntime,
        profile: Path,
        *,
        operation_id: str | None = None,
        desired_revision: int = 1,
        pid: int | None = None,
        process_start: str = "same",
    ) -> tuple[dict[str, object], GatewayGeneration]:
        payload = runtime.adapter.launcher_payload(
            self.bot_id,
            operation_id=operation_id or self.operation_id,
            desired_revision=desired_revision,
            readiness_probe=None,
        )
        marker = dict(payload["marker"])
        marker.update(
            {
                "pid": pid or self.pid,
                "started_at": 1_780_000_000.0,
                "proc_start_fingerprint": process_start,
            }
        )
        marker_path = runtime.pid_marker_path(str(profile))
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        marker_path.write_text(json.dumps(marker, sort_keys=True) + "\n", encoding="utf-8")
        generation = GatewayGeneration(
            operation_id=str(marker["operation_id"]),
            desired_revision=int(marker["desired_revision"]),
            pid=int(marker["pid"]),
            command_fingerprint=str(marker["command_fingerprint"]),
            proc_start_fingerprint=process_start,
        )
        return marker, generation

    def test_effects_are_frozen_bounded_and_do_not_retain_secret_fields(self) -> None:
        launch = LaunchEffect("failed", reason="x" * 2_000, readiness_message="z" * 2_000)
        stop = StopEffect("pending", reason="y" * 2_000)

        self.assertLessEqual(len(launch.reason), 512)
        self.assertLessEqual(len(launch.readiness_message or ""), 512)
        self.assertLessEqual(len(stop.reason), 512)
        self.assertNotIn("env", vars(launch))
        self.assertNotIn("payload", vars(launch))
        self.assertNotIn("argv", vars(launch))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            launch.reason = "changed"  # type: ignore[misc]
        with self.assertRaises(dataclasses.FrozenInstanceError):
            stop.reason = "changed"  # type: ignore[misc]

    def test_launch_secret_is_confined_to_private_descriptor_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            captured: dict[str, object] = {}
            secret = "descriptor-only-launch-secret"

            class CapturingPopen:
                pid = self.pid

                def __init__(self, argv, env, stdout, stderr, **kwargs):
                    del stdout, stderr, kwargs
                    captured["argv"] = list(argv)
                    captured["env"] = dict(env)
                    payload_fd = os.dup(int(argv[-2]))
                    ack_fd = os.dup(int(argv[-1]))

                    def publish() -> None:
                        try:
                            chunks: list[bytes] = []
                            while chunk := os.read(payload_fd, 65_536):
                                chunks.append(chunk)
                            payload = json.loads(b"".join(chunks))
                            captured["payload"] = payload
                            marker = dict(payload["marker"])
                            marker.update(
                                {
                                    "pid": self.pid,
                                    "started_at": time.time(),
                                    "proc_start_fingerprint": "same",
                                }
                            )
                            marker_path = Path(payload["marker_path"])
                            marker_path.parent.mkdir(parents=True, exist_ok=True)
                            marker_path.write_text(json.dumps(marker), encoding="utf-8")
                            os.write(ack_fd, b"1")
                        finally:
                            os.close(payload_fd)
                            os.close(ack_fd)

                    threading.Thread(target=publish, daemon=True).start()

                def poll(self) -> int | None:
                    return None

            runtime, record, profile, _hermes = self._fixture(
                root,
                popen_factory=CapturingPopen,
            )
            (profile / ".env").write_text(
                f"OPENROUTER_API_KEY={secret}\n",
                encoding="utf-8",
            )
            launching = dataclasses.replace(
                record,
                status=BotStatus.starting,
                pid=None,
                desired_state=DesiredState.running,
                desired_revision=1,
                pending_operation_id=self.operation_id,
                pending_action="start",
            )

            with patch.dict(os.environ, {"PATH": os.environ.get("PATH", "")}, clear=True):
                effect = runtime.launch(launching, probe=None, wait=False)

            private_payload = captured["payload"]
            assert isinstance(private_payload, dict)
            marker_text = runtime.pid_marker_path(str(profile)).read_text(encoding="utf-8")
            self.assertEqual(secret, private_payload["env"]["OPENROUTER_API_KEY"])
            self.assertNotIn(secret, "\0".join(captured["argv"]))
            self.assertNotIn(secret, json.dumps(captured["env"], sort_keys=True))
            self.assertNotIn(secret, marker_text)
            self.assertNotIn(secret, repr(effect))
            self.assertNotIn(secret, json.dumps(vars(effect), default=str, sort_keys=True))

    def test_exact_generation_rejects_changed_correlation_and_process_identity(self) -> None:
        mutations = {
            "operation": lambda marker: marker.__setitem__("operation_id", "c" * 32),
            "revision": lambda marker: marker.__setitem__("desired_revision", 9),
            "pid": lambda marker: marker.__setitem__("pid", 9999),
            "command": lambda marker: marker.__setitem__("command_fingerprint", "0" * 64),
            "start": lambda marker: marker.__setitem__("proc_start_fingerprint", "reused"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                runtime, record, profile, _hermes = self._fixture(Path(tmp))
                marker, generation = self._schema3_marker(runtime, profile)
                baseline = runtime.classify_exact_gateway_generation(record, generation)
                self.assertEqual("live", baseline.kind)
                mutate(marker)
                runtime.pid_marker_path(str(profile)).write_text(
                    json.dumps(marker, sort_keys=True) + "\n",
                    encoding="utf-8",
                )

                changed = runtime.classify_exact_gateway_generation(record, generation)

                self.assertEqual("untrusted", changed.kind)

    def test_final_pre_sigterm_fingerprint_drift_sends_no_signal_or_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            signals: list[tuple[int, signal.Signals]] = []
            runtime, record, profile, _hermes = self._fixture(
                Path(tmp),
                fingerprints=["same", "same", "reused"],
                signals=signals,
            )
            _marker, _generation = self._schema3_marker(runtime, profile)
            marker_path = runtime.pid_marker_path(str(profile))

            with runtime.marker_publication_lock(record):
                effect = runtime.stop_locked(record, kill_after_timeout=True)

            self.assertEqual("term_reauthorization_failed", effect.outcome)
            self.assertEqual([], signals)
            self.assertTrue(marker_path.exists())

    def test_pre_sigkill_fingerprint_drift_sends_term_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            signals: list[tuple[int, signal.Signals]] = []
            runtime, record, profile, _hermes = self._fixture(
                Path(tmp),
                fingerprints=["same", "same", "same", "reused"],
                signals=signals,
                kill_after_timeout=True,
            )
            self._schema3_marker(runtime, profile)
            marker_path = runtime.pid_marker_path(str(profile))

            with runtime.marker_publication_lock(record):
                effect = runtime.stop_locked(record, kill_after_timeout=True)

            self.assertEqual("kill_reauthorization_failed", effect.outcome)
            self.assertEqual([(self.pid, signal.SIGTERM)], signals)
            self.assertTrue(marker_path.exists())

    def test_legacy_and_schema2_markers_never_signal_start_or_remove(self) -> None:
        payloads: list[dict[str, object]] = [
            {"pid": self.pid, "argv": ["hermes", "gateway", "run"]},
            {
                "schema": 2,
                "pid": self.pid,
                "bot_id": self.bot_id,
                "component": "gateway",
                "action": "run",
                "argv": ["hermes", "-p", self.bot_id, "gateway", "run"],
            },
        ]
        for payload in payloads:
            with self.subTest(schema=payload.get("schema")), tempfile.TemporaryDirectory() as tmp:
                signals: list[tuple[int, signal.Signals]] = []
                launches: list[object] = []

                def forbidden_popen(*args, _launches=launches, **kwargs):
                    _launches.append((args, kwargs))
                    raise AssertionError("stop must not start a process")

                runtime, record, profile, _hermes = self._fixture(
                    Path(tmp),
                    signals=signals,
                    popen_factory=forbidden_popen,
                )
                marker_path = runtime.pid_marker_path(str(profile))
                marker_path.parent.mkdir(parents=True, exist_ok=True)
                marker_path.write_text(json.dumps(payload), encoding="utf-8")

                with runtime.marker_publication_lock(record):
                    effect = runtime.stop_locked(record, kill_after_timeout=True)

                self.assertEqual("compat_untrusted", effect.outcome)
                self.assertEqual([], signals)
                self.assertEqual([], launches)
                self.assertTrue(marker_path.exists())

    def test_exact_cleanup_preserves_hardlink_symlink_and_replacement_evidence(self) -> None:
        for case in ("hardlink", "symlink", "replacement"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                runtime, record, profile, _hermes = self._fixture(Path(tmp))
                marker, generation = self._schema3_marker(runtime, profile)
                marker_path = runtime.pid_marker_path(str(profile))
                evidence = Path(tmp) / "evidence.json"
                if case == "hardlink":
                    os.link(marker_path, evidence)
                elif case == "symlink":
                    evidence.write_text(marker_path.read_text(encoding="utf-8"), encoding="utf-8")
                    marker_path.unlink()
                    marker_path.symlink_to(evidence)
                else:
                    marker["operation_id"] = "c" * 32
                    marker_path.write_text(json.dumps(marker), encoding="utf-8")

                removed = runtime.remove_gateway_generation_marker_locked(record, generation)

                if case == "hardlink":
                    self.assertTrue(removed)
                    self.assertFalse(marker_path.exists())
                else:
                    self.assertFalse(removed)
                    self.assertTrue(os.path.lexists(marker_path))
                if case != "replacement":
                    self.assertTrue(evidence.exists())

    def test_gateway_runtime_has_no_state_store_or_sqlite_dependency(self) -> None:
        import zeus.gateway_runtime as gateway_runtime

        source = Path(gateway_runtime.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertNotIn("sqlite3", imports)
        self.assertNotIn("zeus.state", imports)
        self.assertNotIn("StateStore", source)

    def test_supervisor_reexports_boundary_types_and_preserves_signatures(self) -> None:
        import zeus.supervisor as supervisor_module

        self.assertIs(PopenLike, supervisor_module.PopenLike)
        self.assertIs(PopenFactory, supervisor_module.PopenFactory)
        self.assertIs(KillFn, supervisor_module.KillFn)
        self.assertIs(OwnershipCheck, supervisor_module.OwnershipCheck)
        self.assertIs(MarkerObservation, supervisor_module._MarkerObservation)
        self.assertIs(SignalResult, supervisor_module._SignalResult)
        self.assertEqual(
            [
                "self",
                "store",
                "hermes_bin",
                "hermes_root",
                "popen_factory",
                "kill_fn",
                "pid_alive_fn",
                "cmdline_reader",
                "startup_grace_seconds",
                "stop_grace_seconds",
                "kill_after_timeout",
                "lock_timeout_seconds",
                "readiness_timeout_seconds",
                "readiness_interval_seconds",
                "allow_legacy_pid_markers",
                "restart_backoff_cap_seconds",
                "proc_start_fingerprint_reader",
            ],
            list(inspect.signature(Supervisor.__init__).parameters),
        )
        self.assertEqual(
            ["self", "bot_id", "wait", "timeout_seconds", "source", "request_id"],
            list(inspect.signature(Supervisor.start).parameters),
        )
        self.assertEqual(
            ["self", "bot_id", "kill_after_timeout", "source", "request_id"],
            list(inspect.signature(Supervisor.stop).parameters),
        )

    def test_supervisor_runtime_proxies_remain_live_after_construction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_root = root / "hermes"
            (hermes_root / "profiles").mkdir(parents=True)
            store = StateStore(root / "zeus.db")
            store.init()
            supervisor = Supervisor(store, "hermes", hermes_root)

            def popen(*args, **kwargs):
                return _NeverExits(77)

            def killer(pid, sig):
                return None

            def alive(pid):
                return True

            def cmdline(pid):
                return ["hermes"]

            def fingerprint(pid):
                return "changed"

            processes = {"coder": _NeverExits(77)}

            supervisor.popen_factory = popen
            supervisor.kill_fn = killer
            supervisor.pid_alive_fn = alive
            supervisor.cmdline_reader = cmdline
            supervisor.proc_start_fingerprint_reader = fingerprint
            supervisor._processes = processes
            supervisor.stop_grace_seconds = 9.5
            supervisor.kill_after_timeout = True
            supervisor.lock_timeout_seconds = 4.25

            self.assertIs(popen, supervisor._runtime.popen_factory)
            self.assertIs(killer, supervisor._runtime.kill_fn)
            self.assertIs(alive, supervisor._runtime.pid_alive_fn)
            self.assertIs(cmdline, supervisor._runtime.cmdline_reader)
            self.assertIs(fingerprint, supervisor._runtime.proc_start_fingerprint_reader)
            self.assertIs(processes, supervisor._runtime._processes)
            self.assertEqual(9.5, supervisor._runtime.stop_grace_seconds)
            self.assertTrue(supervisor._runtime.kill_after_timeout)
            self.assertEqual(4.25, supervisor._runtime.lock_timeout_seconds)

    def test_supervisor_normal_stop_uses_shared_final_reauthorization_primitive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime, record, profile, hermes = self._fixture(root)
            self._schema3_marker(runtime, profile)
            store = StateStore(root / "zeus.db")
            store.init()
            fingerprints = iter(("same", "same", "reused"))
            supervisor = Supervisor(
                store,
                hermes,
                root / "hermes",
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: [hermes, "-p", self.bot_id, "gateway", "run"],
                proc_start_fingerprint_reader=lambda pid: next(fingerprints),
                kill_fn=lambda pid, sig: None,
            )
            supervisor._runtime.stop_grace_seconds = 0

            with patch.object(
                supervisor._runtime,
                "reauthorize_and_signal",
                wraps=supervisor._runtime.reauthorize_and_signal,
            ) as reauthorize:
                supervisor._stop_record_effect_locked(
                    record,
                    kill_after_timeout=False,
                    context=supervisor._lifecycle_context("system", None),
                    complete_stop=False,
                )

            self.assertGreaterEqual(reauthorize.call_count, 1)

    def test_public_runtime_result_types_have_expected_frozen_surface(self) -> None:
        observation = MarkerObservation("missing", reason="gone")
        self.assertEqual("missing", observation.kind)
        self.assertEqual("sent", SignalResult.sent.value)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            observation.kind = "present"  # type: ignore[misc]

    def test_marker_observation_snapshots_payload_and_hides_hostile_values(self) -> None:
        hostile = "hostile-marker-value-must-not-escape-repr"
        source: dict[str, object] = {"nested": {"value": hostile}}
        observation = MarkerObservation("present", payload=source)
        source_nested = source["nested"]
        assert isinstance(source_nested, dict)
        source_nested["value"] = "source-mutated"

        first = observation.payload
        assert first is not None
        first_nested = first["nested"]
        assert isinstance(first_nested, dict)
        self.assertEqual(hostile, first_nested["value"])
        first_nested["value"] = "returned-copy-mutated"

        second = observation.payload
        assert second is not None
        second_nested = second["nested"]
        assert isinstance(second_nested, dict)
        self.assertEqual(hostile, second_nested["value"])
        self.assertNotIn(hostile, repr(observation))

        rejected = MarkerObservation("present", payload={"hostile": object()})
        self.assertEqual("untrusted", rejected.kind)
        self.assertIsNone(rejected.payload)


if __name__ == "__main__":
    unittest.main()
