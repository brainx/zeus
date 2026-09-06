"""Exercise the installed pinned Hermes runs API with a local test agent.

Run after scripts/install_pinned_hermes.sh. The child processes have disposable
homes, no inherited provider credentials, and reject non-loopback connections.
Real Hermes HTTP handlers and SQLite idempotency storage remain in use; only
the agent factory is replaced. This does not test an LLM or tool sandbox.
"""

from __future__ import annotations

import asyncio
import importlib.metadata
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

HERMES_VERSION = "0.21.0"
_KEY = "pinned-runs-local-fixture-key"
_INPUT = "Local contract fixture; no provider execution."


def _block_external_connections() -> None:
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def check(address):
        if not isinstance(address, tuple) or address[0] not in {"127.0.0.1", "::1"}:
            raise RuntimeError("contract fixture forbids non-loopback connections")

    def connect(sock, address):
        check(address)
        return original_connect(sock, address)

    def connect_ex(sock, address):
        check(address)
        return original_connect_ex(sock, address)

    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex


async def _exercise(root: Path, *, restarted: bool) -> None:
    # Delay upstream imports until the worker's disposable environment and
    # connection guard are established. Import failures are required failures.
    from aiohttp import web
    from gateway.config import PlatformConfig
    from gateway.platforms.api_server import APIServerAdapter, RunIdempotencyStore
    from gateway.run import _current_max_iterations

    from zeus import hermes_runs_client as client

    assert _current_max_iterations() == 10, "pinned per-run turn-limit bridge changed"
    adapter = APIServerAdapter(
        PlatformConfig(
            enabled=True,
            extra={"key": _KEY, "host": "127.0.0.1", "model_name": "contract-fixture"},
        )
    )
    assert adapter._max_concurrent_runs == 1, "pinned startup concurrency limit changed"
    adapter._run_idempotency_store.close()
    adapter._run_idempotency_store = RunIdempotencyStore(str(root / "run-idempotency.db"))
    assert adapter._run_idempotency_store.durable
    release = threading.Event()
    ready = threading.Event()
    calls = []

    def create_agent(**_kwargs):
        assert not restarted, "a durable replay must not construct a new agent"
        calls.append(True)
        agent = MagicMock()
        agent.session_prompt_tokens = 0
        agent.session_completion_tokens = 0
        agent.session_total_tokens = 0
        agent.interrupt.side_effect = lambda *_args, **_kwargs: release.set()

        def run_conversation(user_message=None, **_kwargs):
            if user_message == "Wait for the explicit stop fixture.":
                ready.set()
                assert release.wait(15), "stop fixture was not interrupted"
                return {"final_response": "stopped fixture", "interrupted": True}
            assert user_message == _INPUT
            return {"final_response": "completed fixture"}

        agent.run_conversation.side_effect = run_conversation
        return agent

    @asynccontextmanager
    async def server():
        app = web.Application()
        app.router.add_get("/v1/capabilities", adapter._handle_capabilities)
        app.router.add_post("/v1/runs", adapter._handle_runs)
        app.router.add_get("/v1/runs/{run_id}", adapter._handle_get_run)
        app.router.add_post("/v1/runs/{run_id}/stop", adapter._handle_stop_run)
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        try:
            assert site._server is not None
            port = site._server.sockets[0].getsockname()[1]
            with patch.object(adapter, "_create_agent", side_effect=create_agent):
                yield f"http://127.0.0.1:{port}/health"
        finally:
            release.set()
            tasks = list(adapter._active_run_tasks.values())
            if tasks:
                await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 5)
            await runner.cleanup()
            adapter._run_idempotency_store.close()

    async def request(function, *args, **kwargs):
        return await asyncio.to_thread(function, *args, **kwargs)

    async def settled(url, run_id, wanted):
        deadline = asyncio.get_running_loop().time() + 5
        while asyncio.get_running_loop().time() < deadline:
            result = await request(client.status, url, _KEY, run_id, include_output=True)
            if result["status"] == wanted:
                return result
            if result["status"] in client.TERMINAL_STATES:
                raise AssertionError("unexpected terminal state in pinned runs fixture")
            await asyncio.sleep(0.05)
        raise AssertionError("pinned run did not reach expected state")

    async with server() as url:
        capabilities = await request(client.capabilities, url, _KEY)
        assert capabilities["features"]["runs_idempotency"]["durable"] is True
        assert capabilities["features"]["runs_idempotency"]["retention_seconds"] == 86400
        if restarted:
            saved = json.loads((root / "receipts.json").read_text(encoding="utf-8"))
            completed = await settled(url, saved["completed"], "completed")
            assert completed["output"] == "completed fixture"
            cancelled = await settled(url, saved["cancelled"], "cancelled")
            assert cancelled["run_id"] == saved["cancelled"]
            replay = await request(client.submit, url, _KEY, _INPUT, "completed-request")
            assert replay == {"run_id": saved["completed"], "status": "completed", "replayed": True}
            stopped = await request(client.stop, url, _KEY, saved["cancelled"])
            assert stopped["status"] == "cancelled"
            assert not calls
            return

        try:
            await request(client.capabilities, url, "wrong-local-fixture-key")
        except client.HermesRunsClientError as exc:
            assert exc.code == "authentication_failed"
        else:
            raise AssertionError("pinned capabilities accepted the wrong key")

        receipt = await request(client.submit, url, _KEY, _INPUT, "completed-request")
        assert receipt["status"] == "started" and receipt["replayed"] is False
        completed_id = receipt["run_id"]
        completed = await settled(url, completed_id, "completed")
        assert completed["output"] == "completed fixture"
        replay = await request(client.submit, url, _KEY, _INPUT, "completed-request")
        assert replay["run_id"] == completed_id and replay["replayed"] is True
        try:
            await request(client.submit, url, _KEY, "changed request", "completed-request")
        except client.HermesRunsClientError as exc:
            assert exc.code == "conflict" and not exc.uncertain
        else:
            raise AssertionError("pinned idempotency did not reject changed input")

        slow = await request(
            client.submit, url, _KEY, "Wait for the explicit stop fixture.", "stop-request"
        )
        assert await asyncio.to_thread(ready.wait, 5), "test agent did not start"
        try:
            await request(client.submit, url, _KEY, _INPUT, "over-capacity-request")
        except client.HermesRunsClientError as exc:
            assert exc.code == "rate_limited" and not exc.uncertain
        else:
            raise AssertionError("pinned concurrency limit did not reject a second run")
        stopped = await request(client.stop, url, _KEY, slow["run_id"])
        assert stopped["status"] == "stopping", "stop acknowledgement must stay cooperative"
        await settled(url, slow["run_id"], "cancelled")
        assert len(calls) == 2, "replay/conflict/capacity checks created extra agents"
        (root / "receipts.json").write_text(
            json.dumps({"completed": completed_id, "cancelled": slow["run_id"]}),
            encoding="utf-8",
        )


def main() -> int:
    try:
        installed = importlib.metadata.version("hermes-agent")
    except importlib.metadata.PackageNotFoundError:
        installed = None
    if installed != HERMES_VERSION:
        print("requires installed hermes-agent==0.21.0; this check cannot skip", file=sys.stderr)
        return 2
    repository = Path(__file__).resolve().parents[1]
    if len(sys.argv) == 4 and sys.argv[1] == "--worker":
        _block_external_connections()
        sys.path.insert(0, str(repository))
        asyncio.run(
            asyncio.wait_for(_exercise(Path(sys.argv[2]), restarted=sys.argv[3] == "restart"), 40)
        )
        return 0

    temporary_root = repository / ".tmp"
    temporary_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="pinned-runs-", dir=temporary_root) as temporary:
        root = Path(temporary)
        home = root / "home"
        hermes_home = root / "hermes"
        home.mkdir(mode=0o700)
        hermes_home.mkdir(mode=0o700)
        (hermes_home / "config.yaml").write_text(
            "model: contract-fixture\nagent:\n  max_turns: 10\n"
            "gateway:\n  api_server:\n    max_concurrent_runs: 1\n",
            encoding="utf-8",
        )
        environment = {
            "HOME": str(home),
            "HERMES_HOME": str(hermes_home),
            "HERMES_SAFE_MODE": "1",
            "HERMES_MANAGED_DIR": str(root / "absent-managed-scope"),
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONNOUSERSITE": "1",
        }
        for phase in ("exercise", "restart"):
            result = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--worker", str(root), phase],
                cwd=root,
                env=environment,
                stdin=subprocess.DEVNULL,
                timeout=60,
                check=False,
            )
            if result.returncode:
                return result.returncode
    print("Pinned Hermes runs capabilities, replay, status, stop, and process restart passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
