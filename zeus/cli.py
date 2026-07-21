from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

from zeus.api import serve, template_to_dict
from zeus.config import Settings, load_dotenv
from zeus.doctor import report_to_json, report_to_text, run_doctor
from zeus.envfile import ENV_KEY_RE
from zeus.errors import ZeusConflictError
from zeus.models import BotCreateRequest, BotStatus, BotStatusResponse, RestartPolicy, TemplateError
from zeus.process_lock import LockTimeoutError
from zeus.reconciliation import ReconcileLockTimeoutError, ReconcileRunSummary
from zeus.state import StateStore
from zeus.supervisor import Supervisor
from zeus.templates import TemplateStore

DEMO_BOT_ID = "demo-coder"
DEMO_TEMPLATE_ID = "coding-bot"
DEMO_FAKE_HERMES = "zeus-fake-hermes"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zeus")
    sub = parser.add_subparsers(dest="resource", required=True)

    serve_cmd = sub.add_parser("serve")
    serve_cmd.add_argument("--host")
    serve_cmd.add_argument("--port", type=int)

    doctor = sub.add_parser("doctor")
    doctor.add_argument("--json", action="store_true", dest="as_json")
    doctor.add_argument("--strict", action="store_true")

    template = sub.add_parser("template")
    template_sub = template.add_subparsers(dest="action", required=True)
    template_list = template_sub.add_parser("list")
    template_list.add_argument("--json", action="store_true", dest="as_json")

    demo = sub.add_parser("demo")
    demo_sub = demo.add_subparsers(dest="action", required=True)
    for action in ["up", "status", "down"]:
        command = demo_sub.add_parser(action)
        command.add_argument("--bot-id", default=DEMO_BOT_ID)
        command.add_argument("--json", action="store_true", dest="as_json")

    bot = sub.add_parser("bot")
    bot_sub = bot.add_subparsers(dest="action", required=True)

    create = bot_sub.add_parser("create")
    create.add_argument("bot_id")
    create.add_argument("--template", required=True, dest="template_id")
    create.add_argument("--name", dest="display_name")
    create.add_argument(
        "--env",
        action="append",
        default=[],
        help=(
            "NAME=VALUE for env keys declared by the selected template; "
            "unsafe for secrets because values enter argv"
        ),
    )
    create.add_argument(
        "--env-from",
        action="append",
        default=[],
        metavar="NAME",
        help="import NAME from the process environment, then trusted ./.env, without argv values",
    )
    create.add_argument("--restart-policy", choices=["manual", "on-failure"], default="manual")
    create.add_argument("--restart-backoff-seconds", type=float, default=5.0)
    create.add_argument("--restart-max-attempts", type=int, default=5)
    create.add_argument("--replace", action="store_true", dest="replace_existing")
    create.add_argument("--stop", action="store_true", dest="stop_if_running")
    create.add_argument("--json", action="store_true", dest="as_json")

    bot_list = bot_sub.add_parser("list")
    bot_list.add_argument("--json", action="store_true", dest="as_json")
    delete = bot_sub.add_parser("delete")
    delete.add_argument("bot_id")
    delete.add_argument("--stop", action="store_true", dest="stop_if_running")
    delete.add_argument("--remove-profile", action="store_true")
    delete.add_argument("--json", action="store_true", dest="as_json")
    archive = bot_sub.add_parser("archive")
    archive.add_argument("bot_id")
    archive.add_argument("--stop", action="store_true", dest="stop_if_running")
    archive.add_argument("--json", action="store_true", dest="as_json")
    reconcile = bot_sub.add_parser("reconcile")
    reconcile.add_argument("bot_id", nargs="?")
    reconcile.add_argument("--json", action="store_true", dest="as_json")
    reconcile.add_argument("--summary", action="store_true")
    reconcile.add_argument("--force", action="store_true")
    reconcile.add_argument("--reset-restart", action="store_true")
    inspect = bot_sub.add_parser("inspect")
    inspect.add_argument("bot_id")
    inspect.add_argument("--json", action="store_true", dest="as_json")
    history = bot_sub.add_parser("history")
    history.add_argument("bot_id")
    history.add_argument("--limit", type=_history_limit, default=50)
    history.add_argument("--before", type=_positive_event_id)
    history.add_argument("--json", action="store_true", dest="as_json")
    for action in ["start", "stop", "restart", "status", "logs", "doctor"]:
        command = bot_sub.add_parser(action)
        command.add_argument("bot_id")
        if action in {"start", "restart"}:
            command.add_argument("--wait", dest="wait", action="store_true", default=False)
            command.add_argument("--no-wait", dest="wait", action="store_false")
            command.add_argument("--timeout", type=float, dest="timeout_seconds")
        if action == "stop":
            command.add_argument(
                "--kill-after-timeout",
                dest="kill_after_timeout",
                action="store_true",
                default=None,
            )
            command.add_argument(
                "--no-kill-after-timeout",
                dest="kill_after_timeout",
                action="store_false",
            )
        if action == "logs":
            command.add_argument("--json", action="store_true", dest="as_json")

    return parser


def _history_limit(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("limit must be an integer") from exc
    if not 1 <= parsed <= 1000:
        raise argparse.ArgumentTypeError("limit must be between 1 and 1000")
    return parsed


def _positive_event_id(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("before must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("before must be positive")
    return parsed


def _services(settings: Settings) -> tuple[StateStore, Supervisor]:
    settings.ensure_dirs()
    store = StateStore(settings.database_path)
    store.init()
    return store, Supervisor(
        store,
        settings.hermes_bin,
        settings.hermes_root,
        kill_after_timeout=settings.stop_kill_after_timeout,
        lock_timeout_seconds=settings.lock_timeout_seconds,
        readiness_timeout_seconds=settings.readiness_timeout_seconds,
        readiness_interval_seconds=settings.readiness_interval_seconds,
        allow_legacy_pid_markers=settings.allow_legacy_pid_markers,
    )


def _demo_services(settings: Settings, bot_id: str) -> tuple[StateStore, Supervisor, str]:
    settings.ensure_dirs()
    fake_hermes = _demo_hermes_bin(settings)
    store = StateStore(settings.database_path)
    store.init()
    return (
        store,
        Supervisor(
            store,
            fake_hermes,
            settings.hermes_root,
            kill_after_timeout=settings.stop_kill_after_timeout,
            lock_timeout_seconds=settings.lock_timeout_seconds,
            readiness_timeout_seconds=settings.readiness_timeout_seconds,
            readiness_interval_seconds=settings.readiness_interval_seconds,
            allow_legacy_pid_markers=settings.allow_legacy_pid_markers,
            cmdline_reader=_demo_cmdline_reader(settings, fake_hermes, bot_id),
        ),
        fake_hermes,
    )


def _demo_hermes_bin(settings: Settings) -> str:
    installed = shutil.which(DEMO_FAKE_HERMES)
    if installed:
        return installed

    shim = settings.state_dir / "demo" / DEMO_FAKE_HERMES
    shim.parent.mkdir(parents=True, exist_ok=True)
    package_root = Path(__file__).resolve().parent.parent
    shim.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        f"sys.path.insert(0, {json.dumps(str(package_root))})\n"
        "from zeus.demo.fake_hermes import main\n"
        "raise SystemExit(main())\n",
        encoding="utf-8",
    )
    shim.chmod(0o755)
    return str(shim)


def _demo_cmdline_reader(
    settings: Settings, fake_hermes: str, bot_id: str
) -> Callable[[int], list[str] | None]:
    def read(pid: int) -> list[str] | None:
        marker = settings.hermes_root / "fake-gateway.json"
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            try:
                payload = json.loads(marker.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                payload = {}
            if payload.get("pid") == pid and payload.get("profile") == bot_id:
                return [fake_hermes, "-p", bot_id, "gateway", "run"]
            time.sleep(0.01)
        return None

    return read


def _display_path(path: str) -> str:
    resolved = Path(path).resolve()
    try:
        return str(resolved.relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(resolved)


def _parse_env(pairs: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for pair in pairs:
        if "=" not in pair:
            raise SystemExit(f"--env must be NAME=VALUE, got {pair!r}")
        key, value = pair.split("=", 1)
        values[key] = value
    return values


def _resolve_create_env(
    pairs: list[str],
    imported_names: list[str],
    *,
    process_env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    values = _parse_env(pairs)
    for name in imported_names:
        if not ENV_KEY_RE.fullmatch(name):
            raise ValueError("--env-from requires a valid environment variable name")

    duplicate_names = sorted(set(values).intersection(imported_names))
    if duplicate_names:
        raise ValueError(
            "environment variable provided by both --env and --env-from: "
            + ", ".join(duplicate_names)
        )

    source_env = os.environ if process_env is None else process_env
    needs_dotenv = any(name not in source_env for name in imported_names)
    dotenv = load_dotenv(Path(".env")) if needs_dotenv else {}
    for name in imported_names:
        value = source_env[name] if name in source_env else dotenv.get(name)
        if value is None or value == "":
            raise ValueError(f"environment variable {name} is missing or empty")
        values[name] = value
    return values


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    create_env: dict[str, str] = {}
    if args.resource == "bot" and args.action == "create":
        try:
            create_env = _resolve_create_env(args.env, args.env_from)
        except ValueError as exc:
            return _print_cli_error("invalid_request", str(exc), as_json=args.as_json)

    try:
        settings = Settings.from_env()
    except ValueError as exc:
        print(f"Invalid Zeus configuration: {exc}", file=sys.stderr)
        return 1

    if args.resource == "serve":
        try:
            serve(
                host=args.host or settings.host,
                port=args.port if args.port is not None else settings.port,
                settings=settings,
            )
        except (LockTimeoutError, OSError, ValueError) as exc:
            print(f"Zeus API failed to start: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.resource == "doctor":
        report = run_doctor(settings, strict=args.strict)
        print(report_to_json(report) if args.as_json else report_to_text(report), end="")
        return 0 if report.ok else 1

    if args.resource == "demo":
        return _run_demo(args, settings)

    store, supervisor = _services(settings)

    if args.resource == "template" and args.action == "list":
        if args.as_json:
            print(json.dumps([template_to_dict(t) for t in TemplateStore().list()], sort_keys=True))
            return 0
        for template in TemplateStore().list():
            print(f"{template.id}\t{template.name}\t{template.description}")
        return 0

    if args.resource == "bot" and args.action == "list":
        if args.as_json:
            print(json.dumps([bot.to_dict() for bot in store.list_bots()], sort_keys=True))
            return 0
        for bot in store.list_bots():
            print(f"{bot.bot_id}\t{bot.status.value}\t{bot.template_id}\t{bot.display_name}")
        return 0

    if args.resource == "bot" and args.action == "history":
        try:
            payload = store.history_payload(args.bot_id, args.limit, args.before)
        except (KeyError, TemplateError, ValueError) as exc:
            return _print_cli_error(
                _cli_error_code(exc), _cli_error_message(exc), as_json=args.as_json
            )
        if args.as_json:
            print(json.dumps(payload, sort_keys=True))
            return 0
        events = cast(list[dict[str, object]], payload["events"])
        for event in events:
            print(
                f"{event['event_id']}\t{event['occurred_at']}\t{event['action']}\t"
                f"{event['outcome']}\t{event['status_before'] or '-'}\t"
                f"{event['status_after'] or '-'}\t{event['reason']}"
            )
        return 0

    if args.resource == "bot" and args.action == "create":
        try:
            request = BotCreateRequest(
                bot_id=args.bot_id,
                template_id=args.template_id,
                display_name=args.display_name,
                env=create_env,
                restart_policy=RestartPolicy(args.restart_policy),
                restart_backoff_seconds=args.restart_backoff_seconds,
                restart_max_attempts=args.restart_max_attempts,
            )
            template = TemplateStore().get(args.template_id)
            record = supervisor.create_bot(
                request,
                template,
                replace_existing=args.replace_existing,
                stop_if_running=args.stop_if_running,
            )
        except LockTimeoutError:
            print(json.dumps(_lock_conflict_payload(args.bot_id), sort_keys=True))
            return 1
        except ZeusConflictError as exc:
            return _print_cli_error(exc.code, str(exc), as_json=args.as_json)
        except (KeyError, TemplateError, ValueError) as exc:
            return _print_cli_error(
                _cli_error_code(exc), _cli_error_message(exc), as_json=args.as_json
            )
        if args.as_json:
            print(json.dumps(record.to_dict(), sort_keys=True))
            return 0
        print(f"created {record.bot_id} from {record.template_id}")
        return 0

    if args.resource == "bot" and args.action == "delete":
        try:
            response = supervisor.delete_bot(
                args.bot_id,
                stop_if_running=args.stop_if_running,
                remove_profile=args.remove_profile,
            )
        except LockTimeoutError:
            print(json.dumps(_lock_conflict_payload(args.bot_id), sort_keys=True))
            return 1
        except ZeusConflictError as exc:
            return _print_cli_error(exc.code, str(exc), as_json=args.as_json)
        except (KeyError, TemplateError) as exc:
            return _print_cli_error(
                _cli_error_code(exc), _cli_error_message(exc), as_json=args.as_json
            )
        if args.as_json:
            print(json.dumps(response.to_dict(), sort_keys=True))
        else:
            print(f"deleted {response.bot_id}")
        return 0

    if args.resource == "bot" and args.action == "archive":
        try:
            payload = supervisor.archive_bot(args.bot_id, stop_if_running=args.stop_if_running)
        except LockTimeoutError:
            print(json.dumps(_lock_conflict_payload(args.bot_id), sort_keys=True))
            return 1
        except ZeusConflictError as exc:
            return _print_cli_error(exc.code, str(exc), as_json=args.as_json)
        except (KeyError, TemplateError) as exc:
            return _print_cli_error(
                _cli_error_code(exc), _cli_error_message(exc), as_json=args.as_json
            )
        if args.as_json:
            print(json.dumps(payload, sort_keys=True))
        else:
            print(f"archived {payload['bot_id']} to {payload['archive_path']}")
        return 0

    if args.resource == "bot" and args.action == "start":
        try:
            response = supervisor.start(
                args.bot_id,
                wait=args.wait,
                timeout_seconds=args.timeout_seconds,
            )
        except LockTimeoutError:
            print(json.dumps(_lock_conflict_payload(args.bot_id), sort_keys=True))
            return 1
        except (KeyError, TemplateError) as exc:
            return _print_cli_error(_cli_error_code(exc), _cli_error_message(exc), as_json=True)
        print(json.dumps(response.to_dict(), sort_keys=True))
        return _lifecycle_exit_code(response, wait_requested=args.wait)
    if args.resource == "bot" and args.action == "stop":
        try:
            response = supervisor.stop(args.bot_id, kill_after_timeout=args.kill_after_timeout)
        except LockTimeoutError:
            print(json.dumps(_lock_conflict_payload(args.bot_id), sort_keys=True))
            return 1
        except (KeyError, TemplateError) as exc:
            return _print_cli_error(_cli_error_code(exc), _cli_error_message(exc), as_json=True)
        print(json.dumps(response.to_dict(), sort_keys=True))
        return _lifecycle_exit_code(response)
    if args.resource == "bot" and args.action == "restart":
        try:
            response = supervisor.restart(
                args.bot_id,
                wait=args.wait,
                timeout_seconds=args.timeout_seconds,
            )
        except LockTimeoutError:
            print(json.dumps(_lock_conflict_payload(args.bot_id), sort_keys=True))
            return 1
        except (KeyError, TemplateError) as exc:
            return _print_cli_error(_cli_error_code(exc), _cli_error_message(exc), as_json=True)
        print(json.dumps(response.to_dict(), sort_keys=True))
        return _lifecycle_exit_code(response, wait_requested=args.wait)
    if args.resource == "bot" and args.action == "reconcile":
        if args.summary:
            try:
                summary = supervisor.reconcile_summary(
                    args.bot_id,
                    force=args.force,
                    reset_restart=args.reset_restart,
                )
            except ReconcileLockTimeoutError:
                return _print_cli_error(
                    "reconcile_locked",
                    "reconciliation is already in progress",
                    as_json=args.as_json,
                )
            except LockTimeoutError:
                return _print_cli_error(
                    "bot_locked",
                    "bot lifecycle operation is already in progress",
                    as_json=args.as_json,
                )
            except (KeyError, TemplateError) as exc:
                return _print_cli_error(
                    _cli_error_code(exc),
                    _cli_error_message(exc),
                    as_json=args.as_json,
                )
            if args.as_json:
                print(json.dumps(summary.to_dict(), sort_keys=True))
            else:
                _print_reconcile_summary(summary)
            return 0 if summary.ok else 1
        try:
            results = supervisor.reconcile(
                args.bot_id, force=args.force, reset_restart=args.reset_restart
            )
        except LockTimeoutError:
            print(json.dumps([_lock_conflict_payload(args.bot_id or "")], sort_keys=True))
            return 1
        except (KeyError, TemplateError) as exc:
            return _print_cli_error(_cli_error_code(exc), _cli_error_message(exc), as_json=True)
        print(json.dumps([result.to_dict() for result in results], sort_keys=True))
        return _reconcile_exit_code(results)
    if args.resource == "bot" and args.action == "status":
        try:
            response = supervisor.status(args.bot_id)
        except LockTimeoutError:
            print(json.dumps(_lock_conflict_payload(args.bot_id), sort_keys=True))
            return 1
        except (KeyError, TemplateError) as exc:
            return _print_cli_error(_cli_error_code(exc), _cli_error_message(exc), as_json=True)
        print(json.dumps(response.to_dict(), sort_keys=True))
        return _lifecycle_exit_code(response)
    if args.resource == "bot" and args.action == "logs":
        try:
            logs = supervisor.logs(args.bot_id)
        except (KeyError, TemplateError) as exc:
            return _print_cli_error(
                _cli_error_code(exc), _cli_error_message(exc), as_json=args.as_json
            )
        if args.as_json:
            print(json.dumps({"bot_id": args.bot_id, "logs": logs}, sort_keys=True))
        else:
            print(logs, end="")
        return 0
    if args.resource == "bot" and args.action == "inspect":
        try:
            payload = supervisor.inspect(args.bot_id)
        except (KeyError, TemplateError) as exc:
            return _print_cli_error(
                _cli_error_code(exc), _cli_error_message(exc), as_json=args.as_json
            )
        if args.as_json:
            print(json.dumps(payload, sort_keys=True))
        else:
            bot_payload = cast(dict[str, object], payload["bot"])
            print(f"{bot_payload['bot_id']}\t{bot_payload['status']}\t{bot_payload['template_id']}")
            profile_files = cast(dict[str, bool], payload["profile_files"])
            for path, exists in profile_files.items():
                state = "present" if exists else "missing"
                print(f"{path}\t{state}")
            print(f"live_cmdline_verified\t{payload['live_cmdline_verified']}")
        return 0
    if args.resource == "bot" and args.action == "doctor":
        try:
            result = supervisor.adapter.run(args.bot_id, "doctor", timeout=120)
        except TemplateError as exc:
            return _print_cli_error(_cli_error_code(exc), _cli_error_message(exc), as_json=True)
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        return result.returncode

    raise AssertionError(f"unhandled command: {args}")


def _run_demo(args: argparse.Namespace, settings: Settings) -> int:
    store, supervisor, fake_hermes = _demo_services(settings, args.bot_id)
    if args.action == "up":
        record = store.get_bot(args.bot_id)
        if record is None:
            template = TemplateStore().get(DEMO_TEMPLATE_ID)
            record = supervisor.create_bot(
                BotCreateRequest(
                    bot_id=args.bot_id,
                    template_id=DEMO_TEMPLATE_ID,
                    display_name="Demo Coding Bot",
                ),
                template,
                replace_existing=True,
            )
        response = supervisor.start(args.bot_id)
        _wait_for_demo_marker(settings, args.bot_id, response.pid)
        record = store.get_bot(args.bot_id) or record
        payload = {
            "bot": record.to_dict(),
            "fake_hermes_bin": fake_hermes,
            "start": response.to_dict(),
        }
        if args.as_json:
            print(json.dumps(payload, sort_keys=True))
        else:
            print(f"{args.bot_id}\t{response.status.value}\t{_display_path(fake_hermes)}")
        return _lifecycle_exit_code(response)

    if args.action == "status":
        response = supervisor.status(args.bot_id)
        if args.as_json:
            print(
                json.dumps(
                    {"fake_hermes_bin": fake_hermes, "status": response.to_dict()},
                    sort_keys=True,
                )
            )
        else:
            print(f"{args.bot_id}\t{response.status.value}\t{response.pid or ''}")
        return _lifecycle_exit_code(response)

    if args.action == "down":
        response = supervisor.stop(args.bot_id)
        if args.as_json:
            print(
                json.dumps(
                    {"fake_hermes_bin": fake_hermes, "stop": response.to_dict()},
                    sort_keys=True,
                )
            )
        else:
            print(f"{args.bot_id}\t{response.status.value}")
        return _lifecycle_exit_code(response)

    raise AssertionError(f"unhandled demo command: {args}")


def _lock_conflict_payload(bot_id: str) -> dict[str, object]:
    return {
        "bot_id": bot_id,
        "status": BotStatus.failed.value,
        "pid": None,
        "profile_path": "",
        "message": "bot lifecycle operation is already in progress",
    }


def _lifecycle_exit_code(response: BotStatusResponse, *, wait_requested: bool = False) -> int:
    if response.status in {BotStatus.failed, BotStatus.unknown}:
        return 1
    if wait_requested and response.status == BotStatus.starting:
        return 1
    return 0


def _reconcile_exit_code(results: list[BotStatusResponse]) -> int:
    expected_pending_prefixes = ("restart scheduled:", "restart pending:")
    for result in results:
        if result.status not in {BotStatus.failed, BotStatus.unknown}:
            continue
        if result.message.startswith(expected_pending_prefixes):
            continue
        return 1
    return 0


def _print_reconcile_summary(summary: ReconcileRunSummary) -> None:
    print(f"run_id: {summary.run_id}")
    print(f"scope: {summary.scope}")
    print(f"started_at: {summary.started_at.isoformat()}")
    print(f"finished_at: {summary.finished_at.isoformat()}")
    print(f"outcome: {summary.outcome}")
    counts = " ".join(f"{name}={value}" for name, value in summary.counts.items())
    print(f"counts: {counts}")
    print(f"total: {summary.total}")
    print("results:")
    for result in summary.results:
        print(
            "\t".join(
                (
                    result.bot_id,
                    result.outcome.value,
                    result.action,
                    result.observed_status or "-",
                    result.message,
                )
            )
        )


def _print_cli_error(code: str, message: str, *, as_json: bool) -> int:
    if as_json:
        print(json.dumps({"error": {"code": code, "message": message}}, sort_keys=True))
    else:
        print(message, file=sys.stderr)
    return 1


def _cli_error_code(exc: Exception) -> str:
    message = _cli_error_message(exc)
    if isinstance(exc, KeyError) and message.startswith("unknown bot:"):
        return "unknown_bot"
    if isinstance(exc, KeyError) and message.startswith("unknown template:"):
        return "unknown_template"
    if message.startswith("bot_id must match"):
        return "invalid_bot_id"
    return "invalid_request"


def _cli_error_message(exc: Exception) -> str:
    if isinstance(exc, KeyError) and exc.args:
        return str(exc.args[0])
    return str(exc)


def _wait_for_demo_marker(settings: Settings, bot_id: str, pid: int | None) -> None:
    if pid is None:
        return
    marker = settings.hermes_root / "fake-gateway.json"
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        try:
            payload = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {}
        if payload.get("pid") == pid and payload.get("profile") == bot_id:
            return
        time.sleep(0.05)


if __name__ == "__main__":
    sys.exit(main())
