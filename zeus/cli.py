from __future__ import annotations

import argparse
import json
import sys

from zeus.api import serve, template_to_dict
from zeus.config import Settings
from zeus.doctor import report_to_json, report_to_text, run_doctor
from zeus.models import BotCreateRequest, RestartPolicy
from zeus.renderer import ProfileRenderer
from zeus.state import StateStore
from zeus.supervisor import Supervisor
from zeus.templates import TemplateStore


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

    bot = sub.add_parser("bot")
    bot_sub = bot.add_subparsers(dest="action", required=True)

    create = bot_sub.add_parser("create")
    create.add_argument("bot_id")
    create.add_argument("--template", required=True, dest="template_id")
    create.add_argument("--name", dest="display_name")
    create.add_argument(
        "--env", action="append", default=[], help="NAME=VALUE for rendered profile .env"
    )
    create.add_argument("--restart-policy", choices=["manual", "on-failure"], default="manual")
    create.add_argument("--restart-backoff-seconds", type=float, default=5.0)
    create.add_argument("--restart-max-attempts", type=int, default=5)
    create.add_argument("--json", action="store_true", dest="as_json")

    bot_list = bot_sub.add_parser("list")
    bot_list.add_argument("--json", action="store_true", dest="as_json")
    reconcile = bot_sub.add_parser("reconcile")
    reconcile.add_argument("bot_id", nargs="?")
    reconcile.add_argument("--json", action="store_true", dest="as_json")
    reconcile.add_argument("--force", action="store_true")
    reconcile.add_argument("--reset-restart", action="store_true")
    for action in ["start", "stop", "restart", "status", "logs", "doctor"]:
        command = bot_sub.add_parser(action)
        command.add_argument("bot_id")
        if action == "logs":
            command.add_argument("--json", action="store_true", dest="as_json")

    return parser


def _services(settings: Settings) -> tuple[StateStore, Supervisor]:
    settings.ensure_dirs()
    store = StateStore(settings.database_path)
    store.init()
    return store, Supervisor(store, settings.hermes_bin, settings.hermes_root)


def _parse_env(pairs: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for pair in pairs:
        if "=" not in pair:
            raise SystemExit(f"--env must be NAME=VALUE, got {pair!r}")
        key, value = pair.split("=", 1)
        values[key] = value
    return values


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = Settings.from_env()

    if args.resource == "serve":
        serve(host=args.host or settings.host, port=args.port or settings.port, settings=settings)
        return 0

    if args.resource == "doctor":
        report = run_doctor(settings, strict=args.strict)
        print(report_to_json(report) if args.as_json else report_to_text(report), end="")
        return 0 if report.ok else 1

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

    if args.resource == "bot" and args.action == "create":
        template = TemplateStore().get(args.template_id)
        record = ProfileRenderer(settings.hermes_root).render(
            BotCreateRequest(
                bot_id=args.bot_id,
                template_id=args.template_id,
                display_name=args.display_name,
                env=_parse_env(args.env),
                restart_policy=RestartPolicy(args.restart_policy),
                restart_backoff_seconds=args.restart_backoff_seconds,
                restart_max_attempts=args.restart_max_attempts,
            ),
            template,
        )
        store.upsert_bot(record)
        store.append_audit_event("bot.create", bot_id=record.bot_id, template_id=record.template_id)
        if args.as_json:
            print(json.dumps(record.to_dict(), sort_keys=True))
            return 0
        print(f"created {record.bot_id} from {record.template_id}")
        return 0

    if args.resource == "bot" and args.action == "start":
        print(json.dumps(supervisor.start(args.bot_id).to_dict(), sort_keys=True))
        return 0
    if args.resource == "bot" and args.action == "stop":
        print(json.dumps(supervisor.stop(args.bot_id).to_dict(), sort_keys=True))
        return 0
    if args.resource == "bot" and args.action == "restart":
        print(json.dumps(supervisor.restart(args.bot_id).to_dict(), sort_keys=True))
        return 0
    if args.resource == "bot" and args.action == "reconcile":
        results = supervisor.reconcile(
            args.bot_id, force=args.force, reset_restart=args.reset_restart
        )
        print(json.dumps([result.to_dict() for result in results], sort_keys=True))
        return 0
    if args.resource == "bot" and args.action == "status":
        print(json.dumps(supervisor.status(args.bot_id).to_dict(), sort_keys=True))
        return 0
    if args.resource == "bot" and args.action == "logs":
        logs = supervisor.logs(args.bot_id)
        if args.as_json:
            print(json.dumps({"bot_id": args.bot_id, "logs": logs}, sort_keys=True))
        else:
            print(logs, end="")
        return 0
    if args.resource == "bot" and args.action == "doctor":
        result = supervisor.adapter.run(args.bot_id, "doctor", timeout=120)
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        return result.returncode

    raise AssertionError(f"unhandled command: {args}")


if __name__ == "__main__":
    sys.exit(main())
