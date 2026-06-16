from __future__ import annotations

import argparse
import json
import sys

from zeus.api import serve
from zeus.config import Settings
from zeus.doctor import report_to_json, report_to_text, run_doctor
from zeus.models import BotCreateRequest
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
    template_sub.add_parser("list")

    bot = sub.add_parser("bot")
    bot_sub = bot.add_subparsers(dest="action", required=True)

    create = bot_sub.add_parser("create")
    create.add_argument("bot_id")
    create.add_argument("--template", required=True, dest="template_id")
    create.add_argument("--name", dest="display_name")
    create.add_argument("--env", action="append", default=[], help="NAME=VALUE for rendered profile .env")

    bot_sub.add_parser("list")
    for action in ["start", "stop", "status", "logs", "doctor"]:
        command = bot_sub.add_parser(action)
        command.add_argument("bot_id")

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
        for template in TemplateStore().list():
            print(f"{template.id}\t{template.name}\t{template.description}")
        return 0

    if args.resource == "bot" and args.action == "list":
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
            ),
            template,
        )
        store.upsert_bot(record)
        print(f"created {record.bot_id} from {record.template_id}")
        return 0

    if args.resource == "bot" and args.action == "start":
        print(json.dumps(supervisor.start(args.bot_id).to_dict(), sort_keys=True))
        return 0
    if args.resource == "bot" and args.action == "stop":
        print(json.dumps(supervisor.stop(args.bot_id).to_dict(), sort_keys=True))
        return 0
    if args.resource == "bot" and args.action == "status":
        print(json.dumps(supervisor.status(args.bot_id).to_dict(), sort_keys=True))
        return 0
    if args.resource == "bot" and args.action == "logs":
        print(supervisor.logs(args.bot_id), end="")
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
