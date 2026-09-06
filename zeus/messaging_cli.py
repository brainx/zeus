"""Explicit asynchronous operator jobs, with bounded input outside shell arguments."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from typing import Any

from zeus.bot_messaging import MAX_INPUT_BYTES, BotMessaging, MessagingError
from zeus.config import Settings
from zeus.hermes_runs_client import HermesRunsClientError
from zeus.message_store import MessageStoreError
from zeus.state import StateReadinessError, StateStore
from zeus.supervisor import Supervisor


def add_messaging_parsers(sub: Any) -> None:
    messages = sub.add_parser("message", help="submit and inspect explicit operator jobs")
    actions = messages.add_subparsers(dest="action", required=True)
    for action in ("send", "retry", "status", "cancel", "list"):
        parser = actions.add_parser(action)
        if action == "send":
            parser.add_argument("bot_id")
            parser.add_argument("--request-key", help="optional stable key for this submission")
        elif action != "list":
            parser.add_argument("message_id")
        if action in {"send", "retry"}:
            parser.add_argument("--file", required=True, help="UTF-8 input file, or - for stdin")
        if action == "list":
            parser.add_argument("--bot-id")
            parser.add_argument("--before", help="cursor returned by the previous page")
            parser.add_argument("--limit", type=int, default=50, help="maximum receipts (1-100)")
        parser.add_argument("--json", action="store_true", dest="as_json")


def _read_input(path: str) -> str:
    try:
        if path == "-":
            data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        else:
            flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
            descriptor = os.open(path, flags)
            with os.fdopen(descriptor, "rb") as source:
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                    raise MessagingError("invalid_input_file")
                data = source.read(MAX_INPUT_BYTES + 1)
        if len(data) > MAX_INPUT_BYTES:
            raise MessagingError("input_too_large")
        return data.decode("utf-8", errors="strict")
    except MessagingError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise MessagingError("invalid_input_file") from exc


def run_messaging_command(args: argparse.Namespace, settings: Settings) -> int:
    # Existing schema is required; commands do not initialize state, migrate,
    # reconcile, or start gateways as a side effect of sending a message.
    workflow = BotMessaging(
        Supervisor(StateStore(settings.database_path), settings.hermes_bin, settings.hermes_root)
    )
    try:
        if args.action == "send":
            payload = workflow.send(
                args.bot_id, _read_input(args.file), request_key=args.request_key
            )
        elif args.action == "retry":
            payload = workflow.retry(args.message_id, _read_input(args.file))
        elif args.action == "status":
            payload = workflow.status(args.message_id)
        elif args.action == "cancel":
            payload = workflow.cancel(args.message_id)
        else:
            payload = workflow.list(bot_id=args.bot_id, limit=args.limit, before=args.before)
    except StateReadinessError:
        return _error("not_ready", args.as_json)
    except (MessagingError, MessageStoreError, HermesRunsClientError) as exc:
        return _error(exc.code, args.as_json)
    except (OSError, RuntimeError, ValueError):
        return _error("message_state_unavailable", args.as_json)
    print(json.dumps(payload, sort_keys=True, indent=None if args.as_json else 2))
    return 1 if payload.get("dispatch_state") in {"unknown", "rejected", "prepared"} else 0


def _error(code: str, as_json: bool) -> int:
    if as_json:
        print(json.dumps({"error": {"code": code, "message": code.replace("_", " ")}}))
    else:
        print(code.replace("_", " "), file=sys.stderr)
    return 1
