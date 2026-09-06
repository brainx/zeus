"""Inspection commands that never initialize state or run lifecycle operations."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from zeus.fleet_overview import FleetOverviewReader
from zeus.reconcile_history import ReconcileHistoryReader
from zeus.sanitization import sanitize_text
from zeus.state import StateReadinessError


def add_operator_parsers(sub: Any) -> None:
    reconcile = sub.add_parser("reconcile", help="inspect persisted reconciliation runs")
    actions = reconcile.add_subparsers(dest="action", required=True)
    listing = actions.add_parser("list", help="list recorded runs without reconciling")
    listing.add_argument("--before", help="opaque cursor from the previous page")
    listing.add_argument(
        "--outcome", choices=("running", "succeeded", "completed_with_errors", "interrupted")
    )
    listing.add_argument("--bot-id", help="include runs requested for or containing this bot")
    detail = actions.add_parser("show", help="show a run and a page of its results")
    detail.add_argument("run_id")
    detail.add_argument("--after", type=int, help="exclusive result ordinal from the previous page")
    fleet = sub.add_parser("fleet", help="inspect stored fleet state and observation freshness")
    status = fleet.add_subparsers(dest="action", required=True).add_parser(
        "status", help="show persisted observations without probing gateways"
    )
    status.add_argument("--after", help="exclusive bot ID from the previous page")
    status.add_argument("--attention-only", action="store_true")
    status.add_argument("--stale-after-seconds", type=float, default=120)
    for parser in (listing, detail, status):
        parser.add_argument("--limit", type=int, default=50, help="page size (1-100, default: 50)")
        parser.add_argument("--json", action="store_true", dest="as_json")


def run_operator_command(args: argparse.Namespace, database_path: Path) -> int:
    try:
        if args.resource == "fleet":
            payload = FleetOverviewReader(database_path).overview(
                limit=args.limit,
                after=args.after,
                attention_only=args.attention_only,
                stale_after_seconds=args.stale_after_seconds,
            )
        elif args.action == "list":
            payload = ReconcileHistoryReader(database_path).list_runs(
                limit=args.limit, before=args.before, outcome=args.outcome, bot_id=args.bot_id
            )
        else:
            result = ReconcileHistoryReader(database_path).get_run(
                args.run_id, limit=args.limit, after=args.after
            )
            if result is None:
                return _error("unknown_reconcile_run", "unknown reconciliation run", args.as_json)
            payload = result
    except StateReadinessError:
        return _error("not_ready", "operator evidence is unavailable", args.as_json)
    except ValueError as exc:
        return _error("invalid_request", str(exc), args.as_json)
    if args.as_json:
        print(json.dumps(payload, sort_keys=True))
    else:
        _render(args, payload)
    return 0


def _error(code: str, message: str, as_json: bool) -> int:
    if as_json:
        print(json.dumps({"error": {"code": code, "message": message}}, sort_keys=True))
    else:
        print(message, file=sys.stderr)
    return 1


def _render(args: argparse.Namespace, payload: dict[str, Any]) -> None:
    if args.resource == "fleet":
        print("Stored fleet evidence (no live probe)")
        for item in payload["items"]:
            reasons = ", ".join(item["attention_reasons"]) or "none"
            print(
                f"{item['bot_id']}\tdesired={item['desired_state']}\tstored={item['stored_status']}"
                f"\tfreshness={item['freshness']}\tattention={reasons}"
            )
        cursor, flag = payload["next_after"], "--after"
    elif args.action == "list":
        for run in payload["runs"]:
            run_id = sanitize_text(run["run_id"], max_length=128)
            print(
                f"{run_id}\t{run['started_at']}\t{run['scope']}\t{run['outcome']}"
                f"\t{run['total']} results"
            )
        cursor, flag = payload["next_before"], "--before"
    else:
        run = payload["run"]
        run_id = sanitize_text(run["run_id"], max_length=128)
        print(f"{run_id}\t{run['outcome']}\t{run['total']} results")
        for result in payload["results"]:
            print(
                f"{result['ordinal']}\t{result['bot_id']}\t{result['outcome']}\t{result['message']}"
            )
        cursor, flag = payload["next_after"], "--after"
    if cursor is not None:
        print(f"Next page: {flag} {cursor}")
