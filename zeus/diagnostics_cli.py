"""Live gateway inspection without initializing state or running lifecycle actions."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, cast

from zeus.bot_diagnostics import diagnose_bot
from zeus.config import Settings
from zeus.models import TemplateError
from zeus.state import StateReadinessError, StateStore
from zeus.supervisor import Supervisor


def run_diagnostics_command(args: argparse.Namespace, settings: Settings) -> int:
    # Constructing the readers does not create directories, migrate the database,
    # or recover pending lifecycle operations.
    supervisor = Supervisor(
        StateStore(settings.database_path), settings.hermes_bin, settings.hermes_root
    )
    try:
        payload = diagnose_bot(supervisor, args.bot_id)
    except StateReadinessError:
        return _error("not_ready", "bot state is unavailable", args.as_json)
    except KeyError:
        return _error("unknown_bot", "unknown bot", args.as_json)
    except TemplateError as exc:
        return _error("invalid_bot_id", str(exc), args.as_json)
    if args.as_json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(f"{payload['bot_id']}\t{payload['status']}\t{payload['reason']}")
        print(f"observed_at\t{payload['observed_at']}")
        if payload["health"] is not None:
            health = cast(dict[str, Any], payload["health"])
            for name, check in health["readiness"]["checks"].items():
                print(f"{name}\t{check['status']}")
            print(f"active_agents\t{health['active_agents']}")
    return 0 if payload["status"] == "ok" else 1


def _error(code: str, message: str, as_json: bool) -> int:
    if as_json:
        print(json.dumps({"error": {"code": code, "message": message}}, sort_keys=True))
    else:
        print(message, file=sys.stderr)
    return 1
