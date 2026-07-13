from __future__ import annotations

import json
import os
import signal
import sys
import time
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        profile_index = args.index("-p") + 1
        bot_id = args[profile_index]
    except (ValueError, IndexError):
        print("fake hermes requires -p <bot-id>", file=sys.stderr)
        return 2

    command = args[profile_index + 1 :]
    if command == ["doctor"]:
        print(f"fake hermes doctor ok for {bot_id}")
        return 0
    if command == ["gateway", "run"]:
        return _run_gateway(bot_id, args)

    print(f"unsupported fake hermes command: {' '.join(args)}", file=sys.stderr)
    return 2


def _run_gateway(bot_id: str, args: list[str]) -> int:
    hermes_home = Path(os.environ["HERMES_HOME"])
    hermes_home.mkdir(parents=True, exist_ok=True)
    marker_path = hermes_home / "fake-gateway.json"
    marker_path.write_text(
        json.dumps(
            {
                "profile": bot_id,
                "argv": [sys.argv[0], *args],
                "pid": os.getpid(),
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print("fake gateway starting", flush=True)

    running = True

    def stop(signum: int, frame: object) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    while running:
        time.sleep(0.05)
    print("fake gateway stopping", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
