#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import signal
import sys
import time
from pathlib import Path


def main() -> int:
    if "-p" not in sys.argv or sys.argv[-2:] != ["gateway", "run"]:
        return 0
    bot_id = sys.argv[sys.argv.index("-p") + 1]
    marker_dir = os.environ.get("FAKE_HERMES_MARKER_DIR")
    if marker_dir:
        path = Path(marker_dir)
        path.mkdir(parents=True, exist_ok=True)
        marker = path / f"{bot_id}-{os.getpid()}.json"
        marker.write_text(
            json.dumps(
                {
                    "bot_id": bot_id,
                    "pid": os.getpid(),
                    "argv": sys.argv,
                    "started_at": time.time(),
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    running = True

    def stop(_signum: int, _frame: object) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while running:
        time.sleep(0.05)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
