from __future__ import annotations

import json
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

from zeus.models import BotCreateRequest, BotStatus
from zeus.renderer import ProfileRenderer
from zeus.state import StateStore
from zeus.supervisor import Supervisor
from zeus.templates import TemplateStore


class FakeHermesIntegrationTests(unittest.TestCase):
    def test_start_status_stop_with_fake_hermes_gateway(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_hermes = root / "fake-hermes"
            fake_hermes.write_text(
                textwrap.dedent(
                    f"""\
                    #!{sys.executable}
                    import json
                    import os
                    import signal
                    import sys
                    import time
                    from pathlib import Path

                    home = Path(os.environ["HERMES_HOME"])
                    profile = sys.argv[sys.argv.index("-p") + 1]

                    if sys.argv[-1] == "doctor":
                        print("fake hermes doctor ok for", profile)
                        raise SystemExit(0)

                    if sys.argv[-2:] == ["gateway", "run"]:
                        marker = home / "fake-gateway.json"
                        payload = {{"profile": profile, "argv": sys.argv}}
                        marker.write_text(json.dumps(payload), encoding="utf-8")
                        print("fake gateway starting", flush=True)

                        running = True
                        def stop(signum, frame):
                            global running
                            running = False

                        signal.signal(signal.SIGTERM, stop)
                        while running:
                            time.sleep(0.05)
                        print("fake gateway stopping", flush=True)
                        raise SystemExit(0)

                    print("unsupported fake hermes command", sys.argv, file=sys.stderr)
                    raise SystemExit(2)
                    """
                ),
                encoding="utf-8",
            )
            fake_hermes.chmod(0o755)

            hermes_root = root / ".zeus" / "hermes"
            template = TemplateStore().get("coding-bot")
            record = ProfileRenderer(hermes_root).render(
                BotCreateRequest(bot_id="coder", template_id="coding-bot"),
                template,
            )
            store = StateStore(root / ".zeus" / "zeus.db")
            store.init()
            store.upsert_bot(record)
            supervisor = Supervisor(store, str(fake_hermes), hermes_root, stop_grace_seconds=2.0)

            started = supervisor.start("coder")
            self.assertEqual(BotStatus.running, started.status)
            self.assertTrue(supervisor.pid_marker_path(record.profile_path).exists())

            marker_path = hermes_root / "fake-gateway.json"
            for _ in range(40):
                if marker_path.exists():
                    break
                time.sleep(0.05)
            self.assertTrue(marker_path.exists())
            payload = json.loads(marker_path.read_text(encoding="utf-8"))
            self.assertEqual("coder", payload["profile"])

            status = supervisor.status("coder")
            self.assertEqual(BotStatus.running, status.status)

            stopped = supervisor.stop("coder")
            self.assertEqual(BotStatus.stopped, stopped.status)
            self.assertFalse(supervisor.pid_marker_path(record.profile_path).exists())
            self.assertIn("fake gateway starting", supervisor.logs("coder"))


if __name__ == "__main__":
    unittest.main()
