"""Run static APK inspection with a read-only input mount and no network."""

import json
import os
import re
import sys
import time
from pathlib import Path

from sentinel.runner import run_parser

ROOT = Path(os.environ.get("SENTINEL_EXCHANGE", "/exchange"))
INBOX = ROOT / "in"
OUTBOX = ROOT / "out"
HEARTBEAT = OUTBOX / "alive"


def refresh():
    (OUTBOX / "alive.tmp").write_text(str(int(time.time())), encoding="ascii")
    (OUTBOX / "alive.tmp").replace(HEARTBEAT)


def main():
    if "--health" in sys.argv:
        raise SystemExit(
            0
            if HEARTBEAT.exists() and time.time() - HEARTBEAT.stat().st_mtime < 18
            else 1
        )
    while True:
        refresh()
        now = time.time()
        for report in OUTBOX.glob("*.json*"):
            if report.lstat().st_mtime < now - 300:
                report.unlink(missing_ok=True)
        for path in sorted(INBOX.glob("*.apk")):
            if not re.fullmatch(r"[0-9a-f-]{36}", path.stem):
                continue
            result = OUTBOX / (path.stem + ".json")
            if result.exists():
                continue
            try:
                parsed = run_parser(path, refresh)
            except Exception:
                parsed = {"error": "Isolated APK parser failed."}
            temporary = result.with_suffix(".json.tmp")
            temporary.write_text(
                json.dumps(parsed, ensure_ascii=True, separators=(",", ":")),
                encoding="ascii",
            )
            temporary.replace(result)
            break
        else:
            time.sleep(0.4)


if __name__ == "__main__":
    main()
