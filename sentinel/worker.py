import logging
import os
import shutil
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import delete, select, update

from sentinel.config import RETENTION, TIMEOUT, UPLOADS
from sentinel.db import (
    catalog,
    engine,
    migrate,
    queue_lock,
    scans,
    sessions,
    state,
    throttle,
)
from sentinel.indicators import load_indicators, match_indicators
from sentinel.model import load_model, predict
from sentinel.runner import read_result, run_parser
from sentinel.rules import VERSION, assess_identity, assessment, findings_for

log = logging.getLogger("sentinel.worker")
EXCHANGE = os.getenv("SENTINEL_EXCHANGE")


def sandbox_online():
    if not EXCHANGE:
        return True
    try:
        return time.time() - (Path(EXCHANGE) / "out" / "alive").lstat().st_mtime < 18
    except FileNotFoundError:
        return False


def heartbeat():
    now = int(time.time()) if sandbox_online() else 0
    with engine.begin() as conn:
        conn.execute(
            update(state).where(state.c.key == "worker_heartbeat").values(value=now)
        )


def claim():
    now = int(time.time())
    with engine.begin() as conn:
        queue_lock(conn)
        conn.execute(
            update(scans)
            .where(scans.c.status == "running", scans.c.started < now - TIMEOUT - 45)
            .values(
                status="failed",
                finished=now,
                error="Worker stopped before completing the scan.",
            )
        )
        row = (
            conn.execute(
                select(scans)
                .where(scans.c.status == "queued")
                .order_by(scans.c.created, scans.c.id)
                .limit(1)
            )
            .mappings()
            .first()
        )
        if row:
            conn.execute(
                update(scans)
                .where(scans.c.id == row["id"])
                .values(status="running", started=now)
            )
            return {**row, "started": now}
    return None


def sweep():
    now = int(time.time())
    with engine.begin() as conn:
        queue_lock(conn)
        conn.execute(delete(sessions).where(sessions.c.expires < now))
        conn.execute(delete(throttle).where(throttle.c.window < now - 86400))
        expired = scans.c.created < now - 86400 * RETENTION
        conn.execute(delete(scans).where(expired, scans.c.status != "running"))
        active = set(
            conn.scalars(
                select(scans.c.id).where(scans.c.status.in_(("queued", "running")))
            )
        )
        for path in UPLOADS.glob("*.apk"):
            if path.stem not in active:
                path.unlink(missing_ok=True)
        for path in UPLOADS.glob("*.partial"):
            if path.stat().st_mtime < now - 3600:
                path.unlink(missing_ok=True)
        if EXCHANGE:
            for path in (Path(EXCHANGE) / "in").iterdir():
                if path.stem not in active:
                    path.unlink(missing_ok=True)


def parse(path):
    if not EXCHANGE:
        return run_parser(path, heartbeat)
    root = Path(EXCHANGE)
    input_path = root / "in" / path.name
    temporary = input_path.with_suffix(".partial")
    output_path = root / "out" / f"{path.stem}.json"
    try:
        shutil.copyfile(path, temporary)
        temporary.replace(input_path)
        deadline = time.monotonic() + TIMEOUT + 12
        while time.monotonic() < deadline:
            try:
                return read_result(output_path)
            except FileNotFoundError:
                heartbeat()
                time.sleep(0.6)
        return {"error": "Isolated scanner exceeded its time limit or was unavailable."}
    finally:
        input_path.unlink(missing_ok=True)
        temporary.unlink(missing_ok=True)


def run_one(model=None, indicators=None):
    row = claim()
    if not row:
        return False
    path = UPLOADS / f"{row['id']}.apk"
    report, error = None, None
    started = time.monotonic()
    try:
        parsed = parse(path)
        error = parsed.get("error")
        if not error:
            with engine.connect() as conn:
                references = conn.scalars(
                    select(catalog.c.record).order_by(catalog.c.package)
                ).all()
            identity = assess_identity(
                parsed["metadata"], parsed["signing"], references
            )
            threat = match_indicators(
                indicators, row["sha256"], parsed["code"]["embedded_hosts"]
            )
            findings = findings_for(parsed, threat)
            model_result = predict(parsed, model)
            report = {
                "report_id": row["id"],
                "schema_version": "1.0",
                "rule_version": VERSION,
                "scanned_at": datetime.now(UTC).isoformat(),
                "filename": row["filename"],
                "sha256": row["sha256"],
                "bytes": row["bytes"],
                **{
                    field: parsed[field]
                    for field in ("metadata", "signing", "code", "missing", "tools")
                },
                "identity": identity,
                "findings": findings,
                "model": model_result,
                "threat_indicators": threat,
                "assessment": assessment(parsed, identity, findings, model_result),
                "limitations": [
                    "Static analysis only. The scanner did not install or execute the APK.",
                    "Permission requests and DEX references describe possible capabilities.",
                    "Distribution provenance is unknown unless supported by independent catalog evidence.",
                    "A low observed risk result leaves other risks possible.",
                ],
                "analysis_seconds": round(time.monotonic() - started, 4),
            }
    except Exception as exc:
        error = "The worker could not finish this scan."
        log.error("Scan %s failed with %s", row["id"], type(exc).__name__)
    with engine.begin() as conn:
        conn.execute(
            update(scans)
            .where(
                scans.c.id == row["id"],
                scans.c.status == "running",
                scans.c.started == row["started"],
            )
            .values(
                status="failed" if error else "completed",
                finished=int(time.time()),
                error=error,
                report=report,
            )
        )
    try:
        path.unlink(missing_ok=True)
    except OSError:
        log.warning("Deferred temporary file cleanup for scan %s", row["id"])
    return True


def main():
    if "--health" in sys.argv:
        with engine.connect() as conn:
            last = conn.scalar(
                select(state.c.value).where(state.c.key == "worker_heartbeat")
            )
        raise SystemExit(0 if last and time.time() - last < 20 else 1)
    logging.basicConfig(level=logging.INFO)
    migrate()
    model = load_model()
    indicators = load_indicators()
    with engine.begin() as conn:
        conn.execute(
            update(state)
            .where(state.c.key == "model_enabled")
            .values(value=int(model is not None))
        )
    log.info("Static analysis worker started")
    last_sweep = 0.0
    while True:
        try:
            heartbeat()
            if time.monotonic() - last_sweep > 30 or last_sweep == 0:
                sweep()
                last_sweep = time.monotonic()
            if not sandbox_online() or not run_one(model, indicators):
                time.sleep(1)
        except Exception as exc:
            log.error("Worker cycle failed with %s", type(exc).__name__)
            time.sleep(3)


if __name__ == "__main__":
    main()
