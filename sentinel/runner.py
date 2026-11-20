import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from sentinel.config import TIMEOUT

PARSER_LIMIT = 512 * 1024
PARSER_ENV = (
    "PATH",
    "SystemRoot",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "SENTINEL_MAX_UPLOAD_MIB",
    "SENTINEL_MAX_UNPACKED_MIB",
    "SENTINEL_MAX_ENTRIES",
    "SENTINEL_APKSIGNER_JAR",
    "SENTINEL_JAVA",
)


def stop_process(process):
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=8,
                check=False,
            )
        finally:
            if process.poll() is None:
                process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.wait(timeout=10)


def read_result(path):
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > PARSER_LIMIT:
            raise ValueError("Invalid parser output")
        data = stream.read(PARSER_LIMIT + 1)
        if len(data) > PARSER_LIMIT:
            raise ValueError("Parser output exceeds its limit")
        return json.loads(data)


def run_parser(path, refresh):
    with tempfile.TemporaryDirectory(prefix="sentinel-") as scratch:
        result = Path(scratch) / "result.json"
        env = {name: os.environ[name] for name in PARSER_ENV if name in os.environ}
        process = subprocess.Popen(
            [sys.executable, "-m", "sentinel.parser", str(path), str(result)],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=os.name != "nt",
        )
        try:
            deadline = time.monotonic() + TIMEOUT
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return {"error": "Scan exceeded the worker time limit."}
                try:
                    code = process.wait(timeout=min(remaining, 4))
                    break
                except subprocess.TimeoutExpired:
                    refresh()
            if code or not result.is_file():
                return {"error": "APK parser exited without a usable result."}
            return read_result(result)
        finally:
            if process.poll() is None:
                stop_process(process)
