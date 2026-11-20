import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()
ROOT = Path(os.getenv("SENTINEL_DATA", "data")).resolve()
UPLOADS = ROOT / "uploads"
DATABASE = os.getenv("SENTINEL_DATABASE", f"sqlite:///{ROOT / 'sentinel.db'}")
SECURE_COOKIE = os.getenv("SENTINEL_SECURE_COOKIE", "false").lower() == "true"
ALLOW_REGISTER = os.getenv("SENTINEL_ALLOW_REGISTER", "true").lower() == "true"


def limit(name, default, minimum, maximum):
    value = int(os.getenv(f"SENTINEL_{name}", default))
    if not minimum <= value <= maximum:
        raise ValueError(f"SENTINEL_{name} is outside its allowed range")
    return value


MAX_UPLOAD = limit("MAX_UPLOAD_MIB", 64, 1, 512) * 1024**2
MAX_UNPACKED = limit("MAX_UNPACKED_MIB", 256, 1, 1024) * 1024**2
MAX_ENTRIES = limit("MAX_ENTRIES", 15000, 1, 50000)
QUEUE_LIMIT = limit("QUEUE_LIMIT", 24, 1, 512)
TIMEOUT = limit("TIMEOUT_SECONDS", 90, 5, 600)
RETENTION = limit("RETENTION_DAYS", 30, 1, 3650)
SESSION_TTL = 12 * 3600
