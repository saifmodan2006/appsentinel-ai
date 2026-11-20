import json
import os
import sys
from pathlib import Path
from zipfile import BadZipFile

from sentinel.apk import InvalidAPK, inspect
from sentinel.runner import PARSER_LIMIT


def main():
    try:
        report = inspect(
            Path(sys.argv[1]),
            os.getenv("SENTINEL_APKSIGNER_JAR"),
            os.getenv("SENTINEL_JAVA", "java"),
        )
    except InvalidAPK as exc:
        report = {"error": str(exc)}
    except (BadZipFile, EOFError, ValueError):
        report = {"error": "Malformed or unsupported APK structure."}
    except Exception:
        report = {"error": "APK parsing failed."}
    serialized = json.dumps(report, ensure_ascii=True, separators=(",", ":"))
    if len(serialized) > PARSER_LIMIT:
        serialized = (
            '{"error":"APK produced more evidence than the worker can retain."}'
        )
    Path(sys.argv[2]).write_text(serialized, encoding="utf-8")


if __name__ == "__main__":
    main()
