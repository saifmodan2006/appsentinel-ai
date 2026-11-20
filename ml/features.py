"""Write the scanner's feature contract from one completed JSON report."""

import argparse
import json
from pathlib import Path

from sentinel.model import features


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    if any(
        item["field"] == "DEX" or item["field"].endswith(".dex")
        for item in report["missing"]
    ):
        raise SystemExit("Report lacks complete DEX coverage")
    print(json.dumps({"sha256": report["sha256"], **features(report)}, sort_keys=True))


if __name__ == "__main__":
    main()
