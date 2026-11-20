"""Load an operator-approved threat indicator snapshot without network calls."""

import hashlib
import json
import os
import re
from pathlib import Path


def load_indicators():
    path = os.getenv("SENTINEL_INDICATORS")
    expected = os.getenv("SENTINEL_INDICATORS_SHA256")
    if not path and not expected:
        return None
    if not path or not expected:
        raise ValueError("Both indicator path and digest are required")
    with Path(path).open("rb") as stream:
        blob = stream.read(512 * 1024 + 1)
    if len(blob) > 512 * 1024 or hashlib.sha256(blob).hexdigest() != expected.lower():
        raise ValueError("Threat indicator inventory integrity check failed")
    data = json.loads(blob)
    version = data["version"]
    entries = data["entries"]
    if (
        not isinstance(version, str)
        or not 1 <= len(version) <= 100
        or not isinstance(entries, list)
    ):
        raise ValueError("Invalid threat indicator snapshot")
    index = {}
    for entry in entries:
        kind, value = entry["type"], entry["value"]
        valid_hash = kind == "apk_sha256" and re.fullmatch("[0-9a-f]{64}", value)
        valid_host = (
            kind == "embedded_host"
            and re.fullmatch(r"[a-z0-9.-]{1,253}", value)
            and "." in value
        )
        if not (valid_hash or valid_host) or not re.fullmatch(
            r"https://[^\s]{1,499}", entry["source"]
        ):
            raise ValueError("Invalid indicator or source")
        if not 5 <= len(entry["context"]) <= 500 or (kind, value) in index:
            raise ValueError("Invalid or duplicate indicator context")
        index[kind, value] = {
            key: entry[key] for key in ("type", "value", "source", "context")
        }
    return {"version": version, "index": index}


def match_indicators(snapshot, checksum, hosts):
    if snapshot is None:
        return {
            "status": "unavailable",
            "matches": [],
            "reason": "No approved threat indicator snapshot is configured.",
        }
    keys = [
        ("apk_sha256", checksum),
        *(("embedded_host", host.lower()) for host in hosts),
    ]
    index = snapshot["index"]
    matches = [index[key] for key in keys if key in index]
    return {
        "status": "checked",
        "version": snapshot["version"],
        "matches": matches,
        "reason": "Exact matches against the configured snapshot.",
    }
