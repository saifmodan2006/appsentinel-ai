import hashlib
import json
import math
import os
from pathlib import Path

from sentinel.rules import SENSITIVE

FEATURES = tuple(f"perm_{name.lower()}" for name in sorted(SENSITIVE)) + (
    "exported_components",
    "native_libraries",
    "debuggable",
    "dynamic_loader",
    "reflection",
    "webview_bridge",
)
SCHEMA = "static-v1"


def features(parsed):
    meta = parsed["metadata"]
    permissions = set(meta["permissions"])
    result = {
        f"perm_{name.lower()}": int(f"android.permission.{name}" in permissions)
        for name in SENSITIVE
    }
    result.update(
        exported_components=sum(
            item["exported"] is True for item in meta["components"]
        ),
        native_libraries=len(meta["native_libraries"]),
        debuggable=int(meta["attributes"].get("debuggable") == "true"),
    )
    result.update(
        {
            marker: int(marker in parsed["code"]["references"])
            for marker in ("dynamic_loader", "reflection", "webview_bridge")
        }
    )
    return result


def load_model():
    path = os.getenv("SENTINEL_MODEL")
    expected = os.getenv("SENTINEL_MODEL_SHA256")
    if not path or not expected:
        return None
    with Path(path).open("rb") as stream:
        content = stream.read(128 * 1024 + 1)
    if (
        len(content) > 128 * 1024
        or hashlib.sha256(content).hexdigest() != expected.lower()
    ):
        raise ValueError("Model artifact integrity check failed")
    model = json.loads(content)
    if model["schema"] != SCHEMA or model["features"] != list(FEATURES):
        raise ValueError("Model feature schema mismatch")
    if not isinstance(model["version"], str) or len(model["weights"]) != len(FEATURES):
        raise ValueError("Model dimensions are invalid")
    if not all(
        math.isfinite(x) and abs(x) <= 1000
        for x in [*model["weights"], model["intercept"]]
    ):
        raise ValueError("Model coefficients are invalid")
    if not 0 < model["threshold"] < 1 or not model.get("evaluation_sha256"):
        raise ValueError("Model evaluation metadata is missing or invalid")
    return model


def predict(parsed, model):
    if not model:
        return {
            "status": "unavailable",
            "reason": "No evaluated, operator-approved model is configured.",
        }
    if any(
        item["field"] == "DEX" or item["field"].endswith(".dex")
        for item in parsed["missing"]
    ):
        return {
            "status": "unavailable",
            "reason": "The scan lacks complete DEX features.",
        }
    vector = features(parsed)
    contribution = {
        name: vector[name] * weight
        for name, weight in zip(FEATURES, model["weights"], strict=True)
    }
    logit = max(-700, min(700, model["intercept"] + sum(contribution.values())))
    probability = 1 / (1 + math.exp(-logit))
    drivers = sorted(
        contribution.items(), key=lambda entry: abs(entry[1]), reverse=True
    )
    return {
        "status": "experimental",
        "version": model["version"],
        "estimate": round(probability, 6),
        "threshold": model["threshold"],
        "above_threshold": probability >= model["threshold"],
        "log_odds_drivers": [
            {"feature": key, "contribution": round(value, 6)}
            for key, value in drivers[:6]
            if value
        ],
        "reason": "An experimental estimate from the enabled model. Calibration may drift across populations.",
    }
