import hashlib
import json
from datetime import date

import pytest

from ml.train import split_groups, threshold_for, train
from sentinel import model


def test_model_artifact_rejects_checksum_mismatch(tmp_path, monkeypatch):
    path = tmp_path / "model.json"
    path.write_text("{}")
    monkeypatch.setenv("SENTINEL_MODEL", str(path))
    monkeypatch.setenv("SENTINEL_MODEL_SHA256", "0" * 64)
    with pytest.raises(ValueError, match="integrity"):
        model.load_model()


def test_features_and_predict(monkeypatch, tmp_path):
    parsed = {
        "metadata": {
            "permissions": ["android.permission.CAMERA"],
            "components": [{"exported": True}],
            "native_libraries": [],
            "attributes": {},
        },
        "code": {"references": ["reflection"]},
        "missing": [],
    }
    features = model.features(parsed)
    assert set(features) == set(model.FEATURES)
    assert (
        features["perm_camera"]
        == features["reflection"]
        == features["exported_components"]
        == 1
    )
    weights = [1.0 if key == "perm_camera" else 0.0 for key in model.FEATURES]
    data = {
        "schema": model.SCHEMA,
        "features": list(model.FEATURES),
        "version": "test",
        "weights": weights,
        "intercept": 0,
        "threshold": 0.5,
        "evaluation_sha256": "0" * 64,
    }
    path = tmp_path / "test-model.json"
    path.write_text(json.dumps(data))
    monkeypatch.setenv("SENTINEL_MODEL", str(path))
    monkeypatch.setenv(
        "SENTINEL_MODEL_SHA256", hashlib.sha256(path.read_bytes()).hexdigest()
    )
    result = model.predict(parsed, model.load_model())
    assert result["status"] == "experimental" and result["above_threshold"]
    assert result["log_odds_drivers"] == [
        {"feature": "perm_camera", "contribution": 1.0}
    ]
    parsed["missing"] = [{"field": "classes.dex"}]
    assert model.predict(parsed, data)["status"] == "unavailable"


def test_temporal_groups_do_not_leak():
    train_date, val_date, test_date = (date(y, 1, 1) for y in (2023, 2024, 2025))
    rows = {"old": [], "valid": [], "new": [], "crossing": []}
    for idx, (name, observed) in enumerate(
        zip(("old", "valid", "new"), (train_date, val_date, test_date))
    ):
        rows[name] = [
            (str(idx * 2 + label), label, name, observed, ()) for label in (0, 1)
        ]
    rows["crossing"] = [
        ("6", 1, "crossing", train_date, ()),
        ("7", 1, "crossing", test_date, ()),
    ]
    folds, omitted = split_groups(rows, val_date, test_date)
    assert omitted == 2
    assert [{row[2] for row in fold} for fold in folds.values()] == [
        {"old"},
        {"valid"},
        {"new"},
    ]
    assert threshold_for([0, 1], __import__("numpy").array([0.1, 0.8])) <= 0.8


def test_training_pipeline_reports_reproducible_results(tmp_path, monkeypatch):
    import csv
    from threadpoolctl import threadpool_limits

    dataset = tmp_path / "pipeline-contract.csv"
    with dataset.open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["sha256", "label", "group", "first_seen", *model.FEATURES])
        # Tiny numerical contract fixture. These rows do not represent apps or model evidence.
        for index in range(18):
            writer.writerow(
                [
                    f"{index:064x}",
                    index % 2,
                    f"group-{index}",
                    f"{2023 + index // 6}-01-01",
                    *([index % 2] * len(model.FEATURES)),
                ]
            )
    digest = hashlib.sha256(dataset.read_bytes()).hexdigest()
    with threadpool_limits(1):
        for folder in ["one", "two"]:
            train(
                dataset,
                digest,
                "unit-test numerical fixture",
                date(2024, 1, 1),
                date(2025, 1, 1),
                tmp_path / folder,
                "unit-test",
            )
    evaluations = [
        json.loads((tmp_path / folder / "evaluation.json").read_text())
        for folder in ["one", "two"]
    ]
    for evaluation in evaluations:
        assert evaluation["split"]["test"]["samples"] == 6
        for metrics in evaluation["models"].values():
            assert metrics.pop("test_batch_ms_per_row") >= 0
    assert evaluations[0] == evaluations[1]
    model_path = tmp_path / "one" / "logistic.json"
    monkeypatch.setenv("SENTINEL_MODEL", str(model_path))
    monkeypatch.setenv(
        "SENTINEL_MODEL_SHA256", hashlib.sha256(model_path.read_bytes()).hexdigest()
    )
    assert model.load_model()["version"] == "unit-test"
