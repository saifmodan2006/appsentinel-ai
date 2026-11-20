"""Train and evaluate Sentinel models from approved, extracted static feature rows."""

import argparse
import csv
import hashlib
import json
import math
import re
import time
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

import numpy as np
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from sentinel.model import FEATURES, SCHEMA

SEED = 1729


def context_checksum(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_dataset(path):
    by_hash = {}
    duplicates = 0
    groups = defaultdict(list)
    with path.open(encoding="utf-8-sig", newline="") as stream:
        for raw in csv.DictReader(stream):
            sha = raw["sha256"].lower()
            label = {"benign": 0, "malware": 1, "0": 0, "1": 1}.get(
                raw["label"].strip().lower()
            )
            group = raw["group"].strip()
            first_seen = date.fromisoformat(raw["first_seen"])
            vector = tuple(int(raw[key]) for key in FEATURES)
            if (
                not re.fullmatch("[0-9a-f]{64}", sha)
                or label is None
                or not group
                or any(n < 0 or n > 50000 for n in vector)
                or any(
                    v > 1
                    for key, v in zip(FEATURES, vector, strict=True)
                    if key not in {"exported_components", "native_libraries"}
                )
            ):
                raise ValueError("Invalid hash, label, group, or feature value")
            sample = (sha, label, group, first_seen, vector)
            prior = by_hash.get(sha)
            if prior:
                if prior != sample:
                    raise ValueError("The dataset contains conflicting duplicate rows")
                duplicates += 1
                continue
            by_hash[sha] = sample
            groups[group].append(sample)
    return groups, duplicates


def split_groups(groups, validation_start, test_start):
    if test_start <= validation_start:
        raise ValueError("Test must begin after validation")
    folds = {"train": [], "validation": [], "test": []}
    omitted = 0
    for group in sorted(groups):
        samples = groups[group]
        names = {
            "train"
            if row[3] < validation_start
            else "validation"
            if row[3] < test_start
            else "test"
            for row in samples
        }
        if len(names) != 1:
            omitted += len(samples)
            continue
        folds[names.pop()].extend(samples)
    for name, rows in folds.items():
        if {row[1] for row in rows} != {0, 1}:
            raise ValueError(
                f"{name} requires both classes in disjoint groups and time intervals"
            )
        rows.sort(key=lambda row: (row[3], row[0]))
    return folds, omitted


def arrays(fold):
    return np.asarray([row[4] for row in fold], dtype=np.float64), np.asarray(
        [row[1] for row in fold]
    )


def threshold_for(actual, scores):
    candidates = np.linspace(0.05, 0.95, 19)
    return float(
        max(
            candidates,
            key=lambda threshold: (f1_score(actual, scores >= threshold), threshold),
        )
    )


def metrics(actual, scores, threshold):
    labels = scores >= threshold
    tn, fp, fn, tp = (
        int(val) for val in confusion_matrix(actual, labels, labels=[0, 1]).ravel()
    )
    bins = []
    for low in np.linspace(0, 0.9, 10):
        high = low + 0.1
        mask = (scores >= low) & ((scores <= 1.0) if high >= 1 else (scores < high))
        if mask.any():
            bins.append(
                {
                    "count": int(mask.sum()),
                    "mean_estimate": float(scores[mask].mean()),
                    "observed_rate": float(actual[mask].mean()),
                }
            )
    return {
        "threshold": threshold,
        "precision": precision_score(actual, labels, zero_division=0),
        "recall": recall_score(actual, labels),
        "f1": f1_score(actual, labels),
        "false_positive_rate": fp / (fp + tn),
        "false_negative_rate": fn / (fn + tp),
        "roc_auc": roc_auc_score(actual, scores),
        "average_precision": average_precision_score(actual, scores),
        "brier": brier_score_loss(actual, scores),
        "calibration_bins": bins,
        "confusion_matrix": [[tn, fp], [fn, tp]],
    }


def train(dataset, expected, source, validation_start, test_start, output, version):
    actual = context_checksum(dataset)
    if actual != expected.lower():
        raise ValueError("CSV SHA-256 does not match the supplied provenance checksum")
    groups, duplicates = read_dataset(dataset)
    folds, omitted = split_groups(groups, validation_start, test_start)
    x_train, y_train = arrays(folds["train"])
    x_validation, y_validation = arrays(folds["validation"])
    x_test, y_test = arrays(folds["test"])
    models = {
        "logistic_regression": LogisticRegression(max_iter=2000, random_state=SEED),
        "random_forest": RandomForestClassifier(
            n_estimators=200, random_state=SEED, n_jobs=1, min_samples_leaf=2
        ),
        "hist_gradient_boosting": HistGradientBoostingClassifier(
            random_state=SEED, max_iter=150
        ),
    }
    result = {
        "model_version": version,
        "feature_schema": SCHEMA,
        "sklearn_version": sklearn.__version__,
        "dataset": {
            "source": source,
            "sha256": actual,
            "dropped_exact_duplicates": duplicates,
            "omitted_rows_in_cross_period_groups": omitted,
            "validation_start": str(validation_start),
            "test_start": str(test_start),
        },
        "split": {},
        "models": {},
        "random_seed": SEED,
        "limitations": "Group quality and label correctness depend on the supplied provenance. The test fold is a temporal holdout from the supplied dataset.",
    }
    for name, rows in folds.items():
        counts = Counter(row[1] for row in rows)
        result["split"][name] = {
            "samples": len(rows),
            "malware": counts[1],
            "benign": counts[0],
            "groups": len({row[2] for row in rows}),
            "first_seen": str(rows[0][3]),
            "last_seen": str(rows[-1][3]),
        }
    for name, estimator in models.items():
        estimator.fit(x_train, y_train)
        validation_scores = estimator.predict_proba(x_validation)[:, 1]
        threshold = threshold_for(y_validation, validation_scores)
        start = time.perf_counter()
        test_scores = estimator.predict_proba(x_test)[:, 1]
        total_ms = (time.perf_counter() - start) * 1000
        result["models"][name] = {
            "validation": metrics(y_validation, validation_scores, threshold),
            "test": metrics(y_test, test_scores, threshold),
            "test_batch_ms_per_row": total_ms / len(x_test),
        }
    output.mkdir(parents=True, exist_ok=False)
    evaluation = output / "evaluation.json"
    evaluation.write_text(
        json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8"
    )
    logistic = models["logistic_regression"]
    artifact = {
        "schema": SCHEMA,
        "features": list(FEATURES),
        "version": version,
        "weights": logistic.coef_[0].tolist(),
        "intercept": float(logistic.intercept_[0]),
        "threshold": result["models"]["logistic_regression"]["test"]["threshold"],
        "evaluation_sha256": context_checksum(evaluation),
    }
    if not all(math.isfinite(x) for x in [*artifact["weights"], artifact["intercept"]]):
        raise ValueError("Model contains nonfinite coefficients")
    model = output / "logistic.json"
    model.write_text(
        json.dumps(artifact, indent=2, allow_nan=False) + "\n", encoding="utf-8"
    )
    print("Evaluation:", evaluation)
    print("Logistic model SHA-256:", context_checksum(model))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument(
        "--source", required=True, help="Dataset, access terms, and label provenance"
    )
    parser.add_argument("--validation-start", type=date.fromisoformat, required=True)
    parser.add_argument("--test-start", type=date.fromisoformat, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    train(
        args.dataset,
        args.sha256,
        args.source,
        args.validation_start,
        args.test_start,
        args.output,
        args.version,
    )


if __name__ == "__main__":
    main()
