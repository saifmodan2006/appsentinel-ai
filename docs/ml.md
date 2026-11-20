# Malware model

ML inference is disabled by default. No validated model, APK malware corpus, dataset license, or trained performance figures are bundled. Scans run the full static rule and authenticity workflow with an explicit model availability outcome.

| Candidate | Evaluation |
| --- | --- |
| [CICMalDroid 2020](https://www.unb.ca/cic/datasets/maldroid-2020.html) | Research dataset includes both dynamic and static views. Citation terms apply. Feature compatibility and commercial rights must be reviewed before training a release model. |
| [Drebin](https://drebin.mlsec.org/) | Historically useful sparse Android features. Access conditions, aging labels, and current-distribution validity require review. |
| [AMD research](https://doi.org/10.1007/978-3-319-60876-1_12) | Historical family study. Bundle access and downstream rights are unverified in this project. |
| [LAMDA](https://github.com/IQSeC-Lab/LAMDA) | Temporal Drebin-style research benchmarks and concept drift. Source feature definitions and labels require a validated mapping and downstream use review before importing into Sentinel. |
| [KronoDroid](https://github.com/aleguma/kronodroid) | Temporal research candidate. Raw APK access is controlled and dynamic features require a compatible extraction path. |

The training script accepts an approved UTF-8 CSV with `sha256,label,group,first_seen` followed by the features exposed by `sentinel.model.FEATURES`. Labels are `malware` or `benign`. Dates are ISO 8601. Group IDs must represent package, family, lineage, and near-duplicate relationships before splitting. Export scanner features from completed JSON reports with `python -m ml.features report.json`. The exporter rejects incomplete DEX extraction. Input feature rows require matching extraction semantics and provenance.

```sh
python -m pip install -r requirements.txt -r requirements-ml.txt
python -m ml.train approved.csv --sha256 "$DATASET_SHA256" \
  --source "$DATASET_PROVENANCE" --validation-start 2024-01-01 \
  --test-start 2025-01-01 --output data/evidence/run-1 --version 1.0.0
```

Set temporal boundaries against the available dates. The pipeline checks CSV integrity and exact duplicate consistency, drops groups spanning intervals, and requires both classes in each partition. Missing feature values are rejected to preserve consistent training and inference coverage. It compares logistic regression, random forest, and histogram gradient boosting. Thresholds come from the validation fold. The untouched later fold yields confusion matrices, precision, recall, F1, FPR, FNR, ROC-AUC, average precision, Brier score, calibration bins and batch inference timing. Repeat evaluation on an independently sourced population before deployment.

The only deployable artifact is the interpretable baseline’s JSON coefficients. Review its evaluation and external validation first. The worker requires an independent artifact SHA-256 and checks the feature schema, dimension, threshold, and coefficient bounds. The report exposes log-odds contributions as experimental evidence. Rotate approved artifact digests through the operator’s release process, then re-scan with the new version. No executable model serialization is loaded.
