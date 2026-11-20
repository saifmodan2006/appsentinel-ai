# Testing and benchmarks

## Reproduce the suite

```sh
docker build --target qa -f infra/Dockerfile -t apptrust-sentinel-qa .
docker run --rm --network none apptrust-sentinel-qa
docker run --rm apptrust-sentinel-qa python -m ruff check --no-cache sentinel ml scripts tests
docker run --rm apptrust-sentinel-qa python -m pip_audit --cache-dir /tmp/pip-audit
```

Generate and copy harmless APK fixtures from the QA image, then start the local Compose stack.

```powershell
New-Item -ItemType Directory -Force data/fixtures | Out-Null
$fixtureContainer = docker create apptrust-sentinel-qa
try { docker cp "${fixtureContainer}:/fixture/output/." data/fixtures }
finally { docker rm $fixtureContainer | Out-Null }
docker compose up -d --build --wait
npm ci
npx playwright install chromium
npm run test:browser
```

The same commands work on Linux with `mkdir -p` and shell syntax for creating, copying from, and removing the temporary fixture container. Existing Chrome can be selected with `SENTINEL_CHROME`. The browser test uses the origin in `SENTINEL_HTTP` or port 8080 by default. Tests create isolated accounts. Browser tests on a shared or reused workspace can reach registration limits. Run them against a dedicated test stack or allow the configured rate window to elapse.

The fixture builder compiles a binary manifest with Android AAPT and signs the application with two independently generated disposable keys. It also retains the unsigned fixture for verification-failure checks. APEX, AAB, APK sets, and live malware samples are outside the fixture suite.

The Python tests cover owner-scoped sessions and exports, empty and oversized uploads, archive validation and limits, duplicate intake, cancellation, worker failures and time limits, binary manifest and signer extraction, reference match and mismatch, catalog revocation, rules and risk uncertainty, PDF and JSON, icon hashing, threat records, and temporal model pipeline integrity. Numerical training fixtures verify the evaluation implementation. They are unrelated to real Android applications and provide no deployed performance evidence.

The browser tests cover keyboard navigation, empty states, a real signed upload through the file chooser, worker completion, displayed findings, PDF and JSON, history search, mobile menu focus, the business calculator, and sign-out access control. A 320-pixel viewport check verifies that sign-in appears before the capability list and the layout stays within the viewport.

## Benchmark

Use a running local Compose stack and the requirements-dev environment for the HTTP client.

```sh
python scripts/benchmark.py data/fixtures/original.apk --count 5
docker compose exec -T sandbox cat /sys/fs/cgroup/memory.peak
```

The benchmark cycles through serial authenticated upload, status polling, PDF download, and report deletion. Container memory peak covers the current container lifetime. Tests use a small benign fixture to demonstrate reproducible local operation. Results depend on APK complexity, host contention, and polling intervals. See the [implementation report](implementation-report.md) for the measured results.
