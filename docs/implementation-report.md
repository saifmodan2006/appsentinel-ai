# AppTrust Sentinel implementation report

Verified locally on 20 November 2026 on Windows 11 Pro with Docker Engine 29.9.2, Compose 5.6.1, a 12-logical-CPU host, about 16 GB of RAM, and CPU-only scanning. The repository workspace is on `main`, tracking `origin/main` at the supplied GitHub repository. Build and verification artifacts are local and excluded from Git.

## Working platform

| Area | Status |
| --- | --- |
| Web dashboard | Operates against actual persisted data. Includes account creation, upload progress, lifecycle states, private history and search, report comparison, exports, administrator catalog and operations views, settings, and a financial scenario calculator. |
| Static analysis | Parses binary Android manifests and DEX references, reports permissions and manifests, inventories native libraries and resources, and verifies signatures with Android apksigner. The Compose parser runs in a non-root container with a read-only filesystem and no network connectivity. |
| Authenticity | Checks whole approved signer sets, accepts explicitly recorded historic signers, and uses label and raster icon similarity as supporting evidence. Administrator writes and revocations have versioned provenance. The catalog starts empty. |
| API and storage | FastAPI serves versioned routes and OpenAPI. PostgreSQL stores protected reports and a bounded queue. SQLite is the development fallback. Applies ownership, RBAC, session expiry, password hashing, rate limits, upload limits, and file cleanup. |
| Reports | Downloads use stored scan evidence. JSON includes the recorded inventory and PDF presents a readable summary with detailed security findings. |
| Model | Training, holdout evaluation, and checksum-pinned inference are implemented. Production inference is disabled by default because there is no validated compatible labeled dataset or model artifact. There are no measured malware-classification metrics. |
| Android | Kotlin/Compose source, debug build, and lint checks. The APK was signature-verified and analyzed by the platform. Device and emulator interaction remain unverified. |
| Deployment | Local Compose stack includes the web gateway, API, PostgreSQL, dispatcher, and isolated parser. Remote deployment requires a dedicated host, DNS and TLS configuration, and a staging validation pass. |

## Local service endpoints

- Dashboard at [http://127.0.0.1:8080](http://127.0.0.1:8080)
- Readiness at [http://127.0.0.1:8080/api/v1/ready](http://127.0.0.1:8080/api/v1/ready)
- Schema at [http://127.0.0.1:8080/api/v1/openapi.json](http://127.0.0.1:8080/api/v1/openapi.json)

The Android artifact is `apps/android/app/build/outputs/apk/debug/app-debug.apk`. The sample PDF and its matching JSON are available under `output/`. They were generated from a scan of the debug companion build.

The `web`, `api`, `db`, `worker`, and `sandbox` services all reported healthy. The final gateway served JavaScript with the correct media type. The sandbox's only network interface was loopback. Its filesystem was read-only and its process UID was 12001.

## Verification results

| Check | Observed result |
| --- | --- |
| Python tests under Docker Linux | 17 passed, with one Starlette TestClient deprecation warning. The tests used SQLite and real signed APK fixtures. |
| Playwright through Compose and PostgreSQL | 2 tests passed in Chrome. The signed-APK workflow covers job completion, findings, PDF and JSON, history, mobile navigation, calculator, and signed-out access denial. The second test checks the welcome screen at 320 pixels. |
| Native Android checks | Gradle `assembleDebug` and `lintDebug` succeeded. Lint reported 0 errors and 3 warnings for dependency version updates and Android 12+ backup configuration. |
| Android transport and real APK scan | The Android bearer-token login and chunked upload contract completed against the local gateway. The 9,175,725-byte companion APK had a verified signature and four parsed DEX files. Its moderate assessment included the debug-mode finding. The sample PDF was rendered and reviewed across all three pages. |
| Ruff and JavaScript syntax | Passed. |

The scanner used Androguard 4.1.4 and Debian apksigner package 31.0.2-1. The APK and report SHA-256 match: `7bfe096986cf20735332ffaf32b29bbd4683c10a210f8be5c587de28415eb8c8`.

## Measured timings

| Measurement | Result |
| --- | ---: |
| Serial runs with an 8,476-byte signed fixture | 5 completed, 0 failed |
| Mean upload and queue admission | 18.3 ms |
| Mean worker analysis | 1.58 s |
| Mean upload through completed status | 2.46 s |
| Mean PDF request | 30.0 ms |
| Observed serial throughput including export | 24.07 scans/min |
| Sandbox peak cgroup memory across fixture and companion runs | 453.7 MiB |
| Companion APK worker time and total time through PDF export | 9.74 s and 10.58 s |

The sample is small and the throughput is single-client. Model inference latency is unavailable because no evaluated model is enabled.

## Dependency and image audits

`pip-audit` reported zero known findings across 94 installed packages in the Linux QA environment after updating Pillow and pip. `npm audit` reported zero findings. Trivy found OS advisories in the initial web base. Replacing the prebundled NGINX modules with the patched Alpine package yielded NGINX 1.30.7 and zero OS advisories in the final gateway image. Trivy recorded the following results for the current OS package sets.

| Image package set | Total | Critical | High | Critical or high with fixes listed |
| --- | ---: | ---: | ---: | ---: |
| Web gateway, Alpine 3.24.4 | 0 | 0 | 0 | 0 |
| API and dispatcher, Debian 12.15 | 367 | 2 | 99 | 0 |
| Scanner sandbox, Debian 12.15 | 577 | 4 | 129 | 0 |
| PostgreSQL, Debian 12.15 | 537 | 3 | 114 | 0 |

These counts are advisory matches from the scanner database snapshot. Their runtime reachability has not been assessed. The Debian findings and Android dependencies still need a production release review. Local raw results are under `.tools/image-audit/` and `.tools/python-audit-linux.json`.

## Remaining coverage and release work

- Android emulator or hardware is needed to exercise the Storage Access Framework, authentication screen, consent, and polling on a device. The SDK platform-tools component is unconfigured on this host.
- Authenticated source evidence is required to approve catalog entries and threat snapshots. Signature lineage extraction, full adaptive icon rendering, split APK aggregation, broad obfuscation analysis, and runtime malware behavior are outside the current static coverage.
- Production requires a reviewed dataset or continuation in rules-only mode, an external staging validation pass, a maintained OS baseline, a project distribution license decision, and a verified backup restore. Native-Windows Python startup is blocked on this host because Windows Application Control rejects the Pydantic core extension. Docker Linux and its SQLite test environment are operational.
- The workspace tracks the GitHub origin. Local source changes are available in the working tree. No remote application instance or CI run was used for this verification.

[Startup](../README.md) · [Reproduction commands](testing.md) · [Security model](security.md) · [Deployment](deployment.md)
