# AppTrust Sentinel

AppTrust Sentinel statically inspects Android APKs and produces private, evidence-based security reports. It decodes the binary manifest and DEX metadata, verifies signatures with Android apksigner, and compares verified signers with administrator-maintained publisher records. Permission and code findings inform the risk assessment. Each report explains its coverage.

## Run locally with Docker

Docker Desktop or Docker Engine with Compose v2 is required. No cloud service, GPU, or Java installation on the host is required for this path. Run these commands from the repository root.

**PowerShell 7**

```powershell
if (-not (Test-Path .env)) {
    $bytes = New-Object byte[] 24
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $dbPassword = [Convert]::ToHexString($bytes).ToLowerInvariant()
    Set-Content -LiteralPath .env -Value "POSTGRES_PASSWORD=$dbPassword" -Encoding ascii
}
docker compose up -d --build --wait
```

**Linux**

```sh
if [ ! -f .env ]; then
  (umask 077; printf 'POSTGRES_PASSWORD=%s\n' "$(openssl rand -hex 24)" > .env)
fi
docker compose up -d --build --wait
```

Open [the dashboard](http://127.0.0.1:8080), create a local account, and choose an APK. Check the scanner indicator in the sidebar. Completed scans can be compared and exported from the dashboard. The OpenAPI schema is available at [the local API endpoint](http://127.0.0.1:8080/api/v1/openapi.json).

Operational commands:

```sh
docker compose ps
docker compose logs --tail 80 api worker sandbox
docker compose exec api python -m sentinel.accounts create-admin operator@example.com
docker compose down
```

The operator command prompts for a password. Account recovery uses the same command with `reset-password` and invalidates existing sessions. Compose keeps relational data in a named volume. Run the publisher catalog without seed records until independent evidence is available.

## Python fallback

Use Python 3.12 in a virtual environment. Once dependencies are installed, run the API and the worker in separate terminals using the same settings and working directory.

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt -r requirements-scanner.txt
.venv\Scripts\python -m uvicorn sentinel.api:app --host 127.0.0.1 --port 8080
```

```powershell
$env:SENTINEL_JAVA = 'C:\path\to\java.exe'
$env:SENTINEL_APKSIGNER_JAR = 'C:\path\to\android-sdk\build-tools\35.0.0\lib\apksigner.jar'
.venv\Scripts\python -m sentinel.worker
```

On Linux, use `.venv/bin/python` and `export NAME=value`. The fallback uses SQLite and a subprocess under the local user account. Use it for authorized test fixtures. The stronger Compose sandbox uses a separate container with no network namespace connectivity. Configure Java and the SDK signer jar to enable cryptographic verification in the fallback.

If Docker reports a port conflict, set `SENTINEL_WEB_PORT` to a different local port in `.env`. If the scanner is unavailable, check `docker compose ps` and both worker and sandbox logs. Windows application control policies can block third-party native Python wheels. The Docker path runs Linux wheels inside its containers.

## Android companion

See [Android build and connection instructions](apps/android/README.md). The companion uses the Android document picker, asks before uploading, and displays the API’s stored statuses and reports.

## Project documentation

- [Architecture](docs/architecture.md) and [API](docs/api.md)
- [Security and privacy](docs/security.md) and [deployment](docs/deployment.md)
- [Technology and licensing decisions](docs/technology-decisions.md)
- [Dataset, training, and model lifecycle](docs/ml.md)
- [Testing and benchmarks](docs/testing.md)
- [Business assumptions](docs/business.md)
- [Web design and coding-agent references](docs/design.md)
- [Verified implementation status](docs/implementation-report.md)
