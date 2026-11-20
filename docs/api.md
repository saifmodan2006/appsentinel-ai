# HTTP API

The API is under `/api/v1` and the generated OpenAPI schema is at `/api/v1/openapi.json`. Use the same origin as the dashboard. Supply `X-Sentinel-Request: 1` on state-changing requests. Web sessions use a same-site HTTP-only cookie. Native login with `?client=android` returns a short-lived bearer token. Neither variant requires a cookie or token on the registration endpoint.

| Method and route | Behavior |
| --- | --- |
| GET /health and /ready | API liveness and scanner readiness |
| POST /auth/register and /auth/login | Register or sign in using email and a password of at least 12 characters |
| POST /auth/logout | Revoke the current session |
| GET /auth/me | Current email, role, and retention interval |
| POST /scans | Raw APK body, optional percent-encoded `X-APK-Filename`, returns 202 with scan ID |
| GET /scans | Owner history, with `q`, `status`, `offset`, `limit`, and `sort` |
| GET /dashboard | Owner totals, risk distribution, and recent observations |
| GET /scans/{id} | Queued, running, completed, cancelled, or failed job and its report |
| POST /scans/{id}/cancel | Cancel queued work |
| DELETE /scans/{id} | Remove a scan and schedule any remaining blob for cleanup |
| GET /scans/compare?left={id}&right={id} | Compare two completed, owner-scoped reports |
| GET /scans/{id}/report.pdf or /report.json | Download the saved scan snapshot |
| GET /catalog | List reference records, with offset-based pagination |
| PUT /catalog/{package} | Create, revise, or revoke a record as administrator |
| GET /operations | Administrator-only worker health, job totals, and recent audit events |

For a PowerShell upload using an authenticated web session:

```powershell
$root = 'http://127.0.0.1:8080/api/v1'
$headers = @{ 'X-Sentinel-Request' = '1' }
$credentials = Get-Credential -Message 'Sentinel email and password'
$body = @{ email=$credentials.UserName; password=$credentials.GetNetworkCredential().Password } | ConvertTo-Json
Invoke-RestMethod "$root/auth/login" -Method Post -Headers $headers -ContentType 'application/json' -Body $body -SessionVariable sentinelSession
$headers['X-APK-Filename'] = 'sample.apk'
$scan = Invoke-RestMethod "$root/scans" -Method Post -Headers $headers -WebSession $sentinelSession -ContentType 'application/vnd.android.package-archive' -InFile './sample.apk'
Invoke-RestMethod "$root/scans/$($scan.id)" -WebSession $sentinelSession
Remove-Variable body,credentials
```

Apply 429 backoff and respect `Retry-After`. A 202 upload confirms intake only. Check the saved job for archive, manifest, and parser errors. Private IDs return 404 for sessions that do not own the scan. Expected client errors include 401 for missing or expired sessions, 403 for role or request-header denial, 409 for invalid lifecycle transitions, 413 for oversized input, 415 for media-type or extension failures, and 422 for validation errors.
