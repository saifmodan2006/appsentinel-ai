import asyncio
import hashlib
import re
import tempfile
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import unquote
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from starlette.concurrency import run_in_threadpool

from sentinel.auth import (
    create_session,
    current_user,
    digest,
    find_user,
    password_hash,
    rate_limit,
    require_admin,
    session_token,
)
from sentinel.config import (
    ALLOW_REGISTER,
    MAX_UPLOAD,
    QUEUE_LIMIT,
    RETENTION,
    SECURE_COOKIE,
    SESSION_TTL,
    UPLOADS,
)
from sentinel.contracts import Credentials, Package, TrustedRecord
from sentinel.db import (
    audit,
    catalog,
    engine,
    migrate,
    queue_lock,
    scans,
    sessions,
    state,
    users,
)
from sentinel.exports import render_pdf
from sentinel.rules import VERSION

V1 = "/api/v1"
BROWSER = "X-Sentinel-Request"
ACTIVE = ("queued", "running")
upload_slots = asyncio.Semaphore(4)


@asynccontextmanager
async def lifespan(_):
    migrate()
    yield


app = FastAPI(
    title="AppTrust Sentinel",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url="/api/v1/openapi.json",
)


@app.exception_handler(RequestValidationError)
def validation_error(_, exc):
    return JSONResponse(
        {
            "detail": [
                {"loc": item["loc"], "type": item["type"]} for item in exc.errors()
            ]
        },
        422,
    )


@app.middleware("http")
async def security(request, call_next):
    if request.method not in {"GET", "HEAD", "OPTIONS"} and request.url.path.startswith(
        V1
    ):
        if (
            request.headers.get(BROWSER) != "1"
            or request.headers.get("sec-fetch-site") == "cross-site"
        ):
            return JSONResponse({"detail": "Request verification failed."}, 403)
    response = await call_next(request)
    if request.url.path.startswith(V1):
        response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if SECURE_COOKIE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


def ip(request):
    return request.client.host if request.client else "local"


@app.get(f"{V1}/health")
def health():
    return {"status": "ok"}


@app.get(f"{V1}/ready")
def ready():
    with engine.connect() as conn:
        heartbeat = conn.scalar(
            select(state.c.value).where(state.c.key == "worker_heartbeat")
        )
    online = bool(heartbeat and time.time() - heartbeat < 20)
    if not online:
        return JSONResponse({"status": "degraded", "worker": "offline"}, 503)
    return {"status": "ready", "worker": "online"}


@app.post(f"{V1}/auth/register", status_code=201)
def register(body: Credentials, request: Request):
    if not ALLOW_REGISTER:
        raise HTTPException(403, "Registration is closed.")
    rate_limit(f"register:{ip(request)}", 8, 3600)
    try:
        with engine.begin() as conn:
            conn.execute(
                users.insert().values(
                    id=str(uuid4()),
                    email=body.email,
                    password=password_hash(body.password),
                    role="user",
                )
            )
    except IntegrityError as exc:
        raise HTTPException(409, "This account cannot be registered.") from exc
    return {"status": "created"}


@app.post(f"{V1}/auth/login")
def login(
    body: Credentials,
    request: Request,
    response: Response,
    client: str = Query("web", pattern="^(web|android)$"),
):
    email = body.email
    rate_limit(f"login-ip:{ip(request)}", 20, 300)
    rate_limit(f"login-account:{email}", 10, 300)
    user = find_user(email, body.password)
    if not user:
        raise HTTPException(401, "Email or password is incorrect.")
    token = create_session(user["id"], session_token(request))
    public = {"email": user["email"], "role": user["role"]}
    if client == "android":
        return {**public, "token": token}
    response.set_cookie(
        "sentinel_session",
        token,
        max_age=SESSION_TTL,
        httponly=True,
        secure=SECURE_COOKIE,
        samesite="strict",
        path="/",
    )
    return {**public, "retention_days": RETENTION}


@app.post(f"{V1}/auth/logout", status_code=204)
def logout(request: Request, response: Response):
    with engine.begin() as conn:
        conn.execute(
            delete(sessions).where(sessions.c.digest == digest(session_token(request)))
        )
    response.delete_cookie(
        "sentinel_session",
        path="/",
        secure=SECURE_COOKIE,
        httponly=True,
        samesite="strict",
    )


@app.get(f"{V1}/auth/me")
def profile(user=Depends(current_user)):
    return {**user, "retention_days": RETENTION}


SCAN_FIELDS = (
    "id",
    "sha256",
    "filename",
    "bytes",
    "status",
    "created",
    "started",
    "finished",
    "error",
)
RISK = scans.c.report["assessment"]["level"].as_string()
PACKAGE = scans.c.report["metadata"]["package"].as_string()
SUMMARY = (
    *[scans.c[field] for field in SCAN_FIELDS],
    RISK.label("risk"),
    PACKAGE.label("package"),
)


def public_scan(row, include_report=False):
    result = {field: row[field] for field in SCAN_FIELDS}
    report = row.get("report")
    result["risk"] = report["assessment"]["level"] if report else row.get("risk")
    result["package"] = report["metadata"]["package"] if report else row.get("package")
    if include_report:
        result["report"] = report
    return result


def owned_scan(conn, owner, scan_id):
    row = (
        conn.execute(
            select(scans).where(scans.c.id == str(scan_id), scans.c.owner == owner)
        )
        .mappings()
        .first()
    )
    if row is None:
        raise HTTPException(404, "Scan not found.")
    return row


def enqueue(owner, filename, checksum, size, staged):
    scan_id = str(uuid4())
    path = UPLOADS / f"{scan_id}.apk"
    try:
        with engine.begin() as conn:
            queue_lock(conn)
            duplicate = (
                conn.execute(
                    select(scans)
                    .where(
                        scans.c.owner == owner,
                        scans.c.sha256 == checksum,
                        scans.c.status.in_(ACTIVE),
                    )
                    .order_by(scans.c.created.desc())
                )
                .mappings()
                .first()
            )
            if duplicate:
                return {**public_scan(duplicate), "duplicate": True}
            pending = conn.scalar(
                select(func.count())
                .select_from(scans)
                .where(scans.c.status.in_(ACTIVE))
            )
            if pending >= QUEUE_LIMIT:
                raise HTTPException(
                    429, "Scan queue is full.", headers={"Retry-After": "15"}
                )
            fields = dict(
                id=scan_id,
                owner=owner,
                filename=filename,
                sha256=checksum,
                bytes=size,
                status="queued",
                created=int(time.time()),
            )
            staged.replace(path)
            conn.execute(scans.insert().values(**fields))
        return {
            **public_scan(
                {
                    **fields,
                    "started": None,
                    "finished": None,
                    "error": None,
                    "report": None,
                }
            ),
            "duplicate": False,
        }
    except Exception:
        path.unlink(missing_ok=True)
        raise


@app.post(
    f"{V1}/scans",
    status_code=202,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/vnd.android.package-archive": {
                    "schema": {"type": "string", "format": "binary"}
                }
            },
        }
    },
)
async def upload(request: Request, user=Depends(current_user)):
    await run_in_threadpool(rate_limit, f"upload:{user['id']}", 12, 3600)
    if upload_slots.locked():
        raise HTTPException(
            429, "Upload capacity is full.", headers={"Retry-After": "10"}
        )
    async with upload_slots:
        try:
            async with asyncio.timeout(180):
                return await ingest(request, user["id"])
        except TimeoutError as exc:
            raise HTTPException(408, "Upload time limit exceeded.") from exc


async def ingest(request, owner):
    if request.headers.get("content-type", "").split(";")[0] not in {
        "application/vnd.android.package-archive",
        "application/octet-stream",
    }:
        raise HTTPException(415, "Send a single APK as the request body.")
    raw_name = unquote(request.headers.get("x-apk-filename", "application.apk"))
    filename = re.sub(r"[^\w .()-]", "_", raw_name.replace("\\", "/").split("/")[-1])[
        -180:
    ]
    if not filename.lower().endswith(".apk"):
        raise HTTPException(415, "Select a file ending in .apk.")
    length = request.headers.get("content-length")
    if length and (not length.isascii() or not length.isdecimal() or len(length) > 20):
        raise HTTPException(400, "Invalid Content-Length.")
    if length and int(length) > MAX_UPLOAD:
        raise HTTPException(413, "APK exceeds the configured upload limit.")
    checksum = hashlib.sha256()
    size = 0
    signature = bytearray()
    with tempfile.NamedTemporaryFile(
        dir=UPLOADS, suffix=".partial", delete=False
    ) as stream:
        staged = Path(stream.name)
        try:
            async for chunk in request.stream():
                size += len(chunk)
                if size > MAX_UPLOAD:
                    raise HTTPException(413, "APK exceeds the configured upload limit.")
                if len(signature) < 4:
                    signature.extend(chunk[: 4 - len(signature)])
                    if len(signature) == 4 and signature != b"PK\x03\x04":
                        raise HTTPException(422, "APK must be a ZIP archive.")
                checksum.update(chunk)
                await run_in_threadpool(stream.write, chunk)
            if len(signature) != 4:
                raise HTTPException(422, "Empty or truncated APK.")
            await run_in_threadpool(stream.close)
            return await run_in_threadpool(
                enqueue, owner, filename, checksum.hexdigest(), size, staged
            )
        finally:
            stream.close()
            staged.unlink(missing_ok=True)


@app.get(f"{V1}/scans")
def history(
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100000),
    q: str = Query("", max_length=180),
    status: str = Query("", pattern="^(|queued|running|completed|failed|cancelled)$"),
    sort: str = Query("newest", pattern="^(newest|oldest)$"),
    user=Depends(current_user),
):
    scope = scans.c.owner == user["id"]
    if status:
        scope &= scans.c.status == status
    if q:
        scope &= (
            scans.c.filename.icontains(q, autoescape=True)
            | scans.c.sha256.icontains(q, autoescape=True)
            | PACKAGE.icontains(q, autoescape=True)
        )
    ordering = scans.c.created.desc() if sort == "newest" else scans.c.created.asc()
    with engine.connect() as conn:
        values = (
            conn.execute(
                select(*SUMMARY)
                .where(scope)
                .order_by(ordering, scans.c.id)
                .limit(limit)
                .offset(offset)
            )
            .mappings()
            .all()
        )
        counts = conn.execute(
            select(scans.c.status, func.count()).where(scope).group_by(scans.c.status)
        ).all()
    return {
        "items": [public_scan(row) for row in values],
        "counts": dict(counts),
        "total": sum(n for _, n in counts),
    }


@app.get(f"{V1}/dashboard")
def overview(user=Depends(current_user)):
    scope = scans.c.owner == user["id"]
    with engine.connect() as conn:
        counts = conn.execute(
            select(scans.c.status, func.count()).where(scope).group_by(scans.c.status)
        ).all()
        risks = conn.execute(
            select(RISK, func.count())
            .where(scope, scans.c.status == "completed")
            .group_by(RISK)
        ).all()
        recent = (
            conn.execute(
                select(*SUMMARY)
                .where(scope)
                .order_by(scans.c.created.desc(), scans.c.id)
                .limit(8)
            )
            .mappings()
            .all()
        )
        recent_reports = conn.execute(
            select(scans.c.id, scans.c.report)
            .where(scope, scans.c.status == "completed")
            .order_by(scans.c.finished.desc(), scans.c.id)
            .limit(8)
        ).all()
    findings = [
        {"id": scan_id, "title": f["title"], "severity": f["severity"]}
        for scan_id, report in recent_reports
        for f in report["findings"]
    ][:8]
    return {
        "counts": dict(counts),
        "risks": dict(risks),
        "total": sum(n for _, n in counts),
        "items": [public_scan(row) for row in recent],
        "findings": findings,
    }


@app.get(f"{V1}/scans/compare")
def compare(left: UUID, right: UUID, user=Depends(current_user)):
    with engine.connect() as conn:
        before = owned_scan(conn, user["id"], left)["report"]
        after = owned_scan(conn, user["id"], right)["report"]
    if not before or not after:
        raise HTTPException(409, "Both scans must have completed reports.")
    old = set(before["metadata"]["permissions"])
    new = set(after["metadata"]["permissions"])
    return {
        "identical_hash": before["sha256"] == after["sha256"],
        "same_package": before["metadata"]["package"] == after["metadata"]["package"],
        "permissions_added": sorted(new - old),
        "permissions_removed": sorted(old - new),
        "before": before,
        "after": after,
    }


@app.get(f"{V1}/scans/{{scan_id}}")
def scan_status(scan_id: UUID, user=Depends(current_user)):
    with engine.connect() as conn:
        return public_scan(owned_scan(conn, user["id"], scan_id), True)


@app.post(f"{V1}/scans/{{scan_id}}/cancel")
def cancel(scan_id: UUID, user=Depends(current_user)):
    with engine.begin() as conn:
        queue_lock(conn)
        row = owned_scan(conn, user["id"], scan_id)
        if row["status"] != "queued":
            raise HTTPException(409, "Only queued scans can be cancelled.")
        conn.execute(
            update(scans)
            .where(scans.c.id == str(scan_id))
            .values(status="cancelled", finished=int(time.time()))
        )
    return {"status": "cancelled"}


@app.delete(f"{V1}/scans/{{scan_id}}", status_code=204)
def remove_scan(scan_id: UUID, user=Depends(current_user)):
    with engine.begin() as conn:
        queue_lock(conn)
        row = owned_scan(conn, user["id"], scan_id)
        if row["status"] == "running":
            raise HTTPException(409, "Wait for the running scan to finish.")
        conn.execute(delete(scans).where(scans.c.id == str(scan_id)))
    return Response(status_code=204)


@app.get(f"{V1}/scans/{{scan_id}}/report.{{extension}}")
def export_report(scan_id: UUID, extension: str, user=Depends(current_user)):
    if extension not in {"json", "pdf"}:
        raise HTTPException(404, "Report format unavailable.")
    with engine.connect() as conn:
        report = owned_scan(conn, user["id"], scan_id)["report"]
    if report is None:
        raise HTTPException(409, "No report is available for this scan.")
    headers = {
        "Content-Disposition": f'attachment; filename="sentinel-{scan_id}.{extension}"'
    }
    if extension == "pdf":
        rate_limit(f"pdf:{user['id']}", 30, 60)
        return Response(
            render_pdf(report), media_type="application/pdf", headers=headers
        )
    return JSONResponse(report, headers=headers)


@app.get(f"{V1}/catalog")
def read_catalog(offset: int = Query(0, ge=0), user=Depends(current_user)):
    with engine.connect() as conn:
        rows = conn.scalars(
            select(catalog.c.record)
            .order_by(catalog.c.package)
            .limit(100)
            .offset(offset)
        ).all()
    return {
        "items": [
            row for row in rows if row["status"] == "active" or user["role"] == "admin"
        ],
        "next": offset + 100 if len(rows) == 100 else None,
    }


@app.put(f"{V1}/catalog/{{package}}")
def write_catalog(package: Package, body: TrustedRecord, user=Depends(current_user)):
    require_admin(user)
    if package != body.package:
        raise HTTPException(422, "Package in URL and record must match.")
    data = body.model_dump(mode="json")
    with engine.begin() as conn:
        queue_lock(conn)
        previous = conn.scalar(
            select(catalog.c.record).where(catalog.c.package == package)
        )
        data["reference_id"] = previous["reference_id"] if previous else str(uuid4())
        data["revision"] = previous["revision"] + 1 if previous else 1
        if previous:
            conn.execute(
                update(catalog).where(catalog.c.package == package).values(record=data)
            )
        else:
            conn.execute(catalog.insert().values(package=package, record=data))
        conn.execute(
            audit.insert().values(
                id=str(uuid4()),
                actor=user["id"],
                created=int(time.time()),
                record={"event": "catalog_update", "before": previous, "after": data},
            )
        )
    return data


@app.get(f"{V1}/operations")
def operations(user=Depends(current_user)):
    require_admin(user)
    with engine.connect() as conn:
        counts = conn.execute(
            select(scans.c.status, func.count()).group_by(scans.c.status)
        ).all()
        events = (
            conn.execute(select(audit).order_by(audit.c.created.desc()).limit(25))
            .mappings()
            .all()
        )
        installed = conn.scalar(
            select(state.c.value).where(state.c.key == "model_enabled")
        )
    return {
        "counts": dict(counts),
        "worker": "online" if isinstance(ready(), dict) else "offline",
        "rule_version": VERSION,
        "model": "Experimental model enabled" if installed else "Unavailable",
        "audit": [dict(event) for event in events],
    }


app.mount(
    "/",
    StaticFiles(
        directory=Path(__file__).resolve().parents[1] / "apps" / "web", html=True
    ),
    name="web",
)
