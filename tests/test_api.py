import hashlib
import os
from uuid import uuid4

from sqlalchemy import select, update

from sentinel.config import MAX_UPLOAD, UPLOADS
from sentinel.db import engine, scans, users
from sentinel.worker import run_one, sweep

HEADERS = {"X-Sentinel-Request": "1"}
APK_HEADERS = {
    **HEADERS,
    "Content-Type": "application/vnd.android.package-archive",
    "X-APK-Filename": "harmless.apk",
}


def account(client, role="user", android=False):
    email = f"{uuid4().hex}@example.test"
    credentials = {"email": email, "password": f"local-test-{uuid4()}"}
    assert (
        client.post(
            "/api/v1/auth/register", headers=HEADERS, json=credentials
        ).status_code
        == 201
    )
    if role == "admin":
        with engine.begin() as conn:
            conn.execute(update(users).where(users.c.email == email).values(role=role))
    query = "?client=android" if android else ""
    result = client.post(
        "/api/v1/auth/login" + query, headers=HEADERS, json=credentials
    )
    assert result.status_code == 200, result.text
    return result


def upload(client, data):
    response = client.post("/api/v1/scans", headers=APK_HEADERS, content=data)
    assert response.status_code == 202, response.text
    return response.json()


def test_auth_and_validation(client):
    assert client.get("/api/v1/scans").status_code == 401
    credentials = {"email": "owner@example.test", "password": "secret"}
    denied = client.post("/api/v1/auth/login", json=credentials)
    assert denied.status_code == 403
    invalid = client.post("/api/v1/auth/login", headers=HEADERS, json=credentials)
    assert invalid.status_code == 422 and "secret" not in invalid.text
    android = account(client, android=True).json()
    assert "sentinel_session" not in client.cookies
    bearer = {"Authorization": f"Bearer {android['token']}"}
    assert client.get("/api/v1/auth/me", headers=bearer).status_code == 200
    assert (
        client.post("/api/v1/auth/logout", headers={**bearer, **HEADERS}).status_code
        == 204
    )
    assert client.get("/api/v1/auth/me", headers=bearer).status_code == 401


def test_queue_duplicate_is_owner_scoped_and_cancelled(client):
    account(client)
    data = b"PK\x03\x04test" + os.urandom(20)
    first = upload(client, data)
    assert first["sha256"] == hashlib.sha256(data).hexdigest()
    assert not first["duplicate"]
    duplicate = upload(client, data)
    assert duplicate["duplicate"] and duplicate["id"] == first["id"]
    path = "/api/v1/scans/" + first["id"]
    assert client.post(path + "/cancel", headers=HEADERS).status_code == 200
    assert client.get(path).json()["status"] == "cancelled"
    assert client.post(path + "/cancel", headers=HEADERS).status_code == 409
    sweep()
    assert not (UPLOADS / (first["id"] + ".apk")).exists()
    assert client.delete(path, headers=HEADERS).status_code == 204
    assert client.get(path).status_code == 404


def test_upload_rejects_invalid_type_and_size(client):
    account(client)
    assert (
        client.post("/api/v1/scans", headers=HEADERS, content=b"bad").status_code == 415
    )
    assert (
        client.post("/api/v1/scans", headers=APK_HEADERS, content=b"bad").status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/scans",
            headers=APK_HEADERS,
            content=b"PK\x03\x04" + b"a" * MAX_UPLOAD,
        ).status_code
        == 413
    )


def test_malformed_zip_fails_in_worker(client):
    account(client)
    job = upload(client, b"PK\x03\x04truncated")
    assert run_one()
    failed = client.get("/api/v1/scans/" + job["id"]).json()
    assert failed["status"] == "failed"
    assert "Malformed" in failed["error"]
    assert failed["report"] is None


def test_complete_fixture_workflow(client, signed_apks):
    account(client, role="admin")
    first = upload(client, signed_apks[0])
    assert run_one()
    one_url = "/api/v1/scans/" + first["id"]
    one_scan = client.get(one_url).json()
    assert one_scan["status"] == "completed", one_scan
    report = one_scan["report"]
    assert report["signing"]["status"] == "verified", report["signing"]
    assert report["identity"]["verdict"] == "unverified_identity"
    assert report["metadata"]["package"] == "org.example.sentinel.fixture"
    assert report["metadata"]["label"] == "Sentinel Test Fixture"
    assert report["model"]["status"] == "unavailable"
    assert {f["id"] for f in report["findings"]} >= {"PERM-001", "MAN-003"}

    trusted = {
        "package": report["metadata"]["package"],
        "publisher": "Local fixture generator",
        "label": report["metadata"]["label"],
        "source": "https://example.test/fixture",
        "evidence": "Generated and signed as part of this isolated automated test.",
        "verified_on": "2026-01-01",
        "status": "active",
        "signer_sets": [report["signing"]["sha256"]],
    }
    catalog = "/api/v1/catalog/" + trusted["package"]
    assert client.put(catalog, headers=HEADERS, json=trusted).status_code == 200

    def scanned(data):
        job = upload(client, data)
        assert run_one()
        response = client.get("/api/v1/scans/" + job["id"]).json()
        assert response["status"] == "completed", response
        return job, response["report"]

    match, match_report = scanned(signed_apks[0])
    assert match_report["identity"]["verdict"] == "verified_match"
    different, different_report = scanned(signed_apks[1])
    assert different_report["identity"]["verdict"] == "identity_mismatch"
    assert different_report["assessment"]["level"] == "high"
    _, unsigned = scanned(signed_apks[2])
    assert unsigned["signing"]["status"] == "failed"
    assert "SIGN-001" in {finding["id"] for finding in unsigned["findings"]}
    trusted["status"] = "revoked"
    assert client.put(catalog, headers=HEADERS, json=trusted).json()["revision"] == 2
    assert client.get("/api/v1/operations").status_code == 200
    comparisons = client.get(
        "/api/v1/scans/compare", params={"left": match["id"], "right": different["id"]}
    ).json()
    assert comparisons["same_package"] and not comparisons["identical_hash"]
    assert comparisons["permissions_added"] == []
    dashboard = client.get("/api/v1/dashboard").json()
    assert dashboard["total"] == 4 and dashboard["risks"]["high"] == 2
    assert (
        client.get("/api/v1/scans", params={"q": trusted["package"]}).json()["total"]
        == 4
    )
    assert client.get(one_url + "/report.json").json() == report
    pdf = client.get(one_url + "/report.pdf")
    assert pdf.headers["content-type"] == "application/pdf" and pdf.content.startswith(
        b"%PDF"
    )
    with engine.connect() as conn:
        stored = conn.execute(
            select(scans.c.report).where(scans.c.id == first["id"])
        ).scalar_one()
    assert stored["sha256"] == report["sha256"]
    assert not (UPLOADS / (first["id"] + ".apk")).exists()
    client.cookies.clear()
    account(client)
    assert client.get(one_url).status_code == 404
    assert client.get(one_url + "/report.pdf").status_code == 404
    assert client.put(catalog, headers=HEADERS, json=trusted).status_code == 403
