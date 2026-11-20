"""Measure serial upload-to-report stages using a harmless APK against running Sentinel."""

import argparse
import json
import secrets
import statistics
import time
from pathlib import Path

import httpx


def evaluate(url, apk, count):
    data = apk.read_bytes()
    results = []
    with httpx.Client(
        base_url=url, headers={"X-Sentinel-Request": "1"}, timeout=120
    ) as client:
        identity = {
            "email": secrets.token_hex(12) + "@example.test",
            "password": secrets.token_urlsafe(24),
        }
        client.post("/api/v1/auth/register", json=identity).raise_for_status()
        client.post("/api/v1/auth/login", json=identity).raise_for_status()
        for _ in range(count):
            started = time.perf_counter()
            job = client.post(
                "/api/v1/scans",
                headers={"Content-Type": "application/octet-stream"},
                content=data,
            )
            job.raise_for_status()
            uploaded = time.perf_counter()
            endpoint = "/api/v1/scans/" + job.json()["id"]
            try:
                while time.perf_counter() - started < 120:
                    scan = client.get(endpoint).raise_for_status().json()
                    if scan["status"] in {"completed", "failed", "cancelled"}:
                        break
                    time.sleep(0.1)
                else:
                    raise TimeoutError("Scan did not complete")
                completed = time.perf_counter()
                if scan["status"] != "completed":
                    results.append({"failed": True, "reason": scan["error"]})
                    continue
                pdf = client.get(endpoint + "/report.pdf").raise_for_status()
                exported = time.perf_counter()
                if not pdf.content.startswith(b"%PDF"):
                    raise ValueError("PDF content was invalid")
                results.append(
                    {
                        "failed": False,
                        "upload_ms": (uploaded - started) * 1000,
                        "worker_seconds": scan["report"]["analysis_seconds"],
                        "upload_to_completed_ms": (completed - started) * 1000,
                        "pdf_ms": (exported - completed) * 1000,
                        "total_seconds": exported - started,
                    }
                )
            finally:
                client.delete(endpoint)
        client.post("/api/v1/auth/logout").raise_for_status()
    successful = [entry for entry in results if not entry["failed"]]
    averages = (
        {
            key: round(statistics.mean(entry[key] for entry in successful), 3)
            for key in (
                "upload_ms",
                "worker_seconds",
                "upload_to_completed_ms",
                "pdf_ms",
            )
        }
        if successful
        else {}
    )
    return {
        "apk_bytes": len(data),
        "serial_scans": count,
        "failed": count - len(successful),
        "averages": averages,
        "serial_successful_scans_per_minute": round(
            60 * len(successful) / sum(entry["total_seconds"] for entry in successful),
            2,
        )
        if successful
        else 0,
        "samples": results,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", type=Path)
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--count", type=int, choices=range(1, 11), default=5)
    args = parser.parse_args()
    print(json.dumps(evaluate(args.url, args.apk, args.count), indent=2))


if __name__ == "__main__":
    main()
