from pathlib import Path
from zipfile import ZipFile

import pytest

from sentinel import apk
from sentinel.rules import assess_identity, assessment
from sentinel.runner import read_result


def test_zip_structure_and_limits(tmp_path, monkeypatch):
    path = tmp_path / "sample.apk"
    with ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"test data")
        archive.writestr("res/asset.txt", b"example")
    with ZipFile(path) as archive:
        assert apk.check_archive(path, archive) == {
            "AndroidManifest.xml",
            "res/asset.txt",
        }
        monkeypatch.setattr(apk, "MAX_UNPACKED", 6)
        with pytest.raises(apk.InvalidAPK, match="decompressed size"):
            apk.check_archive(path, archive)


def test_archive_without_manifest(tmp_path):
    path = tmp_path / "sample.apk"
    with ZipFile(path, "w") as archive:
        archive.writestr("note.txt", b"hello")
    with ZipFile(path) as archive, pytest.raises(apk.InvalidAPK, match="missing"):
        apk.check_archive(path, archive)


def test_identity_similarity_and_rotation():
    metadata = {
        "package": "com.example.real",
        "label": "Example Notes",
        "icon_hash": None,
    }
    root = {
        "package": metadata["package"],
        "reference_id": "test",
        "revision": 1,
        "publisher": "Example",
        "source": "https://example.test",
        "verified_on": "2026-01-01",
        "evidence": "Test catalog evidence.",
        "label": "Example Notes",
        "status": "active",
        "signer_sets": [["old"], ["new", "partner"]],
    }
    signing = {"status": "verified", "sha256": ["partner", "new"]}
    assert assess_identity(metadata, signing, [root])["verdict"] == "verified_match"
    assert (
        assess_identity(metadata, {**signing, "sha256": ["new"]}, [root])["verdict"]
        == "identity_mismatch"
    )
    assert (
        assess_identity(metadata, {"status": "unavailable"}, [root])["verdict"]
        == "insufficient_evidence"
    )
    assert (
        assess_identity({**metadata, "package": "org.other.app"}, signing, [root])[
            "verdict"
        ]
        == "possible_impersonation"
    )
    assert (
        assess_identity(metadata, signing, [{**root, "status": "revoked"}])["verdict"]
        == "unverified_identity"
    )


def test_assessment_distinguishes_uncertainty_and_permission_risk():
    parsed = {"signing": {"status": "unavailable"}, "missing": [{"field": "signing"}]}
    identity = {"verdict": "unverified_identity"}
    assert assessment(parsed, identity, [], {})["level"] == "inconclusive"
    assert (
        assessment(
            parsed,
            identity,
            [{"severity": "medium", "title": "Review permissions"}],
            {},
        )["level"]
        == "moderate"
    )
    assert (
        assessment(
            {"signing": {"status": "verified"}, "missing": []}, identity, [], {}
        )["level"]
        == "low_observed"
    )


def test_parser_deadline_terminates_process(monkeypatch, tmp_path):
    import subprocess
    from types import SimpleNamespace

    from sentinel import runner

    process = SimpleNamespace(
        wait=lambda timeout: (_ for _ in ()).throw(
            subprocess.TimeoutExpired("fixture", timeout)
        ),
        poll=lambda: None,
    )
    ended = []
    ticks = iter([10, 10, 1000])
    monkeypatch.setattr(runner.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(runner.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(runner, "stop_process", ended.append)
    assert runner.run_parser(tmp_path / "fixture.apk", lambda: None) == {
        "error": "Scan exceeded the worker time limit."
    }
    assert ended == [process]


def test_result_size_is_bounded(tmp_path):
    path = Path(tmp_path) / "report.json"
    path.write_text('{"metadata":{}}')
    assert read_result(path) == {"metadata": {}}
    with path.open("ab") as stream:
        stream.truncate(7 * 1024**2)
    with pytest.raises(ValueError):
        read_result(path)


def test_raster_icon_similarity_uses_decoded_pixels(tmp_path):
    from io import BytesIO

    from PIL import Image

    image = Image.new("L", (9, 8))
    image.putdata([255 - 16 * x for _ in range(8) for x in range(9)])
    encoded = BytesIO()
    image.save(encoded, format="PNG")
    path = tmp_path / "raster.apk"
    with ZipFile(path, "w") as archive:
        archive.writestr("res/icon.png", encoded.getvalue())
    with ZipFile(path) as archive:
        assert apk.icon_fingerprint(archive, "res/icon.png") == "ffffffffffffffff"
        assert apk.icon_fingerprint(archive, "res/missing.png") is None


def test_verified_threat_snapshot_matches_only_exact_indicators(tmp_path, monkeypatch):
    import hashlib
    import json

    from sentinel.indicators import load_indicators, match_indicators

    sha = "a" * 64
    entry = {
        "type": "apk_sha256",
        "value": sha,
        "source": "https://example.test/fixture",
        "context": "Use this record only in the threat snapshot contract test.",
    }
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps({"version": "test", "entries": [entry]}))
    monkeypatch.setenv("SENTINEL_INDICATORS", str(path))
    monkeypatch.setenv(
        "SENTINEL_INDICATORS_SHA256", hashlib.sha256(path.read_bytes()).hexdigest()
    )
    snapshot = load_indicators()
    assert match_indicators(snapshot, sha, [])["matches"] == [entry]
    assert match_indicators(snapshot, "b" * 64, [])["matches"] == []
