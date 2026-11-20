import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# These values apply only to the pytest process and protect the live datastore.
scratch = tempfile.TemporaryDirectory(prefix="sentinel-tests-")
os.environ["SENTINEL_DATA"] = scratch.name
os.environ["SENTINEL_DATABASE"] = f"sqlite:///{Path(scratch.name) / 'test.db'}"
os.environ["SENTINEL_MAX_UPLOAD_MIB"] = "1"
os.environ["SENTINEL_ALLOW_REGISTER"] = "true"
os.environ["SENTINEL_SECURE_COOKIE"] = "false"
os.environ["SENTINEL_EXCHANGE"] = ""


@pytest.fixture
def client():
    from sentinel.api import app

    with TestClient(app) as instance:
        yield instance


@pytest.fixture
def signed_apks():
    root = Path(os.getenv("SENTINEL_TEST_FIXTURES", "data/fixtures"))
    paths = [root / name for name in ("original.apk", "rotated.apk", "unsigned.apk")]
    if not all(path.is_file() for path in paths):
        pytest.skip("Generate harmless signed APK fixtures first")
    if not os.getenv("SENTINEL_APKSIGNER_JAR"):
        pytest.skip("Configure Android apksigner for cryptographic verification")
    return [path.read_bytes() for path in paths]
