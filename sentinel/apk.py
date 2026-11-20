import io
import re
import stat
import subprocess
from importlib.metadata import version
from pathlib import PurePosixPath
from urllib.parse import urlsplit
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile

from androguard.core.apk import APK
from androguard.core.dex import DEX
from loguru import logger
from PIL import Image, UnidentifiedImageError

from sentinel.config import MAX_ENTRIES, MAX_UNPACKED, MAX_UPLOAD

logger.remove()
ANDROID = "{http://schemas.android.com/apk/res/android}"
DEX_NAME = re.compile(r"classes(?:[2-9]|[1-9][0-9]+)?\.dex")
MAX_MANIFEST = 4 * 1024**2
MAX_DEX = 32 * 1024**2
Image.MAX_IMAGE_PIXELS = 2_000_000


class InvalidAPK(ValueError):
    pass


def check_archive(path, archive):
    if path.stat().st_size > MAX_UPLOAD:
        raise InvalidAPK("APK exceeds the configured limit.")
    items = archive.infolist()
    if not 0 < len(items) <= MAX_ENTRIES:
        raise InvalidAPK("Archive entry count exceeds the configured limit.")
    if sum(item.file_size for item in items) > MAX_UNPACKED:
        raise InvalidAPK("Archive exceeds the decompressed size limit.")
    names = set()
    offsets = set()
    for item in items:
        name = item.orig_filename
        parts = name.removesuffix("/").split("/")
        if (
            any(part in {"", ".", ".."} for part in parts)
            or "\\" in name
            or ":" in name
            or len(name) > 512
            or any(ord(c) < 32 for c in name)
            or PurePosixPath(name).is_absolute()
            or stat.S_ISLNK(item.external_attr >> 16)
        ):
            raise InvalidAPK("Archive contains an unsafe entry path.")
        if name in names or item.header_offset in offsets:
            raise InvalidAPK("Archive contains overlapping or duplicate entries.")
        if item.flag_bits & 1 or item.compress_type not in {ZIP_DEFLATED, ZIP_STORED}:
            raise InvalidAPK(
                "Archive uses an unsupported compression or encryption method."
            )
        names.add(name)
        offsets.add(item.header_offset)
    if "AndroidManifest.xml" not in names:
        raise InvalidAPK("AndroidManifest.xml is missing.")
    if not 0 < archive.getinfo("AndroidManifest.xml").file_size <= MAX_MANIFEST:
        raise InvalidAPK("Android manifest size is unsupported.")
    total = 0
    for item in items:
        actual = 0
        with archive.open(item) as entry:
            for block in iter(lambda: entry.read(128 * 1024), b""):
                actual += len(block)
                total += len(block)
                if actual > item.file_size or total > MAX_UNPACKED:
                    raise InvalidAPK("Archive expands past its declared limits.")
        if actual != item.file_size:
            raise InvalidAPK("Archive entry is truncated.")
    return names


def signer(path, jar, java):
    if not jar:
        return {
            "status": "unavailable",
            "reason": "Android apksigner is not configured.",
            "sha256": [],
            "schemes": [],
        }
    command = [java, "-Xmx256m", "-jar", jar]
    try:
        result = subprocess.run(
            [*command, "verify", "--verbose", "--print-certs", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=25,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {
            "status": "unavailable",
            "reason": "Android apksigner failed to start or timed out.",
            "sha256": [],
            "schemes": [],
        }
    values = re.findall(
        r"^Signer #\d+ certificate SHA-256 digest: ([a-fA-F0-9]{64})\s*$",
        result.stdout,
        re.M,
    )
    schemes = re.findall(
        r"^Verified using (v[\d.]+) scheme[^:]*: true\s*$", result.stdout, re.M
    )
    if result.returncode and (
        "DOES NOT VERIFY" in result.stdout or "ERROR:" in result.stdout
    ):
        return {
            "status": "failed",
            "reason": "Android apksigner rejected signature verification.",
            "sha256": [],
            "schemes": [],
        }
    if result.returncode or not values:
        return {
            "status": "unavailable",
            "reason": "Android apksigner did not return verified signers.",
            "sha256": [],
            "schemes": [],
        }
    subjects = re.findall(
        r"^Signer #\d+ certificate DN: (.{1,500})$", result.stdout, re.M
    )
    return {
        "status": "verified",
        "reason": None,
        "sha256": sorted(set(v.lower() for v in values)),
        "schemes": schemes,
        "subjects": subjects,
    }


def icon_fingerprint(archive, icon_path):
    if not icon_path or not icon_path.lower().endswith(
        (".png", ".jpg", ".jpeg", ".webp")
    ):
        return None
    try:
        info = archive.getinfo(icon_path)
        if info.file_size > 2 * 1024**2:
            return None
        with Image.open(io.BytesIO(archive.read(info))) as image:
            pixels = list(
                image.convert("L")
                .resize((9, 8), Image.Resampling.LANCZOS)
                .get_flattened_data()
            )
        bits = "".join(
            "1" if pixels[y * 9 + x] > pixels[y * 9 + x + 1] else "0"
            for y in range(8)
            for x in range(8)
        )
        return f"{int(bits, 2):016x}"
    except (
        KeyError,
        UnidentifiedImageError,
        Image.DecompressionBombError,
        OSError,
        ValueError,
    ):
        return None


def components(manifest, sdk):
    application = manifest.find("application")
    if application is None:
        return []
    entries = []
    for node in application:
        if node.tag not in {
            "activity",
            "activity-alias",
            "service",
            "receiver",
            "provider",
        }:
            continue
        explicit = node.get(ANDROID + "exported")
        has_filter = node.find("intent-filter") is not None
        if explicit in {"true", "false"}:
            exported = explicit == "true"
        elif explicit is not None or (
            has_filter and sdk >= 31 and node.tag != "provider"
        ):
            exported = None
        elif node.tag == "provider":
            exported = sdk < 17
        else:
            exported = has_filter
        permission = node.get(
            ANDROID + "permission", application.get(ANDROID + "permission")
        )
        entries.append(
            {
                "type": node.tag,
                "name": node.get(ANDROID + "name"),
                "exported": exported,
                "explicit": explicit,
                "permission": permission,
                "read_permission": node.get(ANDROID + "readPermission"),
                "write_permission": node.get(ANDROID + "writePermission"),
                "launcher": any(
                    "android.intent.category.LAUNCHER" == entry.get(ANDROID + "name")
                    for entry in node.findall("intent-filter/category")
                ),
            }
        )
    return entries


CODE_REFERENCES = {
    ("Ldalvik/system/DexClassLoader;", "<init>"): "dynamic_loader",
    ("Ldalvik/system/InMemoryDexClassLoader;", "<init>"): "dynamic_loader",
    ("Ljava/lang/reflect/Method;", "invoke"): "reflection",
    ("Landroid/webkit/WebView;", "addJavascriptInterface"): "webview_bridge",
    ("Landroid/webkit/WebSettings;", "setJavaScriptEnabled"): "webview_js",
    ("Landroid/telephony/SmsManager;", "sendTextMessage"): "sms_api",
}
HOST = re.compile(r"^https?://[^\s]{3,512}$", re.I)


def inspect_code(archive, dex_files):
    indicators = set()
    hosts = set()
    partial = []
    for name in dex_files:
        if archive.getinfo(name).file_size > MAX_DEX:
            partial.append(
                {"field": name, "reason": "DEX exceeds the individual parsing limit."}
            )
            continue
        try:
            dex = DEX(archive.read(name))
            for method in dex.get_methods():
                marker = CODE_REFERENCES.get(
                    (method.get_class_name(), method.get_name())
                )
                if marker:
                    indicators.add(marker)
            for value in dex.get_strings():
                if len(hosts) >= 100 or not HOST.fullmatch(value):
                    continue
                try:
                    hostname = urlsplit(value).hostname
                except ValueError:
                    continue
                if hostname:
                    hosts.add(hostname[:253])
        except Exception:
            partial.append(
                {"field": name, "reason": "DEX parser could not decode this file."}
            )
    return {"references": sorted(indicators), "embedded_hosts": sorted(hosts)}, partial


def inspect(path, jar, java):
    with ZipFile(path) as archive:
        names = check_archive(path, archive)
        package = APK(str(path), skip_analysis=False)
        manifest = package.get_android_manifest_xml()
        if manifest is None or not package.is_valid_APK() or not package.get_package():
            raise InvalidAPK("Android binary manifest could not be decoded.")
        missing = []
        application = manifest.find("application")
        attrs = (
            {k.removeprefix(ANDROID): v for k, v in application.attrib.items()}
            if application is not None
            else {}
        )
        target = package.get_effective_target_sdk_version()
        dex_files = sorted(name for name in names if DEX_NAME.fullmatch(name))
        native_files = sorted(
            name for name in names if re.fullmatch(r"lib/[^/]+/[^/]+\.so", name)
        )
        code, partial = inspect_code(archive, dex_files)
        missing.extend(partial)
        if not dex_files:
            missing.append(
                {
                    "field": "DEX",
                    "reason": "No standard DEX entries were found in this archive.",
                }
            )
        try:
            label = package.get_app_name()
            icon_path = package.get_app_icon()
        except Exception:
            label = icon_path = None
        image_hash = icon_fingerprint(archive, icon_path)
        if not image_hash:
            missing.append(
                {
                    "field": "icon_hash",
                    "reason": "A supported raster app icon could not be resolved.",
                }
            )
        if not label:
            missing.append(
                {"field": "label", "reason": "Application label could not be resolved."}
            )
        signed = signer(path, jar, java)
        if signed["status"] == "unavailable":
            missing.append({"field": "signing", "reason": signed["reason"]})
        return {
            "metadata": {
                "package": package.get_package(),
                "label": label or None,
                "version_name": package.get_androidversion_name(),
                "version_code": package.get_androidversion_code(),
                "min_sdk": package.get_min_sdk_version(),
                "target_sdk": package.get_target_sdk_version(),
                "effective_target_sdk": target,
                "split": manifest.get("split"),
                "permissions": sorted(set(package.get_permissions())),
                "components": components(manifest, target),
                "attributes": attrs,
                "icon_path": icon_path,
                "icon_hash": image_hash,
                "dex_files": dex_files,
                "native_libraries": native_files,
                "entry_count": len(names),
                "resource_entries": sorted(n for n in names if n.startswith("res/"))[
                    :100
                ],
            },
            "signing": signed,
            "code": code,
            "missing": missing,
            "tools": {
                "androguard": version("androguard"),
                "apksigner": "Android SDK build-tools (verify)" if jar else None,
            },
        }
