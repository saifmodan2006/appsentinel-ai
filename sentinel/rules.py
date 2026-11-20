import re
import unicodedata
from difflib import SequenceMatcher

VERSION = "1.0.0"
MANIFEST = "https://developer.android.com/guide/topics/manifest/application-element"
PERMISSIONS = "https://developer.android.com/reference/android/Manifest.permission"
EXPORTED = "https://developer.android.com/privacy-and-security/risks/android-exported"
WEBVIEW = "https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges"
DYNAMIC = (
    "https://developer.android.com/privacy-and-security/risks/dynamic-code-loading"
)

SENSITIVE = {
    "READ_SMS",
    "RECEIVE_SMS",
    "SEND_SMS",
    "READ_CONTACTS",
    "RECORD_AUDIO",
    "CAMERA",
    "ACCESS_FINE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION",
    "REQUEST_INSTALL_PACKAGES",
    "SYSTEM_ALERT_WINDOW",
    "READ_CALL_LOG",
    "MANAGE_EXTERNAL_STORAGE",
    "QUERY_ALL_PACKAGES",
}


def normalized(label):
    return re.sub(r"[\W_]", "", unicodedata.normalize("NFKC", label).casefold())


def assess_identity(meta, signing, references):
    records = [record for record in references if record["status"] == "active"]
    exact = next(
        (record for record in records if record["package"] == meta["package"]), None
    )
    if exact:
        reference = {
            key: exact[key]
            for key in (
                "reference_id",
                "revision",
                "package",
                "publisher",
                "source",
                "verified_on",
                "evidence",
            )
        }
        if signing["status"] != "verified":
            return {
                "verdict": "insufficient_evidence",
                "reference": reference,
                "reason": "A trusted package exists but its signer could not be verified.",
            }
        observed = sorted(signing["sha256"])
        matched = any(
            set(observed) == set(approved) for approved in exact["signer_sets"]
        )
        return {
            "verdict": "verified_match" if matched else "identity_mismatch",
            "reference": reference,
            "observed_signers": observed,
            "accepted_signer_sets": exact["signer_sets"],
            "reason": "Verified signer set matches the catalog."
            if matched
            else "The APK verifies, but its signer set differs from the catalog. Check for an authorized key rotation or distribution channel.",
        }
    label = normalized(meta["label"] or "")
    matches = []
    for record in records:
        trusted_label = normalized(record["label"])
        similarity = (
            SequenceMatcher(None, label, trusted_label, autojunk=False).ratio()
            if len(label) >= 5
            else 0
        )
        icon, reference_icon = meta.get("icon_hash"), record.get("icon_hash")
        distance = (
            (int(icon, 16) ^ int(reference_icon, 16)).bit_count()
            if icon and reference_icon
            else None
        )
        if similarity >= 0.90 or (distance is not None and distance <= 5):
            matches.append(
                {
                    "reference_id": record["reference_id"],
                    "revision": record["revision"],
                    "package": record["package"],
                    "publisher": record["publisher"],
                    "source": record["source"],
                    "label_similarity": round(similarity, 3),
                    "icon_hamming_distance": distance,
                }
            )
    if matches:
        return {
            "verdict": "possible_impersonation",
            "candidates": matches[:10],
            "reason": "The label or icon resembles an active catalog entry with a different package identity.",
        }
    return {
        "verdict": "unverified_identity",
        "reason": "No matching active reference was found.",
    }


def findings_for(parsed, threat=None):
    meta = parsed["metadata"]
    found = []

    def add(id, severity, title, description, evidence, source, reference, action):
        found.append(
            {
                "id": id,
                "version": VERSION,
                "severity": severity,
                "title": title,
                "description": description,
                "evidence": evidence,
                "source": source,
                "reference": reference,
                "action": action,
                "limitation": "Static evidence. Behavior depends on runtime conditions and app context.",
            }
        )

    sensitive = [
        p
        for p in meta["permissions"]
        if p.startswith("android.permission.") and p.rsplit(".", 1)[-1] in SENSITIVE
    ]
    if sensitive:
        add(
            "PERM-001",
            "medium",
            "Sensitive access requested",
            "Permissions may enable access to private data or privileged features.",
            sensitive,
            "AndroidManifest.xml",
            PERMISSIONS,
            "Check that each permission supports a feature you expect.",
        )
    permissions = set(sensitive)
    if {
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.REQUEST_INSTALL_PACKAGES",
    } <= permissions:
        add(
            "PERM-002",
            "medium",
            "Overlay and package installation access",
            "Together these capabilities merit additional review.",
            [
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.REQUEST_INSTALL_PACKAGES",
            ],
            "AndroidManifest.xml",
            PERMISSIONS,
            "Confirm the publisher and verify that both capabilities are expected.",
        )
    exposed = [
        c["name"]
        for c in meta["components"]
        if c["exported"] and not c["permission"] and not c["launcher"]
    ]
    if exposed:
        add(
            "MAN-001",
            "medium",
            "Exported components need review",
            "Other apps may reach components without a general manifest permission. Component-specific controls may apply.",
            exposed,
            "AndroidManifest.xml",
            EXPORTED,
            "Review component access checks before distributing the app.",
        )
    for key, rule, title, detail in [
        (
            "debuggable",
            "MAN-002",
            "Debug mode enabled",
            "Debuggable release builds expose additional inspection interfaces.",
        ),
        (
            "usesCleartextTraffic",
            "MAN-003",
            "Cleartext traffic allowed",
            "The manifest allows cleartext traffic. Network security configuration and library behavior may affect enforcement.",
        ),
    ]:
        if meta["attributes"].get(key) == "true":
            add(
                rule,
                "medium",
                title,
                detail,
                [f"android:{key}=true"],
                "AndroidManifest.xml",
                MANIFEST,
                "Ask the publisher to review this release configuration.",
            )
    refs = set(parsed["code"]["references"])
    for marker, id, severity, title, reference in [
        (
            "dynamic_loader",
            "DEX-001",
            "medium",
            "Dynamic code loading API referenced",
            DYNAMIC,
        ),
        (
            "webview_bridge",
            "DEX-002",
            "medium",
            "WebView JavaScript bridge API referenced",
            WEBVIEW,
        ),
        (
            "reflection",
            "DEX-003",
            "low",
            "Reflection API referenced",
            "https://developer.android.com/reference/java/lang/reflect/Method",
        ),
        (
            "sms_api",
            "DEX-004",
            "low",
            "SMS sending API referenced",
            "https://developer.android.com/reference/android/telephony/SmsManager",
        ),
    ]:
        if marker in refs:
            add(
                id,
                severity,
                title,
                "A method ID appears in DEX. Reachability, arguments, and runtime behavior were not established.",
                [marker],
                "DEX method IDs",
                reference,
                "Review whether this capability is necessary for the expected app behavior.",
            )
    if meta["native_libraries"]:
        add(
            "NATIVE-001",
            "info",
            "Native libraries present",
            "Native binaries are listed as part of the archive inventory.",
            meta["native_libraries"],
            "APK ZIP entries",
            MANIFEST,
            "Use a dedicated native-code review when assessing these libraries.",
        )
    if parsed["signing"]["status"] == "failed":
        add(
            "SIGN-001",
            "high",
            "Android signature verification failed",
            parsed["signing"]["reason"],
            ["apksigner verify"],
            "Android SDK apksigner",
            "https://developer.android.com/tools/apksigner",
            "Obtain a fresh APK from the official publisher and verify it before installation.",
        )
    for match in (threat or {}).get("matches", []):
        exact_apk = match["type"] == "apk_sha256"
        add(
            "IOC-001" if exact_apk else "IOC-002",
            "critical" if exact_apk else "medium",
            "APK hash matches a threat record"
            if exact_apk
            else "Embedded hostname matches a threat record",
            match["context"],
            [match["value"]],
            "Operator-approved indicator snapshot",
            match["source"],
            "Review the source evidence before installing or distributing the APK.",
        )
    return found


def assessment(parsed, identity, findings, model):
    critical = [
        finding["title"] for finding in findings if finding["severity"] == "critical"
    ]
    if critical:
        return {"level": "critical", "reasons": critical, "policy_version": VERSION}
    reasons = []
    if identity["verdict"] == "identity_mismatch":
        reasons.append("Verified signers differ from the trusted catalog.")
    reasons.extend(f["title"] for f in findings if f["severity"] == "high")
    if reasons:
        return {"level": "high", "reasons": reasons, "policy_version": VERSION}
    if model.get("above_threshold"):
        reasons.append("The enabled model exceeded its documented decision threshold.")
    if identity["verdict"] == "possible_impersonation":
        reasons.append("Label or icon similarity warrants a publisher check.")
    reasons.extend(f["title"] for f in findings if f["severity"] == "medium")
    if reasons:
        return {"level": "moderate", "reasons": reasons, "policy_version": VERSION}
    if parsed["signing"]["status"] != "verified" or any(
        x["field"] == "DEX" or x["field"].endswith(".dex") for x in parsed["missing"]
    ):
        return {
            "level": "inconclusive",
            "reasons": ["Signature verification or DEX coverage is incomplete."],
            "policy_version": VERSION,
        }
    return {
        "level": "low_observed",
        "reasons": ["Available static checks found no high or moderate risk evidence."],
        "policy_version": VERSION,
    }
