import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from ..helpers.ids import next_id
from ..helpers.xpath import build_xpath
from ..models import (
    DeclaredPermissionRecord, GeneratedBy,
    PermissionRecord, PermissionsFile, Source,
)

logger = logging.getLogger(__name__)

EXTRACTOR = "permission_parser_v1"
TOOL = "apktool-2.12.1"
NS = "http://schemas.android.com/apk/res/android"

# Protection level lookup for well-known Android permissions.
# Source: https://developer.android.com/reference/android/Manifest.permission
# Only the security-relevant ones are listed — unknown permissions default to "unknown".
_PROTECTION_LEVELS: dict[str, tuple[str, bool]] = {
    # (protection_level, is_dangerous)
    "android.permission.INTERNET":                          ("normal",    False),
    "android.permission.ACCESS_NETWORK_STATE":              ("normal",    False),
    "android.permission.ACCESS_WIFI_STATE":                 ("normal",    False),
    "android.permission.CHANGE_WIFI_STATE":                 ("normal",    False),
    "android.permission.RECEIVE_BOOT_COMPLETED":            ("normal",    False),
    "android.permission.VIBRATE":                           ("normal",    False),
    "android.permission.WAKE_LOCK":                         ("normal",    False),
    "android.permission.USE_BIOMETRIC":                     ("normal",    False),
    "android.permission.USE_FINGERPRINT":                   ("normal",    False),
    "android.permission.REQUEST_INSTALL_PACKAGES":          ("signature", False),
    "android.permission.INSTALL_PACKAGES":                  ("signature", False),
    "android.permission.READ_LOGS":                         ("signature", False),
    "android.permission.CAMERA":                            ("dangerous", True),
    "android.permission.READ_CONTACTS":                     ("dangerous", True),
    "android.permission.WRITE_CONTACTS":                    ("dangerous", True),
    "android.permission.READ_CALL_LOG":                     ("dangerous", True),
    "android.permission.WRITE_CALL_LOG":                    ("dangerous", True),
    "android.permission.READ_PHONE_STATE":                  ("dangerous", True),
    "android.permission.CALL_PHONE":                        ("dangerous", True),
    "android.permission.RECORD_AUDIO":                      ("dangerous", True),
    "android.permission.ACCESS_FINE_LOCATION":              ("dangerous", True),
    "android.permission.ACCESS_COARSE_LOCATION":            ("dangerous", True),
    "android.permission.ACCESS_BACKGROUND_LOCATION":        ("dangerous", True),
    "android.permission.READ_EXTERNAL_STORAGE":             ("dangerous", True),
    "android.permission.WRITE_EXTERNAL_STORAGE":            ("dangerous", True),
    "android.permission.MANAGE_EXTERNAL_STORAGE":           ("dangerous", True),
    "android.permission.READ_MEDIA_IMAGES":                 ("dangerous", True),
    "android.permission.READ_MEDIA_VIDEO":                  ("dangerous", True),
    "android.permission.READ_MEDIA_AUDIO":                  ("dangerous", True),
    "android.permission.READ_SMS":                          ("dangerous", True),
    "android.permission.SEND_SMS":                          ("dangerous", True),
    "android.permission.RECEIVE_SMS":                       ("dangerous", True),
    "android.permission.READ_CALENDAR":                     ("dangerous", True),
    "android.permission.WRITE_CALENDAR":                    ("dangerous", True),
    "android.permission.BODY_SENSORS":                      ("dangerous", True),
    "android.permission.BLUETOOTH_SCAN":                    ("dangerous", True),
    "android.permission.BLUETOOTH_CONNECT":                 ("dangerous", True),
    "android.permission.NEARBY_WIFI_DEVICES":               ("dangerous", True),
    "android.permission.PROCESS_OUTGOING_CALLS":            ("dangerous", True),
    "android.permission.GET_ACCOUNTS":                      ("dangerous", True),
    "android.permission.USE_ICC_AUTH_WITH_DEVICE_IDENTIFIER": ("dangerous", True),
}

_SIGNATURE_LEVELS = frozenset({"signature", "signatureOrSystem", "privileged"})


def build(job_id: str, apktool_result) -> PermissionsFile:
    """
    Parse uses-permission and permission declarations from AndroidManifest.xml.

    Args:
        job_id:          Analysis job identifier.
        apktool_result:  ApktoolResult from the extraction coordinator.

    Returns:
        Populated PermissionsFile.
    """
    manifest_path = apktool_result.manifest_path
    if not manifest_path or not manifest_path.exists():
        logger.warning("Manifest not found for job %s", job_id)
        return _empty(job_id)

    try:
        tree = ET.parse(manifest_path)
    except ET.ParseError as exc:
        logger.error("Failed to parse manifest for job %s: %s", job_id, exc)
        return _empty(job_id)

    root = tree.getroot()
    base_path = apktool_result.output_dir
    rel_path = _rel(manifest_path, base_path)

    requested = _parse_requested(job_id, root, tree, rel_path)
    declared = _parse_declared(job_id, root, tree, rel_path)

    return PermissionsFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        requested=requested,
        declared=declared,
    )


def _parse_requested(
    job_id: str,
    root: ET.Element,
    tree: ET.ElementTree,
    rel_path: str,
) -> list[PermissionRecord]:
    records = []

    for elem in root.findall("uses-permission"):
        name = elem.get(f"{{{NS}}}name") or elem.get("name")
        if not name:
            continue

        max_sdk = elem.get(f"{{{NS}}}maxSdkVersion")
        protection_level, is_dangerous = _lookup_protection(name)
        is_signature_only = protection_level in _SIGNATURE_LEVELS
        xpath = build_xpath(elem, tree)

        records.append(PermissionRecord(
            id=next_id(job_id, "perm"),
            name=name,
            protection_level=protection_level,
            is_dangerous=is_dangerous,
            is_signature_only=is_signature_only,
            max_sdk_version=int(max_sdk) if max_sdk else None,
            usage_min_sdk_version=None,
            confidence=1.0,
            source=Source(
                artifact="manifest",
                path=rel_path,
                xpath=xpath,
                extractor=EXTRACTOR,
                tool=TOOL,
            ),
        ))

    return records


def _parse_declared(
    job_id: str,
    root: ET.Element,
    tree: ET.ElementTree,
    rel_path: str,
) -> list[DeclaredPermissionRecord]:
    records = []

    for elem in root.findall("permission"):
        name = elem.get(f"{{{NS}}}name") or elem.get("name")
        if not name:
            continue

        raw_level = elem.get(f"{{{NS}}}protectionLevel")
        protection_level = _decode_protection_level(raw_level)
        label = elem.get(f"{{{NS}}}label")
        description = elem.get(f"{{{NS}}}description")
        xpath = build_xpath(elem, tree)

        records.append(DeclaredPermissionRecord(
            id=next_id(job_id, "perm"),
            name=name,
            protection_level=protection_level,
            label=label,
            description=description,
            confidence=1.0,
            source=Source(
                artifact="manifest",
                path=rel_path,
                xpath=xpath,
                extractor=EXTRACTOR,
                tool=TOOL,
            ),
        ))

    return records


def _lookup_protection(name: str) -> tuple[str, bool]:
    """Return (protection_level, is_dangerous) for a permission name."""
    entry = _PROTECTION_LEVELS.get(name)
    if entry:
        return entry
    # Heuristic: third-party permissions default to normal unless declared otherwise
    return ("unknown", False)


def _decode_protection_level(raw: str | None) -> str | None:
    """
    Decode Android's protectionLevel integer flags to a human-readable string.
    The low 4 bits encode the base level; higher bits encode additional flags.
    """
    if raw is None:
        return None
    try:
        value = int(raw, 0)
    except (ValueError, TypeError):
        return raw

    base = value & 0xF
    mapping = {0: "normal", 1: "dangerous", 2: "signature", 3: "signatureOrSystem"}
    return mapping.get(base, f"unknown({base})")


def _rel(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return path.name


def _empty(job_id: str) -> PermissionsFile:
    return PermissionsFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        requested=[],
        declared=[],
    )