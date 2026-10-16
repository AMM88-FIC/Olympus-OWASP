import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from ..helpers.ids import next_id
from ..helpers.xpath import build_xpath
from ..models import (
    BackupPolicy, BackupRule, GeneratedBy, ManifestFlags,
    ManifestFindingsFile, MetaDataRecord, Source,
)

logger = logging.getLogger(__name__)

EXTRACTOR = "manifest_parser_v1"
TOOL = "apktool-2.12.1"
NS = "http://schemas.android.com/apk/res/android"


def build(job_id: str, apktool_result) -> ManifestFindingsFile:
    """
    Parse AndroidManifest.xml and extract app-level flags and meta-data.

    Args:
        job_id:          Analysis job identifier.
        apktool_result:  ApktoolResult from the extraction coordinator.

    Returns:
        Populated ManifestFindingsFile.
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
    app_el = root.find("application")

    flags = _parse_flags(app_el)
    meta_data = _parse_meta_data(job_id, app_el, tree, manifest_path)

    backup_policy = _parse_backup_policy(flags, apktool_result.output_dir)

    return ManifestFindingsFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        flags=flags,
        meta_data=meta_data,
        backup_policy=backup_policy,
        source=Source(
            artifact="manifest",
            path=_rel(manifest_path, apktool_result.output_dir),
            xpath="/manifest/application",
            extractor=EXTRACTOR,
            tool=TOOL,
        ),
    )


def _parse_flags(app_el: ET.Element | None) -> ManifestFlags:
    if app_el is None:
        return ManifestFlags()

    def attr(name: str) -> str | None:
        return app_el.get(f"{{{NS}}}{name}")

    def bool_attr(name: str) -> bool | None:
        v = attr(name)
        if v is None:
            return None
        return v.lower() == "true"

    return ManifestFlags(
        debuggable=bool_attr("debuggable"),
        allow_backup=bool_attr("allowBackup"),
        uses_cleartext_traffic=bool_attr("usesCleartextTraffic"),
        network_security_config_ref=attr("networkSecurityConfig"),
        target_sandbox_version=_to_int(attr("targetSandboxVersion")),
        extract_native_libs=bool_attr("extractNativeLibs"),
        full_backup_content_ref=attr("fullBackupContent"),
        data_extraction_rules_ref=attr("dataExtractionRules"),
        task_affinity=attr("taskAffinity"),
        large_heap=bool_attr("largeHeap"),
        allow_task_reparenting=bool_attr("allowTaskReparenting"),
        test_only=bool_attr("testOnly"),
    )


def _parse_meta_data(
    job_id: str,
    app_el: ET.Element | None,
    tree: ET.ElementTree,
    manifest_path: Path,
) -> list[MetaDataRecord]:
    if app_el is None:
        return []

    records = []
    rel_path = str(manifest_path.name)

    for elem in app_el.findall("meta-data"):
        name = elem.get(f"{{{NS}}}name") or elem.get("name")
        value = elem.get(f"{{{NS}}}value") or elem.get("value")
        resource = elem.get(f"{{{NS}}}resource") or elem.get("resource")

        if not name:
            continue

        xpath = build_xpath(elem, tree)

        records.append(
            MetaDataRecord(
                id=next_id(job_id, "meta"),
                name=name,
                value=value,
                resource_ref=resource,
                scope="application",
                confidence=1.0,
                source=Source(
                    artifact="manifest",
                    path=rel_path,
                    xpath=xpath,
                    extractor=EXTRACTOR,
                    tool=TOOL,
                ),
            )
        )

    return records


def _to_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _rel(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return path.name


def _empty(job_id: str) -> ManifestFindingsFile:
    return ManifestFindingsFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        flags=ManifestFlags(),
        meta_data=[],
        source=Source(
            artifact="manifest",
            path="AndroidManifest.xml",
            extractor=EXTRACTOR,
            tool=TOOL,
        ),
    )


def _parse_backup_policy(flags: ManifestFlags, output_dir) -> BackupPolicy:
    """
    Parse backup rules from full_backup_content and data_extraction_rules XML
    referenced in the manifest. Falls back to flag-only summary when XMLs
    are absent or malformed.
    """
    from pathlib import Path

    def resolve_xml_ref(ref: str | None) -> Path | None:
        if not ref:
            return None
        # Strip @xml/ prefix → res/xml/<name>.xml
        name = ref.split("/")[-1]
        if not name.endswith(".xml"):
            name += ".xml"
        candidate = Path(output_dir) / "res" / "xml" / name
        return candidate if candidate.exists() else None

    fbc_path = resolve_xml_ref(flags.full_backup_content_ref)
    der_path = resolve_xml_ref(flags.data_extraction_rules_ref)

    cloud_rules = _parse_backup_rules_xml(fbc_path) if fbc_path else []
    device_rules = _parse_backup_rules_xml(der_path, device_only=True) if der_path else []

    return BackupPolicy(
        allow_backup_app_flag=flags.allow_backup,
        full_backup_content_path=str(fbc_path) if fbc_path else None,
        data_extraction_rules_path=str(der_path) if der_path else None,
        cloud_backup_rules=cloud_rules,
        device_transfer_rules=device_rules,
        parsed=bool(fbc_path or der_path),
    )


def _parse_backup_rules_xml(
    xml_path,
    device_only: bool = False,
) -> list[BackupRule]:
    """Parse include/exclude rules from a full-backup-content or data-extraction-rules XML."""
    from pathlib import Path
    rules = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for elem in root.iter():
            tag = elem.tag.lower()
            if tag not in ("include", "exclude"):
                continue
            domain_raw = elem.get("domain", "file")
            domain_map = {
                "root": "root", "file": "file", "database": "database",
                "sharedpref": "sharedpref", "external": "external",
                "device": "device_only",
            }
            domain = domain_map.get(domain_raw, "file")
            rules.append(BackupRule(
                domain=domain,
                path=elem.get("path"),
                rule="include" if tag == "include" else "exclude",
                requires_flag=None,
            ))
    except Exception:
        pass
    return rules