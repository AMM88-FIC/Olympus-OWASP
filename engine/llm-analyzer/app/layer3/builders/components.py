import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from ..helpers.ids import next_id
from ..helpers.xpath import build_xpath
from ..models import (
    ComponentRecord, ComponentsFile, ExportedStatus,
    GeneratedBy, IntentFilter, IntentFilterData,
    PathPermission, ProviderSpecific, Source,
)

logger = logging.getLogger(__name__)

EXTRACTOR = "manifest_parser_v1"
TOOL = "apktool-2.12.1"
NS = "http://schemas.android.com/apk/res/android"

# On API < 31, a component with an intent-filter and no explicit exported
# attribute is implicitly exported. We flag this for the LLM to reason about.
IMPLICIT_EXPORT_MAX_SDK = 30

_TAG_TO_TYPE = {
    "activity": "activity",
    "activity-alias": "activity",
    "service": "service",
    "receiver": "receiver",
    "provider": "provider",
}


def build(job_id: str, apktool_result, target_sdk: int | None = None) -> ComponentsFile:
    """
    Parse all components from AndroidManifest.xml.

    Computes the effective exported status for each component, accounting for
    the implicit export rule on API < 31.

    Args:
        job_id:          Analysis job identifier.
        apktool_result:  ApktoolResult from the extraction coordinator.
        target_sdk:      App's targetSdkVersion (used for implicit export logic).

    Returns:
        Populated ComponentsFile.
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
    if app_el is None:
        return _empty(job_id)

    records: list[ComponentRecord] = []
    base_path = apktool_result.output_dir

    for tag, comp_type in _TAG_TO_TYPE.items():
        for elem in app_el.findall(tag):
            record = _parse_component(
                job_id, elem, comp_type, tree, manifest_path, base_path, target_sdk
            )
            if record:
                records.append(record)

    return ComponentsFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=records,
    )


def _parse_component(
    job_id: str,
    elem: ET.Element,
    comp_type: str,
    tree: ET.ElementTree,
    manifest_path: Path,
    base_path: Path,
    target_sdk: int | None,
) -> ComponentRecord | None:
    def attr(name: str) -> str | None:
        return elem.get(f"{{{NS}}}{name}")

    def bool_attr(name: str) -> bool | None:
        v = attr(name)
        if v is None:
            return None
        return v.lower() == "true"

    name = attr("name")
    if not name:
        return None

    intent_filters = _parse_intent_filters(elem)
    has_filter = len(intent_filters) > 0

    declared_exported = bool_attr("exported")
    implicit = False

    if declared_exported is None and has_filter:
        sdk = target_sdk or 31
        if sdk <= IMPLICIT_EXPORT_MAX_SDK:
            implicit = True

    effective = declared_exported if declared_exported is not None else implicit

    exported_status = ExportedStatus(
        declared=declared_exported,
        implicit_from_intent_filter=implicit,
        effective=effective,
    )

    provider_specific = None
    if comp_type == "provider":
        provider_specific = _parse_provider_specific(elem)

    xpath = build_xpath(elem, tree)

    return ComponentRecord(
        id=next_id(job_id, "cmp"),
        type=comp_type,
        name=name,
        exported=exported_status,
        enabled=bool_attr("enabled") if bool_attr("enabled") is not None else True,
        permission=attr("permission"),
        launch_mode=attr("launchMode"),
        task_affinity=attr("taskAffinity"),
        process=attr("process"),
        intent_filters=intent_filters,
        meta_data=[],
        provider_specific=provider_specific,
        confidence=1.0,
        related_ids=[],
        source=Source(
            artifact="manifest",
            path=_rel(manifest_path, base_path),
            xpath=xpath,
            extractor=EXTRACTOR,
            tool=TOOL,
        ),
    )


def _parse_intent_filters(elem: ET.Element) -> list[IntentFilter]:
    filters = []
    for f in elem.findall("intent-filter"):
        actions = [
            e.get(f"{{{NS}}}name", "")
            for e in f.findall("action")
        ]
        categories = [
            e.get(f"{{{NS}}}name", "")
            for e in f.findall("category")
        ]
        data_entries = [_parse_data(d) for d in f.findall("data")]
        auto_verify = f.get(f"{{{NS}}}autoVerify", "false").lower() == "true"
        priority = int(f.get(f"{{{NS}}}priority", "0") or "0")

        filters.append(IntentFilter(
            actions=actions,
            categories=categories,
            data=data_entries,
            auto_verify=auto_verify,
            priority=priority,
        ))
    return filters


def _parse_data(elem: ET.Element) -> IntentFilterData:
    def attr(name: str) -> str | None:
        return elem.get(f"{{{NS}}}{name}")

    return IntentFilterData(
        scheme=attr("scheme"),
        host=attr("host"),
        port=attr("port"),
        path=attr("path"),
        path_pattern=attr("pathPattern"),
        path_prefix=attr("pathPrefix"),
        mime_type=attr("mimeType"),
    )


def _parse_provider_specific(elem: ET.Element) -> ProviderSpecific:
    def attr(name: str) -> str | None:
        return elem.get(f"{{{NS}}}{name}")

    raw_authorities = attr("authorities") or ""
    authorities = [a.strip() for a in raw_authorities.split(";") if a.strip()]

    grant_uri = (attr("grantUriPermissions") or "false").lower() == "true"

    path_permissions = []
    for pp in elem.findall("path-permission"):
        def ppattr(name: str) -> str | None:
            return pp.get(f"{{{NS}}}{name}")

        path_permissions.append(PathPermission(
            path=ppattr("path"),
            path_pattern=ppattr("pathPattern"),
            path_prefix=ppattr("pathPrefix"),
            read_permission=ppattr("readPermission"),
            write_permission=ppattr("writePermission"),
        ))

    return ProviderSpecific(
        authorities=authorities,
        read_permission=attr("readPermission"),
        write_permission=attr("writePermission"),
        grant_uri_permissions=grant_uri,
        path_permissions=path_permissions,
    )


def _rel(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return path.name


def _empty(job_id: str) -> ComponentsFile:
    return ComponentsFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=[],
    )