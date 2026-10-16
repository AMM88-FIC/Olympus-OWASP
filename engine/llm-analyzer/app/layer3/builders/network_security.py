import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from ..helpers.ids import next_id
from ..helpers.xpath import build_xpath
from ..models import (
    BaseConfig, CertPin, DebugOverrides, DomainConfigRecord,
    DomainEntry, GeneratedBy, NetworkSecurityFile, PinSet,
    Source, TrustAnchor,
)

logger = logging.getLogger(__name__)

EXTRACTOR = "nsc_parser_v1"
TOOL = "apktool-2.12.1"


def build(job_id: str, apktool_result, manifest_findings=None) -> NetworkSecurityFile:
    """
    Parse the Network Security Configuration XML when present, or infer
    network security posture from manifest flags when absent.

    Args:
        job_id:             Analysis job identifier.
        apktool_result:     ApktoolResult from the extraction coordinator.
        manifest_findings:  Optional ManifestFindingsFile to read flags from
                            when NSC is absent.

    Returns:
        Populated NetworkSecurityFile.
    """
    nsc_path = apktool_result.nsc_path

    if nsc_path and nsc_path.exists():
        return _parse_nsc(job_id, nsc_path, apktool_result.output_dir)

    return _infer_from_manifest(job_id, manifest_findings, apktool_result)


def _parse_nsc(
    job_id: str,
    nsc_path: Path,
    base_path: Path,
) -> NetworkSecurityFile:
    try:
        tree = ET.parse(nsc_path)
    except ET.ParseError as exc:
        logger.error("Failed to parse NSC for job %s: %s", job_id, exc)
        return _empty(job_id, nsc_present=True)

    root = tree.getroot()
    rel_path = _rel(nsc_path, base_path)

    base_config = _parse_base_config(root)
    domain_configs = _parse_domain_configs(job_id, root, tree, rel_path)
    debug_overrides = _parse_debug_overrides(root)

    return NetworkSecurityFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        nsc_present=True,
        nsc_path=rel_path,
        base_config=base_config,
        domain_configs=domain_configs,
        debug_overrides=debug_overrides,
        inferred_from_manifest=False,
    )


def _parse_base_config(root: ET.Element) -> BaseConfig | None:
    bc = root.find("base-config")
    if bc is None:
        return None

    cleartext = bc.get("cleartextTrafficPermitted")
    return BaseConfig(
        cleartext_traffic_permitted=_to_bool(cleartext),
        trust_anchors=_parse_trust_anchors(bc),
    )


def _parse_domain_configs(
    job_id: str,
    root: ET.Element,
    tree: ET.ElementTree,
    rel_path: str,
) -> list[DomainConfigRecord]:
    records = []

    for dc in root.findall("domain-config"):
        domains = [
            DomainEntry(
                name=d.get("name", ""),
                include_subdomains=_to_bool(d.get("includeSubdomains")) or False,
            )
            for d in dc.findall("domain")
        ]

        cleartext = dc.get("cleartextTrafficPermitted")
        trust_anchors = _parse_trust_anchors(dc)
        pin_set = _parse_pin_set(dc)
        xpath = build_xpath(dc, tree)

        records.append(DomainConfigRecord(
            id=next_id(job_id, "nsc"),
            domains=domains,
            cleartext_traffic_permitted=_to_bool(cleartext),
            trust_anchors=trust_anchors,
            pin_set=pin_set,
            confidence=1.0,
            source=Source(
                artifact="nsc_xml",
                path=rel_path,
                xpath=xpath,
                extractor=EXTRACTOR,
                tool=TOOL,
            ),
        ))

    return records


def _parse_debug_overrides(root: ET.Element) -> DebugOverrides:
    do = root.find("debug-overrides")
    if do is None:
        return DebugOverrides(present=False)

    return DebugOverrides(
        present=True,
        trust_anchors=_parse_trust_anchors(do),
    )


def _parse_trust_anchors(parent: ET.Element) -> list[TrustAnchor]:
    anchors = []
    ta_el = parent.find("trust-anchors")
    if ta_el is None:
        return anchors

    for cert in ta_el.findall("certificates"):
        src = cert.get("src", "")
        override = _to_bool(cert.get("overridePins")) or False
        anchors.append(TrustAnchor(src=src, override_pins=override))

    return anchors


def _parse_pin_set(parent: ET.Element) -> PinSet | None:
    ps = parent.find("pin-set")
    if ps is None:
        return None

    expiration = ps.get("expiration")
    pins = []
    for pin in ps.findall("pin"):
        digest = pin.get("digest", "SHA-256")
        value = pin.text or ""
        if value:
            pins.append(CertPin(digest=digest, value=value.strip()))

    return PinSet(expiration=expiration, pins=pins)


def _infer_from_manifest(
    job_id: str,
    manifest_findings,
    apktool_result,
) -> NetworkSecurityFile:
    """
    When no NSC file exists, infer cleartext permissions from manifest flags.
    target_sdk < 28 means cleartext is permitted by default.
    """
    cleartext_permitted = None

    if manifest_findings:
        flags = manifest_findings.flags
        if flags.uses_cleartext_traffic is not None:
            cleartext_permitted = flags.uses_cleartext_traffic

    return NetworkSecurityFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        nsc_present=False,
        nsc_path=None,
        base_config=BaseConfig(
            cleartext_traffic_permitted=cleartext_permitted,
            trust_anchors=[],
        ),
        domain_configs=[],
        debug_overrides=DebugOverrides(present=False),
        inferred_from_manifest=True,
    )


def _to_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    return value.lower() == "true"


def _rel(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return path.name


def _empty(job_id: str, nsc_present: bool = False) -> NetworkSecurityFile:
    return NetworkSecurityFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        nsc_present=nsc_present,
        inferred_from_manifest=not nsc_present,
    )