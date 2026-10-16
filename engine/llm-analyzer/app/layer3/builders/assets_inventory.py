import hashlib
import logging
import mimetypes
from datetime import datetime, timezone
from pathlib import Path

from ..helpers.ids import next_id
from ..models import AssetRecord, AssetsInventoryFile, GeneratedBy, Source

logger = logging.getLogger(__name__)

EXTRACTOR = "assets_scanner_v1"
TOOL = "apktool-2.12.1"

_SENSITIVE_KEYWORDS = frozenset({
    "api_key", "apikey", "secret", "password", "token",
    "private_key", "credential", "auth",
})

_KIND_MAP: dict[str, str] = {
    ".json":  "config",
    ".xml":   "config",
    ".yaml":  "config",
    ".yml":   "config",
    ".properties": "config",
    ".pem":   "certificate",
    ".cer":   "certificate",
    ".crt":   "certificate",
    ".der":   "certificate",
    ".bks":   "certificate_store",
    ".jks":   "certificate_store",
    ".p12":   "certificate_store",
    ".pfx":   "certificate_store",
    ".db":    "database",
    ".sqlite": "database",
    ".js":    "javascript",
    ".html":  "html",
    ".htm":   "html",
    ".key":   "private_key",
}

# Text-based extensions where we scan for sensitive keywords
_TEXT_EXTENSIONS = frozenset({
    ".json", ".xml", ".yaml", ".yml", ".properties",
    ".txt", ".html", ".htm", ".js", ".pem", ".cer", ".crt",
})


def build(job_id: str, apktool_result, network_security_file=None) -> AssetsInventoryFile:
    """
    Inventory all files in assets/ and res/raw/ from the Apktool output.

    Args:
        job_id:                Analysis job identifier.
        apktool_result:        ApktoolResult from the extraction coordinator.
        network_security_file: Optional NetworkSecurityFile to cross-reference
                               trust anchor resource refs against asset paths.

    Returns:
        Populated AssetsInventoryFile.
    """
    records: list[AssetRecord] = []

    nsc_refs = _collect_nsc_refs(network_security_file)

    for directory, artifact_type in [
        (apktool_result.assets_dir, "asset"),
        (_res_raw_dir(apktool_result), "resource"),
    ]:
        if not directory or not directory.exists():
            continue
        _scan_directory(job_id, directory, artifact_type, apktool_result.output_dir, nsc_refs, records)

    return AssetsInventoryFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=records,
    )


def _scan_directory(
    job_id: str,
    directory: Path,
    artifact_type: str,
    base_path: Path,
    nsc_refs: set[str],
    records: list[AssetRecord],
) -> None:
    for file_path in sorted(directory.rglob("*")):
        if not file_path.is_file():
            continue

        rel_path = _rel(file_path, base_path)
        ext = file_path.suffix.lower()
        kind = _KIND_MAP.get(ext, "other")
        sensitive_keys = _scan_sensitive_keys(file_path, ext)
        referenced_by_nsc = _is_nsc_referenced(rel_path, nsc_refs)

        records.append(AssetRecord(
            id=next_id(job_id, "asset"),
            path=rel_path,
            size_bytes=file_path.stat().st_size,
            sha256=_sha256(file_path),
            mime_type=mimetypes.guess_type(str(file_path))[0],
            kind=kind,
            extension=ext.lstrip(".") or None,
            contains_sensitive_keys_heuristic=sensitive_keys,
            referenced_by_nsc=referenced_by_nsc,
            confidence=0.95,
            related_ids=[],
            source=Source(
                artifact=artifact_type,
                path=rel_path,
                extractor=EXTRACTOR,
                tool=TOOL,
            ),
        ))


def _scan_sensitive_keys(file_path: Path, ext: str) -> list[str]:
    if ext not in _TEXT_EXTENSIONS:
        return []
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace").lower()
        return [kw for kw in _SENSITIVE_KEYWORDS if kw in content]
    except OSError:
        return []


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return "unknown"


def _collect_nsc_refs(network_security_file) -> set[str]:
    """Collect all @raw/ trust anchor references from the NSC evidence."""
    refs: set[str] = set()
    if not network_security_file:
        return refs
    for dc in network_security_file.domain_configs:
        for ta in dc.trust_anchors:
            if ta.src and ta.src.startswith("@raw/"):
                refs.add(ta.src.replace("@raw/", "res/raw/"))
    if network_security_file.base_config:
        for ta in network_security_file.base_config.trust_anchors:
            if ta.src and ta.src.startswith("@raw/"):
                refs.add(ta.src.replace("@raw/", "res/raw/"))
    return refs


def _is_nsc_referenced(rel_path: str, nsc_refs: set[str]) -> bool:
    return any(rel_path.endswith(ref.split("/")[-1]) for ref in nsc_refs)


def _res_raw_dir(apktool_result) -> Path | None:
    if apktool_result.res_dir and apktool_result.res_dir.exists():
        raw = apktool_result.res_dir / "raw"
        return raw if raw.exists() else None
    return None


def _rel(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)