import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path

from ..models import (
    AppContext, AppInfo, AppMetadataFile, Certificate, DexFile,
    GeneratedBy, NativeLibrary, Source,
)

logger = logging.getLogger(__name__)

EXTRACTOR = "app_metadata_v1"
TOOL = "androguard-4.1.3"


def build(
    job_id: str,
    androguard_result,
    apk_path: Path,
    app_category: str = "unknown",
) -> AppMetadataFile:
    """
    Build app_metadata.json from Androguard output.

    Args:
        job_id:            Analysis job identifier.
        androguard_result: AndroguardResult from the extraction coordinator.
        apk_path:          Absolute path to the original APK file.
        app_category:      Optional category declared by user at job creation.
                           Defaults to "unknown".

    Returns:
        Populated AppMetadataFile ready for serialization.
    """
    ar = androguard_result
    apk_path = Path(apk_path)

    app = AppInfo(
        package_name=ar.package_name or "unknown",
        version_name=ar.version_name,
        version_code=str(ar.version_code) if ar.version_code else None,
        min_sdk=_to_int(ar.min_sdk),
        target_sdk=_to_int(ar.target_sdk),
        compile_sdk=None,
        apk_sha256=_sha256(apk_path),
        apk_size_bytes=apk_path.stat().st_size if apk_path.exists() else None,
    )

    dex_files = _build_dex_files(ar)
    native_libraries = _build_native_libraries(ar)
    certificates, certs_status = _build_certificates(ar)
    extraction_track = _extraction_track(ar)
    app_context = _build_app_context(app_category)

    return AppMetadataFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        app=app,
        dex_files=dex_files,
        native_libraries=native_libraries,
        certificates=certificates,
        certificates_status=certs_status,
        app_context=app_context,
        extraction_track=extraction_track,
        source=Source(
            artifact="manifest",
            path="AndroidManifest.xml",
            extractor=EXTRACTOR,
            tool=TOOL,
        ),
    )


def _to_int(value) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return "unknown"


def _build_dex_files(ar) -> list[DexFile]:
    return [
        DexFile(
            path="classes.dex",
            size_bytes=0,
            class_count=len(ar.classes) if ar.classes else 0,
        )
    ]


def _build_native_libraries(ar) -> list[NativeLibrary]:
    results = []
    for lib in ar.native_libraries or []:
        results.append(
            NativeLibrary(
                name=lib if isinstance(lib, str) else lib.get("name", "unknown"),
                abis=[],
                path=f"lib/{lib}" if isinstance(lib, str) else lib.get("path", ""),
            )
        )
    return results


def _build_certificates(ar) -> tuple[list[Certificate], str]:
    """Return (certificates, status)."""
    if not ar.success:
        return [], "unavailable"

    certs = []
    try:
        for cert in ar.certificates or []:
            certs.append(
                Certificate(
                    issuer=cert.get("issuer", "unknown"),
                    subject=cert.get("subject", "unknown"),
                    not_valid_before=cert.get("not_valid_before"),
                    not_valid_after=cert.get("not_valid_after"),
                    hash_algo=cert.get("hash_algo"),
                    signature_algo=cert.get("signature_algo"),
                    is_debug_cert=_is_debug_cert(cert.get("subject", "")),
                    sha256_fingerprint=None,
                )
            )
        if certs:
            return certs, "extracted"
        return [], "none_found"
    except Exception as exc:
        logger.warning("Certificate extraction failed: %s", exc)
        return [], "extraction_failed"


def _is_debug_cert(subject: str) -> bool:
    debug_markers = ("android debug", "cn=android debug")
    return any(marker in subject.lower() for marker in debug_markers)


def _build_app_context(category: str) -> AppContext:
    valid = {
        "browser", "vpn", "password_manager", "banking", "health",
        "developer_tool", "messaging", "social", "ecommerce",
        "media", "productivity", "game", "generic", "unknown",
    }
    safe_category = category if category in valid else "unknown"
    source = "user_provided" if category in valid and category != "unknown" else "default"
    return AppContext(
        category=safe_category,
        category_source=source,
        interpretation_notes=[],
    )


def _extraction_track(ar) -> str:
    signals = ar.obfuscation_signals or []
    obfuscation_ratio = _short_class_ratio(ar)
    if obfuscation_ratio > 0.3 or "dynamic_dex_loading" in signals:
        return "bytecode"
    return "readable"


def _short_class_ratio(ar) -> float:
    classes = ar.classes or []
    if not classes:
        return 0.0
    short = sum(
        1 for name in classes
        if len(name.split("/")[-1].rstrip(";")) <= 3
    )
    return short / len(classes)