import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path

from ..models import (
    AppContext, AppInfo, AppMetadataFile, Certificate, DexFile,
    GeneratedBy, NativeLibrary, SigningScheme, Source,
)

logger = logging.getLogger(__name__)

EXTRACTOR = "app_metadata_v1"
TOOL = "androguard-4.1.3+apksigner"


def build(
    job_id: str,
    androguard_result,
    apk_path: Path,
    app_category: str = "unknown",
    apksigner_result=None,
) -> AppMetadataFile:
    """
    Build app_metadata.json from Androguard output, with signature data
    sourced from apksigner.

    Args:
        job_id:            Analysis job identifier.
        androguard_result: AndroguardResult from the extraction coordinator.
        apk_path:          Absolute path to the original APK file.
        app_category:      Optional category declared by user at job creation.
                           Defaults to "unknown".
        apksigner_result:  Optional ApksignerResult from the extraction
                           coordinator. When None or unsuccessful, the
                           certificates list is empty and certificates_status
                           is "unavailable".

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
    certificates, certs_status = _build_certificates(apksigner_result)
    signing_schemes = _build_signing_schemes(apksigner_result)
    signatures_verified = _build_signatures_verified(apksigner_result)
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
        signing_schemes=signing_schemes,
        signatures_verified=signatures_verified,
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


def _build_certificates(apksigner_result) -> tuple[list[Certificate], str]:
    """Build the certificates list from apksigner's signer data.

    Returns (certificates, status). Status vocabulary:
      - "extracted":       apksigner ran and reported one or more signers
      - "unsigned":        apksigner ran and reported zero signers
      - "unavailable":     apksigner did not run or failed
      - "extraction_failed": apksigner ran but signer parsing raised

    apksigner replaces Androguard for this field because Androguard's
    certificate extraction was unreliable — empty results even on signed
    APKs in many cases. apksigner is the canonical Android signature
    verification tool and its output is more complete.
    """
    if apksigner_result is None or not apksigner_result.success:
        return [], "unavailable"

    certs: list[Certificate] = []
    try:
        for signer in apksigner_result.signers or []:
            dn = signer.distinguished_name
            certs.append(Certificate(
                signer_index=signer.index,
                distinguished_name=dn,
                sha256_fingerprint=signer.sha256,
                sha1_fingerprint=signer.sha1,
                md5_fingerprint=signer.md5,
                key_algorithm=signer.key_algorithm,
                key_size_bits=signer.key_size_bits,
                public_key_sha256=signer.public_key_sha256,
                public_key_sha1=signer.public_key_sha1,
                public_key_md5=signer.public_key_md5,
                is_debug_cert=_is_debug_cert(dn or ""),
            ))
    except Exception as exc:
        logger.warning("Certificate extraction from apksigner failed: %s", exc)
        return [], "extraction_failed"

    if certs:
        return certs, "extracted"
    return [], "unsigned"


def _build_signing_schemes(apksigner_result) -> list[SigningScheme]:
    """Build the signing_schemes list from apksigner's scheme data.

    Replaces the old flat-dict shape (v1/v2/v3/v4/v1_only booleans,
    sourced from Androguard and consistently wrong) with apksigner's
    list of per-scheme verification results.

    When apksigner is unavailable, returns an empty list — consumers
    should check certificates_status to disambiguate "no signature
    schemes detected" from "apksigner did not run."
    """
    if apksigner_result is None or not apksigner_result.success:
        return []
    return [
        SigningScheme(version=s.version, verified=s.verified)
        for s in apksigner_result.schemes or []
    ]


def _build_signatures_verified(apksigner_result) -> bool | None:
    """Surface apksigner's top-level Verifies / DOES NOT VERIFY verdict.

    Returns True if the APK's overall signature verification passed,
    False if it explicitly failed, None if apksigner did not run or
    the verdict could not be parsed.
    """
    if apksigner_result is None or not apksigner_result.success:
        return None
    return apksigner_result.verified_overall


def _is_debug_cert(distinguished_name: str) -> bool:
    """Heuristically detect Android debug-signing certificates from the
    distinguished name. Android's debug keystore signs all DNs with
    'Android Debug' as the CN.
    """
    debug_markers = ("android debug", "cn=android debug")
    return any(marker in distinguished_name.lower() for marker in debug_markers)


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