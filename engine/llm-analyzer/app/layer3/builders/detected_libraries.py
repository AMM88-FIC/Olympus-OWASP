import ujson
import logging
import re
from datetime import datetime, timezone

from ..helpers.ids import next_id
from ..models import (
    DetectedLibrariesFile, DetectedLibraryRecord, GeneratedBy,
)

logger = logging.getLogger(__name__)

EXTRACTOR = "libscout_consumer_v1"
TOOL = "libscout-2.3.2"

# Regex for "this package name looks obfuscated" — all dot-separated
# components are 3 characters or fewer (e.g. "y0", "aj.a", "bk.cz.q").
# Real obfuscated packages have short opaque names. LibScout sometimes
# cross-matches one named library to another (e.g. "com.google.gson"
# matched as "androidx.palette") with high sim score; those non-obfuscated
# matches are not what we want here. We only care about packages whose
# names themselves indicate obfuscation, because those are the ones
# downstream consumers (e.g. the verdict engine's scope filter) cannot
# otherwise recognize as third-party.
_OBFUSCATED_NAME_RE = re.compile(r"^([a-z0-9]{1,3})(\.[a-z0-9]{1,3})*$")


def build(job_id: str, libscout_result) -> DetectedLibrariesFile:
    """
    Consume LibScout's output and produce the detected_libraries evidence
    file.

    Only obfuscated-package matches are emitted. A package qualifies as
    "obfuscated" when its name is composed of short (<=3 char) components.
    Non-obfuscated matches (e.g. com.facebook.* preserved by ProGuard
    keep-rules) are excluded — those are already recognizable by name and
    do not need an evidence record to map them to a library.

    LibScout's library attribution accuracy is not used as a filter. The
    purpose of this file is to mark "this obfuscated package is a library"
    so downstream consumers can exclude it from proprietary-code scope.
    Whether LibScout correctly identified *which* library is secondary.

    Args:
        job_id:           Analysis job identifier.
        libscout_result:  LibScoutResult from the extraction coordinator.

    Returns:
        Populated DetectedLibrariesFile.
    """
    if not libscout_result.success or not libscout_result.output_json:
        logger.warning(
            "LibScout output unavailable for job %s — skipping detected "
            "libraries build", job_id,
        )
        return _empty(job_id)

    try:
        data =ujson.loads(libscout_result.output_json.read_text(encoding="utf-8"))
    except (OSError, ujson.JSONDecodeError) as exc:
        logger.error(
            "Failed to read LibScout output for job %s: %s", job_id, exc,
        )
        return _empty(job_id)

    raw_matches = data.get("lib_matches") or []
    records: list[DetectedLibraryRecord] = []
    seen_packages: set[str] = set()

    for match in raw_matches:
        package = match.get("libRootPackage") or ""
        if not _is_obfuscated_name(package):
            continue
        # A single obfuscated package can legitimately match multiple
        # library entries (e.g. androidx.X is the rebrand of
        # com.android.support.X — both match the same bytecode). Keep
        # only the first to avoid duplicate records that confuse the
        # downstream consumer.
        if package in seen_packages:
            continue
        seen_packages.add(package)

        records.append(DetectedLibraryRecord(
            id=next_id(job_id, "lib"),
            obfuscated_name=package,
            detected_package=match.get("libName") or "unknown",
            confidence=float(match.get("simScore") or 0.0),
        ))

    return DetectedLibrariesFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=records,
    )


def _is_obfuscated_name(package: str) -> bool:
    """Return True when the package name looks like a ProGuard/R8
    obfuscation result: all dot-separated components are at most 3
    characters of lowercase letters or digits."""
    if not package:
        return False
    return bool(_OBFUSCATED_NAME_RE.match(package))


def _empty(job_id: str) -> DetectedLibrariesFile:
    return DetectedLibrariesFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=[],
    )