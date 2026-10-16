import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from ..helpers.ids import next_id
from ..helpers.snippet import get_snippet_context
from ..helpers.taint import detect_taint_sources
from ..models import (
    CryptoUsageFile, CryptoUsageRecord, GeneratedBy,
    SnippetContext, Source,
)
from ._patterns import (
    CRYPTO_PATTERNS, extract_class_name, current_method, harvest_string_constants,
    iter_java_files, resolve_const_arg,
)

logger = logging.getLogger(__name__)

EXTRACTOR = "crypto_usage_matcher_v1"
TOOL = "androguard-4.1.3+jadx-1.5.5"

_TRANSFORM_RE = re.compile(
    r'^(?P<algo>[A-Z0-9]+)(?:/(?P<mode>[A-Z0-9]+)(?:/(?P<padding>[A-Z0-9]+))?)?$'
)
_HARDCODED_KEY_RE = re.compile(
    r'(?:new\s+SecretKeySpec\s*\(\s*"(?P<k>[^"]+)"|'
    r'getBytes\s*\(\s*\)|"[A-Za-z0-9+/]{16,}"\.getBytes)'
)
_KEY_SIZE_RE = re.compile(r'\.init\s*\(\s*(\d+)\s*\)')
_PROVIDER_RE = re.compile(r'getInstance\s*\([^,]+,\s*"(?P<p>[^"]+)"')


def build(job_id: str, jadx_result) -> CryptoUsageFile:
    """
    Scan JADX Java source for cryptographic API calls and extract structured
    per-usage records with algorithm, mode, padding, key source, and IV source.

    Args:
        job_id:       Analysis job identifier.
        jadx_result:  JadxResult from the extraction coordinator.

    Returns:
        Populated CryptoUsageFile.
    """
    if not jadx_result.success or not jadx_result.source_dir:
        logger.warning("JADX output unavailable for job %s — skipping crypto scan", job_id)
        return _empty(job_id)

    source_dir = jadx_result.source_dir
    records: list[CryptoUsageRecord] = []

    for java_file in iter_java_files(source_dir):
        try:
            _scan_file(job_id, java_file, source_dir, records)
        except Exception as exc:
            logger.debug("Error scanning %s: %s", java_file, exc)

    return CryptoUsageFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=records,
    )


def _scan_file(
    job_id: str,
    java_file: Path,
    source_dir: Path,
    records: list[CryptoUsageRecord],
) -> None:
    try:
        content = java_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    lines = content.splitlines()
    class_name = extract_class_name(java_file, source_dir)
    # Resolved once per file: a transformation may be passed as a named
    # constant declared elsewhere in the same class.
    constants = harvest_string_constants(content)

    for pattern_name, pattern in CRYPTO_PATTERNS:
        for line_idx, line in enumerate(lines):
            m = pattern.search(line)
            if not m:
                continue

            line_no = line_idx + 1
            method = current_method(lines, line_idx)
            ctx = get_snippet_context(java_file, line_no, line_no)
            all_context = ctx["before"] + ctx["after"]

            algo, mode, padding = _parse_transform(
                m, pattern_name, line, constants)

            # A non-literal argument that is NOT a resolvable same-file
            # constant stays unrecorded — exactly the behaviour before
            # constant resolution was added. Library wrappers such as Bouncy
            # Castle's `Cipher.getInstance(str)` take the transformation from
            # their caller, so they are unresolvable at this layer; emitting
            # algorithm-less records for them would add dozens of rows per app
            # that no test case can act on, and would bury the findings that
            # matter. The widened pattern exists to catch CONSTANTS, not to
            # widen what gets reported.
            if algo is None and any(
                m.groupdict().get(k)
                for k in ("transform_expr", "algo_expr", "proto_expr")
            ):
                continue

            key_source = _detect_key_source(lines, line_idx)
            iv_source = _detect_iv_source(lines, line_idx)
            key_size = _detect_key_size(lines, line_idx)
            provider = _detect_provider(line)

            taint = detect_taint_sources(all_context, [None])

            records.append(CryptoUsageRecord(
                id=next_id(job_id, "crypto"),
                api_call=_api_name(pattern_name, m),
                algorithm=algo,
                mode=mode,
                padding=padding,
                key_size_bits=key_size,
                provider=provider,
                iv_source=iv_source,
                key_source=key_source,
                caller_class=class_name,
                caller_method=method,
                snippet=line.strip(),
                snippet_context=SnippetContext(**ctx),
                taint_sources=taint,
                reachable_from=[],
                extraction_track="readable",
                confidence=0.93,
                related_ids=[],
                source=Source(
                    artifact="java",
                    path=str(java_file.relative_to(source_dir.parent)),
                    line_start=line_no,
                    line_end=line_no,
                    extractor=EXTRACTOR,
                    tool="jadx-1.5.5",
                ),
            ))


def _api_name(pattern_name: str, m: re.Match) -> str:
    mapping = {
        "cipher_get_instance": "javax.crypto.Cipher.getInstance",
        "key_generator":       "javax.crypto.KeyGenerator.getInstance",
        "secret_key_spec":     "javax.crypto.spec.SecretKeySpec.<init>",
        "message_digest":      "java.security.MessageDigest.getInstance",
        "secure_random_new":   "java.security.SecureRandom.<init>",
        "secure_random_get":   "java.security.SecureRandom.getInstance",
        "keystore_get":        "java.security.KeyStore.getInstance",
        "key_gen_param":       "android.security.keystore.KeyGenParameterSpec.Builder",
        "ssl_context":         "javax.net.ssl.SSLContext.getInstance",
    }
    return mapping.get(pattern_name, pattern_name)


def _parse_transform(
    m: re.Match,
    pattern_name: str,
    line: str,
    constants: dict[str, str] | None = None,
) -> tuple[str | None, str | None, str | None]:
    """Parse algorithm/mode/padding from a transformation string.

    The transformation may arrive three ways:

      1. a string literal                -> `transform` / `algo` group
      2. a same-file `final String` const -> `*_expr` group, resolved here
      3. anything else (parameter, call)  -> unresolvable; returns all None

    Case 2 is why this takes `constants`. Case 3 returns None for every field
    rather than guessing, which is also what it did before — the difference is
    that case 2 used to fall into case 3 and produce a record with no
    algorithm, or no record at all.
    """
    g = m.groupdict()
    transform = g.get("transform") or g.get("algo") or g.get("proto")

    if not transform:
        expr = (g.get("transform_expr") or g.get("algo_expr")
                or g.get("proto_expr"))
        if expr:
            transform = resolve_const_arg(expr, constants or {})

    if not transform:
        return None, None, None

    tm = _TRANSFORM_RE.match(transform.upper())
    if tm:
        return tm.group("algo"), tm.group("mode"), tm.group("padding")

    return transform.upper(), None, None


def _detect_key_source(lines: list[str], pivot: int) -> str:
    """
    Look in a ±10 line window around the crypto call to infer key origin.
    """
    window = lines[max(0, pivot - 10): pivot + 10]
    combined = "\n".join(window)

    if "KeyStore" in combined or "getSecretKey" in combined:
        return "keystore"
    if _HARDCODED_KEY_RE.search(combined):
        return "hardcoded"
    if "SecretKeyFactory" in combined or "PBKDF" in combined:
        return "derived"
    if "SecureRandom" in combined:
        return "random"
    return "unknown"


def _detect_iv_source(lines: list[str], pivot: int) -> str | None:
    """Infer IV source from the surrounding method context."""
    window = "\n".join(lines[max(0, pivot - 15): pivot + 5])

    if re.search(r'IvParameterSpec\s*\(\s*new\s+byte\s*\[', window):
        return "hardcoded"
    if re.search(r'IvParameterSpec\s*\(\s*iv\s*\)', window) and "SecureRandom" in window:
        return "random"
    if "IvParameterSpec" in window:
        return "unknown"
    return None


def _detect_key_size(lines: list[str], pivot: int) -> int | None:
    window = "\n".join(lines[max(0, pivot - 5): pivot + 10])
    m = _KEY_SIZE_RE.search(window)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            pass
    return None


def _detect_provider(line: str) -> str | None:
    m = _PROVIDER_RE.search(line)
    return m.group("p") if m else None


def _empty(job_id: str) -> CryptoUsageFile:
    return CryptoUsageFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=[],
    )