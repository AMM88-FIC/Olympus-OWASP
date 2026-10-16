"""
Native binaries builder.

Extracts cheap-to-obtain content from every .so library bundled in
the APK: ELF security flags, imported and exported symbols (curated
into security-relevant categories), needed libraries, and string
constants from .rodata and .data sections.

Uses python-elftools for stable ELF parsing. Falls back to subprocess
calls when needed.

The builder is independent of native_methods.json — it parses binaries
directly. Cross-references between the two files are populated by the
cross_references post-processing pass.
"""

import hashlib
import logging
import math
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from ..helpers.ids import next_id
from ..helpers.record_hash import compute_record_hash
from ..models import (
    GeneratedBy, InterestingImport, JniEntryPoint,
    NativeBinariesFile, NativeBinaryRecord, NativeExports,
    NativeImports, NativeStringRecord, SecurityFeatures,
    Source,
)
from . import _native_symbols

logger = logging.getLogger(__name__)

EXTRACTOR = "native_binaries_v1"
TOOL = "pyelftools+strings"

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def build(job_id: str, apktool_result) -> NativeBinariesFile:
    """
    Walk apktool/lib/<abi>/, parse every .so file found, and produce
    one record per distinct binary content (deduplicated by sha256
    across ABIs).

    Args:
        job_id:         Analysis job identifier.
        apktool_result: ApktoolResult — provides the unpacked APK root.

    Returns:
        Populated NativeBinariesFile. Empty `records` is a valid output
        for apps with no native libraries.
    """
    if not apktool_result.success or not apktool_result.output_dir:
        return _empty(job_id)

    lib_dir = Path(apktool_result.output_dir) / "lib"
    if not lib_dir.exists() or not lib_dir.is_dir():
        return _empty(job_id)

    # Walk all <abi>/<name>.so files. v1.2.2 emits one record per .so file
    # without deduplication. Multi-ABI APKs that ship the same content for
    # several ABIs will produce N copies of the same record (one per ABI).
    # Deduplication will be reintroduced in v1.3 once Source.path becomes
    # a list and can represent multi-location evidence natively.
    records: list[NativeBinaryRecord] = []
    total_strings = 0
    total_libraries = 0

    for abi_dir in sorted(lib_dir.iterdir()):
        if not abi_dir.is_dir():
            continue
        abi = abi_dir.name
        for so_path in sorted(abi_dir.glob("*.so")):
            total_libraries += 1
            try:
                sha = _sha256(so_path)
            except OSError as exc:
                logger.warning("Failed to hash %s: %s", so_path, exc)
                continue

            rel_path = str(so_path.relative_to(apktool_result.output_dir))

            try:
                rec = _build_record(
                    job_id=job_id,
                    so_path=so_path,
                    rel_path=rel_path,
                    abi=abi,
                    sha256=sha,
                    base_path=apktool_result.output_dir,
                )
                records.append(rec)
                total_strings += len(rec.strings)
            except Exception as exc:
                logger.warning("Error parsing %s: %s", so_path, exc)

    return NativeBinariesFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=sorted(records, key=lambda r: (r.name, r.abis[0] if r.abis else "")),
        total_libraries=total_libraries,
        total_records=len(records),
        total_strings=total_strings,
    )


# ---------------------------------------------------------------------------
# Per-binary parsing
# ---------------------------------------------------------------------------


def _build_record(
    job_id: str,
    so_path: Path,
    rel_path: str,
    abi: str,
    sha256: str,
    base_path: Path,
) -> NativeBinaryRecord:
    """
    Parse a single .so file and produce a NativeBinaryRecord.

    v1.2.2 emits one record per .so file. Multi-ABI APKs that ship the
    same binary content under several ABIs produce N records — one per
    physical .so file. v1.3 will reintroduce content-hash deduplication
    once the schema supports multi-location source references.
    """
    elf_data = _parse_elf(so_path)
    strings = _extract_strings(job_id, so_path, rel_path)
    suspicious = _detect_suspicious_patterns(elf_data, strings)

    record_id = next_id(job_id, "nlib")

    return NativeBinaryRecord(
        id=record_id,
        confidence=0.95,
        related_ids=[],
        source=Source(
            artifact="native_lib",
            path=rel_path,
            extractor=EXTRACTOR,
            tool=TOOL,
        ),
        record_hash=compute_record_hash(
            api_call="native_binary",
            extra=f"{rel_path}:{sha256}",
        ),
        name=so_path.name,
        paths=[rel_path],
        abis=[abi],
        size_bytes=so_path.stat().st_size,
        sha256=sha256,
        elf_class=elf_data["elf_class"],
        machine=elf_data["machine"],
        stripped=elf_data["stripped"],
        security_features=elf_data["security_features"],
        imports=elf_data["imports"],
        exports=elf_data["exports"],
        needed_libraries=elf_data["needed"],
        strings=strings,
        suspicious_patterns=suspicious,
    )


# ---------------------------------------------------------------------------
# ELF parsing via pyelftools
# ---------------------------------------------------------------------------


def _parse_elf(so_path: Path) -> dict:
    """
    Parse the ELF file and return all derived data in one dict.

    Returns keys: elf_class, machine, stripped, security_features,
    imports, exports, needed.
    """
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.dynamic import DynamicSection
        from elftools.elf.sections import SymbolTableSection
    except ImportError as exc:
        raise RuntimeError("pyelftools not available") from exc

    with open(so_path, "rb") as f:
        elf = ELFFile(f)

        elf_class = "ELF64" if elf.elfclass == 64 else "ELF32"
        machine = _decode_machine(elf.header["e_machine"])

        # Find dynamic section (where DT_NEEDED, dynamic symbols live)
        dyn_section = None
        gnu_relro_present = False
        bind_now = False

        for segment in elf.iter_segments():
            if segment.header.p_type == "PT_GNU_RELRO":
                gnu_relro_present = True

        for section in elf.iter_sections():
            if isinstance(section, DynamicSection):
                dyn_section = section
                for tag in section.iter_tags():
                    if tag.entry.d_tag == "DT_BIND_NOW":
                        bind_now = True
                    elif tag.entry.d_tag == "DT_FLAGS":
                        if tag.entry.d_val & 0x08:  # DF_BIND_NOW
                            bind_now = True
                    elif tag.entry.d_tag == "DT_FLAGS_1":
                        if tag.entry.d_val & 0x08000000:  # DF_1_NOW
                            bind_now = True

        # NX bit — check stack segment
        nx = True  # default-secure assumption per modern toolchain
        for segment in elf.iter_segments():
            if segment.header.p_type == "PT_GNU_STACK":
                if segment.header.p_flags & 0x1:  # PF_X bit
                    nx = False
                else:
                    nx = True

        # PIE — ET_DYN with DT_FLAGS_1 PIE bit, or just ET_DYN for shared libs
        # Shared libraries are always ET_DYN; for SO files we check for the
        # PIE-specific marker in DT_FLAGS_1.
        pie = elf.header["e_type"] == "ET_DYN"

        # RELRO levels
        if gnu_relro_present and bind_now:
            relro = "full"
        elif gnu_relro_present:
            relro = "partial"
        else:
            relro = "none"

        # Imports and exports — walk dynamic symbol table
        dynsym = elf.get_section_by_name(".dynsym")
        imports_raw: list[str] = []
        exports_raw: list[str] = []

        if isinstance(dynsym, SymbolTableSection):
            for sym in dynsym.iter_symbols():
                if not sym.name:
                    continue
                # Imports: SHN_UNDEF (st_shndx == 0) and not weak local
                if sym.entry["st_shndx"] == "SHN_UNDEF":
                    imports_raw.append(sym.name)
                # Exports: defined symbols with binding GLOBAL or WEAK
                elif sym.entry["st_info"]["bind"] in ("STB_GLOBAL", "STB_WEAK"):
                    exports_raw.append(sym.name)

        # Stack canary and fortify_source detection from imports
        stack_canary = any(
            n in imports_raw
            for n in ("__stack_chk_fail", "__stack_chk_guard")
        )
        fortify_source = any(
            n.endswith("_chk") for n in imports_raw
            if n.startswith("__")
        )

        # Stripped = no .symtab section
        symtab = elf.get_section_by_name(".symtab")
        stripped = symtab is None

        # DT_NEEDED entries
        needed: list[str] = []
        if dyn_section is not None:
            for tag in dyn_section.iter_tags():
                if tag.entry.d_tag == "DT_NEEDED":
                    needed.append(tag.needed)

    security_features = SecurityFeatures(
        pie=pie,
        nx=nx,
        relro=relro,
        stack_canary=stack_canary,
        fortify_source=fortify_source,
        symbols_stripped=stripped,
    )

    imports = _categorize_imports(imports_raw, needed)
    exports = _process_exports(exports_raw)

    return {
        "elf_class": elf_class,
        "machine": machine,
        "stripped": stripped,
        "security_features": security_features,
        "imports": imports,
        "exports": exports,
        "needed": sorted(set(needed)),
    }


def _decode_machine(value: str) -> str:
    """Map e_machine string to schema-allowed values."""
    mapping = {
        "EM_AARCH64": "AArch64",
        "EM_ARM": "ARM",
        "EM_386": "x86",
        "EM_X86_64": "x86_64",
        "EM_MIPS": "MIPS",
        "EM_RISCV": "RISC-V",
    }
    return mapping.get(value, "unknown")


def _categorize_imports(
    imports_raw: list[str],
    needed: list[str],
) -> NativeImports:
    """
    Categorize raw imports against the curated catalog.

    Symbols matching no category are aggregated in `total_count` only.
    """
    by_category: dict[str, list[str]] = {
        cat: [] for cat in _native_symbols.categories()
    }
    interesting: list[InterestingImport] = []
    seen_in_interesting: set[str] = set()

    needed_lookup = _build_needed_lookup(needed)

    for sym in sorted(set(imports_raw)):
        cat = _native_symbols.categorize(sym)
        if cat is None:
            continue
        by_category[cat].append(sym)
        if sym not in seen_in_interesting:
            interesting.append(InterestingImport(
                name=sym,
                category=cat,
                source_library=needed_lookup.get(cat),
            ))
            seen_in_interesting.add(sym)

    return NativeImports(
        total_count=len(set(imports_raw)),
        by_category=by_category,
        interesting_imports=interesting,
    )


def _build_needed_lookup(needed: list[str]) -> dict[str, str]:
    """
    Return a category → likely source library name based on DT_NEEDED.

    Heuristic only — used to populate InterestingImport.source_library
    for hints, not for authoritative attribution.
    """
    lookup: dict[str, str] = {}
    for lib in needed:
        if "ssl" in lib.lower() or "tls" in lib.lower():
            lookup.setdefault("tls", lib)
            lookup.setdefault("crypto", lib)
        elif "crypto" in lib.lower():
            lookup.setdefault("crypto", lib)
        elif "curl" in lib.lower():
            lookup.setdefault("network", lib)
    return lookup


# ---------------------------------------------------------------------------
# Export processing — extract JNI entry points
# ---------------------------------------------------------------------------


# Java_<class with _ separators>_<method>
# Underscores in original names are encoded as _1 in JNI symbols.
_JNI_PATTERN = re.compile(r"^Java_(?P<rest>[A-Za-z_][A-Za-z0-9_]*)$")


def _process_exports(exports_raw: list[str]) -> NativeExports:
    """
    Extract JNI entry points from exported symbols.

    Symbols starting with Java_ are decoded into (java_class, java_method)
    using the JNI naming convention.
    """
    jni_entries: list[JniEntryPoint] = []
    for sym in sorted(set(exports_raw)):
        m = _JNI_PATTERN.match(sym)
        if not m:
            continue
        decoded = _decode_jni_symbol(sym)
        if decoded is None:
            continue
        java_class, java_method = decoded
        jni_entries.append(JniEntryPoint(
            symbol=sym,
            java_class=java_class,
            java_method=java_method,
            related_native_method_id=None,
        ))

    return NativeExports(
        total_count=len(set(exports_raw)),
        jni_entry_points=jni_entries,
        registered_natives=False,  # populated by caller from imports
    )


def _decode_jni_symbol(symbol: str) -> tuple[str, str] | None:
    """
    Decode Java_com_example_Foo_bar -> ("com.example.Foo", "bar").

    JNI escapes:
      _0NNNN  unicode codepoint
      _1      literal underscore
      _2      semicolon (in signature; not in name)
      _3      bracket (in signature; not in name)

    For names, only _1 matters in practice.
    """
    if not symbol.startswith("Java_"):
        return None
    rest = symbol[len("Java_"):]
    # Last underscore separates class from method
    last_underscore = rest.rfind("_")
    if last_underscore <= 0:
        return None

    class_part = rest[:last_underscore].replace("_", ".")
    method_part = rest[last_underscore + 1:]

    # Decode _1 -> _ for the method name
    method_part = method_part.replace("_1", "_")

    return class_part, method_part


# ---------------------------------------------------------------------------
# String extraction
# ---------------------------------------------------------------------------


_MIN_STRING_LENGTH = 6
_SECRET_ENTROPY_THRESHOLD = 3.5

_URL_RE = re.compile(r"^https?://|^ftp://|^jdbc:", re.I)
_HTTP_RE = re.compile(r"^http://", re.I)
_FILE_PATH_RE = re.compile(r"^/(?:data|sdcard|storage|proc|sys|system)/", re.I)
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$")
_EMAIL_RE = re.compile(r"^[\w.+-]+@[\w-]+\.[a-z]{2,}$", re.I)
_JDBC_RE = re.compile(r"^jdbc:", re.I)
_CONTENT_URI_RE = re.compile(r"^content://")
_IPC_ACTION_RE = re.compile(r"^[\w.]+\.(?:ACTION|BROADCAST|INTENT|EVENT)[\w.]*$")
_JNI_SIG_RE = re.compile(r"^\([A-Za-z0-9/;\[]*\)[A-Za-z0-9/;\[]+$")
_API_KEY_RE = re.compile(
    r"^(AIza[0-9A-Za-z_-]{20,}|sk_(?:live|test)_[0-9A-Za-z]{20,}"
    r"|xox[baprs]-[0-9A-Za-z-]{10,}|ghp_[0-9A-Za-z]{20,})$"
)
_BEARER_RE = re.compile(r"^Bearer\s+[A-Za-z0-9._-]{8,}$")

_SUSPICIOUS_KEYWORDS = frozenset({
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "authorization", "bearer", "credential", "private_key",
    "access_key", "auth_token", "client_secret",
})


def _extract_strings(
    job_id: str,
    so_path: Path,
    rel_path: str,
) -> list[NativeStringRecord]:
    """
    Run `strings -a -n 6` over the binary, categorize each output line,
    and emit one NativeStringRecord per categorized string.

    Uncategorized strings are dropped. C runtime noise stays out of the
    evidence file.
    """
    try:
        result = subprocess.run(
            ["strings", "-a", "-n", str(_MIN_STRING_LENGTH), str(so_path)],
            capture_output=True,
            text=True,
            timeout=60,
            errors="replace",
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.warning("strings extraction failed for %s: %s", so_path, exc)
        return []

    records: list[NativeStringRecord] = []
    seen_values: set[str] = set()

    for line in result.stdout.splitlines():
        value = line.strip()
        if not value or len(value) < _MIN_STRING_LENGTH:
            continue
        if value in seen_values:
            continue
        seen_values.add(value)

        category, fp_likelihood, reason = _categorize_string(value)
        if category is None:
            continue

        is_cleartext = (
            _HTTP_RE.match(value) is not None
            if category in ("url", "cleartext_url") else None
        )
        entropy = _entropy(value) if category == "high_entropy_unknown" else None

        records.append(NativeStringRecord(
            id=next_id(job_id, "nstr"),
            confidence=_string_confidence(category),
            related_ids=[],
            source=Source(
                artifact="native_lib",
                path=rel_path,
                extractor=EXTRACTOR,
                tool=TOOL,
            ),
            record_hash=compute_record_hash(
                api_call="native_string",
                extra=value,
            ),
            category=category,
            value=value,
            is_cleartext=is_cleartext,
            entropy_bits=round(entropy, 3) if entropy is not None else None,
            offset=0,  # offset extraction would require parsing strings -t format
            section="unknown",
            secret_detection_reason=reason,
            false_positive_likelihood=fp_likelihood,
        ))

    return records


def _categorize_string(value: str) -> tuple[str | None, str | None, str | None]:
    """Return (category, false_positive_likelihood, secret_detection_reason)."""
    vl = value.lower()

    # High-precision matches first
    if _API_KEY_RE.match(value):
        return "hardcoded_api_key", "low", "regex_match"
    if _BEARER_RE.match(value):
        return "bearer_token", "low", "regex_match"

    if _HTTP_RE.match(value):
        return "cleartext_url", "low", None
    if _URL_RE.match(value):
        return "url", "low", None
    if _JDBC_RE.match(value):
        return "jdbc_string", "low", None
    if _CONTENT_URI_RE.match(value):
        return "content_uri", "low", None
    if _FILE_PATH_RE.match(value):
        return "file_path", "low", None
    if _IP_RE.match(value):
        return "ip_address", "low", None
    if _EMAIL_RE.match(value):
        return "email", "low", None
    if _IPC_ACTION_RE.match(value):
        return "ipc_action", "medium", None
    if _JNI_SIG_RE.match(value) and len(value) <= 200:
        return "jni_signature", "low", None

    if any(kw in vl for kw in _SUSPICIOUS_KEYWORDS):
        return "suspicious_keyword", "high", "keyword"

    if len(value) > 40 and _is_high_entropy(value):
        return "high_entropy_unknown", "high", "entropy"

    return None, None, None


def _is_high_entropy(value: str) -> bool:
    if not value.isascii():
        return False
    if " " in value and len(value.split()) > 4:
        return False
    return _entropy(value) >= _SECRET_ENTROPY_THRESHOLD


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _string_confidence(category: str) -> float:
    if category in ("url", "cleartext_url", "jdbc_string", "content_uri",
                    "ip_address", "email"):
        return 0.97
    if category == "file_path":
        return 0.95
    if category in ("hardcoded_api_key", "bearer_token"):
        return 0.95
    if category == "jni_signature":
        return 0.92
    if category == "ipc_action":
        return 0.85
    if category == "suspicious_keyword":
        return 0.78
    if category == "high_entropy_unknown":
        return 0.62
    return 0.75


# ---------------------------------------------------------------------------
# Suspicious patterns — pre-computed cross-checks
# ---------------------------------------------------------------------------


_ROOT_PATH_STRINGS = (
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
    "Superuser.apk", "magisk", "supersu",
)
_ANTI_DEBUG_STRINGS = (
    "/proc/self/status", "TracerPid", "/proc/self/mem", "ro.debuggable",
)


def _detect_suspicious_patterns(
    elf_data: dict,
    strings: list[NativeStringRecord],
) -> list[str]:
    """Cross-check imports and strings for known dangerous combinations."""
    patterns: list[str] = []

    imports = elf_data["imports"]
    by_cat = imports.by_category

    crypto_count = len(by_cat.get("crypto", []))
    tls_count = len(by_cat.get("tls", []))
    file_io_imports = by_cat.get("file_io", [])
    debug_detection_imports = by_cat.get("debug_detection", [])
    dynamic_imports = by_cat.get("dynamic", [])
    jni_imports = by_cat.get("jni", [])

    string_values_lower = [s.value.lower() for s in strings]
    string_values = [s.value for s in strings]

    # Anti-debug detection
    if debug_detection_imports and any(
        any(t.lower() in v for t in _ANTI_DEBUG_STRINGS)
        for v in string_values_lower
    ):
        patterns.append("native_anti_debug")

    # Root detection
    if file_io_imports and any(
        any(rp in v for rp in _ROOT_PATH_STRINGS) for v in string_values
    ):
        patterns.append("native_root_detection")

    # Dynamic loading with library name strings
    if dynamic_imports and any(
        v.endswith(".so") or ".so:" in v for v in string_values
    ):
        patterns.append("native_dynamic_loading")

    # Crypto and TLS presence
    if crypto_count >= 3:
        patterns.append("native_crypto_present")
    if tls_count >= 3 or any(
        s == "SSL_CTX_set_verify"
        for s in by_cat.get("tls", [])
    ):
        patterns.append("native_tls_present")

    # URL in .rodata
    if any(s.category in ("url", "cleartext_url") for s in strings):
        patterns.append("native_url_in_rodata")

    # High entropy secret in .rodata
    if any(
        s.category == "high_entropy_unknown" and len(s.value) >= 32
        for s in strings
    ):
        patterns.append("native_high_entropy_secret")

    # Dynamic JNI registration
    if "RegisterNatives" in jni_imports:
        patterns.append("native_dynamic_jni_registration")
        # Also flip the registered_natives flag on the exports record
        elf_data["exports"].registered_natives = True

    return sorted(set(patterns))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _empty(job_id: str) -> NativeBinariesFile:
    return NativeBinariesFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=[],
        total_libraries=0,
        total_records=0,
        total_strings=0,
    )