import logging
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from ..helpers.ids import next_id
from ..models import (
    GeneratedBy, JavaCaller, NativeMethodRecord,
    NativeMethodsFile, Source,
)
from ._patterns import extract_class_name, iter_java_files

logger = logging.getLogger(__name__)

EXTRACTOR = "jni_bridge_mapper_v1"
TOOL = "androguard-4.1.3+jadx-1.5.5"

_NATIVE_METHOD_RE = re.compile(
    r'(?:public|private|protected|)\s*(?:static\s+)?native\s+'
    r'(?P<ret>[\w\[\]<>]+)\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)'
)
_REGISTER_NATIVES_RE = re.compile(r'RegisterNatives\s*\(')


def build(job_id: str, jadx_result, apktool_result) -> NativeMethodsFile:
    """
    Map the JNI bridge by finding Java `native` method declarations
    and correlating them with exported symbols in bundled .so libraries.

    For each native method:
    - Computes the expected JNI symbol name (Java_<class>_<method> convention)
    - Checks whether that symbol exists in any bundled .so (via `nm -D`)
    - Flags methods registered via RegisterNatives (dynamic binding)

    Args:
        job_id:          Analysis job identifier.
        jadx_result:     JadxResult from the extraction coordinator.
        apktool_result:  ApktoolResult — provides paths to .so files.

    Returns:
        Populated NativeMethodsFile.
    """
    records: list[NativeMethodRecord] = []

    if not jadx_result.success or not jadx_result.source_dir:
        logger.warning("JADX unavailable for job %s — skipping JNI mapping", job_id)
        return _empty(job_id)

    source_dir = jadx_result.source_dir
    so_symbols = _collect_so_symbols(apktool_result)

    for java_file in iter_java_files(source_dir):
        try:
            _scan_file(job_id, java_file, source_dir, so_symbols, records)
        except Exception as exc:
            logger.debug("Error scanning %s for native methods: %s", java_file, exc)

    return NativeMethodsFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=records,
    )


def _scan_file(
    job_id: str,
    java_file: Path,
    source_dir: Path,
    so_symbols: dict[str, str],
    records: list[NativeMethodRecord],
) -> None:
    try:
        content = java_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    if "native " not in content:
        return

    lines = content.splitlines()
    class_name = extract_class_name(java_file, source_dir)
    uses_register_natives = bool(_REGISTER_NATIVES_RE.search(content))

    for line_idx, line in enumerate(lines):
        m = _NATIVE_METHOD_RE.search(line)
        if not m:
            continue

        method_name = m.group("name")
        params = m.group("params").strip()
        modifiers = _extract_modifiers(line)
        jni_symbol = _build_jni_symbol(class_name, method_name)
        found_lib, symbol_type = _find_symbol(jni_symbol, so_symbols)

        records.append(NativeMethodRecord(
            id=next_id(job_id, "jni"),
            java_class=class_name,
            java_method=method_name,
            java_signature=_build_descriptor(params, m.group("ret")),
            java_modifiers=modifiers,
            expected_jni_symbol=jni_symbol,
            found_in_library=found_lib,
            library_path=so_symbols.get(found_lib + ":path") if found_lib else None,
            symbol_present=found_lib is not None,
            symbol_type=symbol_type,
            registered_dynamically=uses_register_natives,
            register_natives_location=None,
            java_callers=[],
            reachable_from=[],
            confidence=0.88,
            related_ids=[],
            source=Source(
                artifact="java",
                path=str(java_file.relative_to(source_dir.parent)),
                line_start=line_idx + 1,
                line_end=line_idx + 1,
                extractor=EXTRACTOR,
                tool="jadx-1.5.5",
            ),
        ))


def _collect_so_symbols(apktool_result) -> dict[str, str]:
    """
    Run `nm -D` on each .so in the APK lib/ directory.
    Returns a dict mapping {symbol_name: lib_name}.
    """
    symbols: dict[str, str] = {}
    lib_dir = apktool_result.output_dir / "lib"
    if not lib_dir.exists():
        return symbols

    for so_file in sorted(lib_dir.rglob("*.so")):
        try:
            result = subprocess.run(
                ["nm", "-D", str(so_file)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    sym_name = parts[-1]
                    sym_type = parts[-2]
                    symbols[sym_name] = so_file.name
                    symbols[so_file.name + ":path"] = str(so_file)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            logger.debug("nm not available or failed for %s", so_file)

    return symbols


def _find_symbol(
    jni_symbol: str,
    so_symbols: dict[str, str],
) -> tuple[str | None, str | None]:
    lib = so_symbols.get(jni_symbol)
    if lib:
        # Try to get the symbol type from nm output (T = global text)
        return lib, "T"
    return None, None


def _build_jni_symbol(class_name: str, method_name: str) -> str:
    """
    Compute the expected JNI symbol using the naming convention:
    Java_<class_with_underscores>_<method>
    e.g. com.example.Crypto.encrypt → Java_com_example_Crypto_encrypt
    """
    safe_class = class_name.replace(".", "_").replace("$", "_")
    safe_method = method_name.replace("_", "_1")
    return f"Java_{safe_class}_{safe_method}"


def _build_descriptor(params: str, return_type: str) -> str | None:
    """Best-effort Java method descriptor. Returns None if params are complex."""
    if not params.strip():
        return f"(){_type_to_descriptor(return_type)}"
    return None


def _type_to_descriptor(java_type: str) -> str:
    mapping = {
        "void": "V", "boolean": "Z", "byte": "B", "char": "C",
        "short": "S", "int": "I", "long": "J", "float": "F",
        "double": "D", "String": "Ljava/lang/String;",
        "byte[]": "[B", "String[]": "[Ljava/lang/String;",
    }
    return mapping.get(java_type.strip(), "Ljava/lang/Object;")


def _extract_modifiers(line: str) -> list[str]:
    modifiers = []
    for mod in ("public", "private", "protected", "static", "final", "native", "synchronized"):
        if re.search(rf'\b{mod}\b', line):
            modifiers.append(mod)
    return modifiers


def _empty(job_id: str) -> NativeMethodsFile:
    return NativeMethodsFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=[],
    )