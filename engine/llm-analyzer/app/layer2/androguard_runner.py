from asyncio.log import logger
from pathlib import Path
from dataclasses import dataclass, field
from androguard.misc import AnalyzeAPK
import logging

logging.getLogger('androguard').setLevel(logging.CRITICAL)

@dataclass
class AndroguardResult:
    success: bool
    job_id: str
    # App identity
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: str | None = None
    target_sdk: str | None = None
    # Permissions
    declared_permissions: list[str] = field(default_factory=list)
    requested_permissions: list[str] = field(default_factory=list)
    # Components (cross-check against Apktool manifest)
    activities: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    receivers: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    # Code-level facts
    classes: list[str] = field(default_factory=list)
    string_constants: list[str] = field(default_factory=list)
    native_libraries: list[str] = field(default_factory=list)
    # Obfuscation signals
    obfuscation_signals: list[str] = field(default_factory=list)
    # Certificates
    certificates: list[dict] = field(default_factory=list)
    # Call graph: maps caller FQN (Java-style "package.Class.method") to
    # the list of methods it directly invokes. Framework callers (java.*,
    # javax.*, android.*, kotlin.*, androidx.*) are excluded to keep the
    # graph relevant to app-level analysis. Used by L4 find_callers tool
    # to trace reachability between proprietary and third-party code.
    call_graph: dict[str, list[str]] = field(default_factory=dict)
    error: str | None = None


# Short class/method names are a strong ProGuard/R8 signal
_SHORT_NAME_THRESHOLD = 3

def _obfuscation_signals(dx) -> list[str]:
    """
    Heuristic checks for obfuscation. Returns a list of signal strings
    rather than a binary flag — the LLM layer decides severity.
    """
    signals = []
    class_names = [c.name for c in dx.get_classes()]
    total = len(class_names)
    if total == 0:
        return signals

    short = sum(
        1 for name in class_names
        # Strip package path, check the simple class name length
        if len(name.split("/")[-1].rstrip(";")) <= _SHORT_NAME_THRESHOLD
    )
    ratio = short / total
    if ratio > 0.3:
        signals.append(f"short_class_names:{ratio:.0%}_of_{total}_classes")

    # Reflection usage
    reflection_classes = {
        "Ljava/lang/reflect/Method;",
        "Ljava/lang/reflect/Field;",
        "Ljava/lang/Class;",
    }
    uses_reflection = any(
        dx.get_class_analysis(rc) is not None for rc in reflection_classes
    )
    if uses_reflection:
        signals.append("uses_reflection")

    # Dynamic class loading
    dex_loaders = {
        "Ldalvik/system/DexClassLoader;",
        "Ldalvik/system/PathClassLoader;",
        "Ldalvik/system/InMemoryDexClassLoader;",
    }
    uses_dex_loader = any(
        dx.get_class_analysis(dl) is not None for dl in dex_loaders
    )
    if uses_dex_loader:
        signals.append("dynamic_dex_loading")

    return signals


def _cert_info(apk) -> list[dict]:
    """Extract basic certificate metadata from the APK signing block."""
    certs = []
    try:
        for cert in apk.get_certificates():
            certs.append({
                "issuer": str(cert.issuer.human_friendly),
                "subject": str(cert.subject.human_friendly),
                "not_valid_before": str(cert.not_valid_before),
                "not_valid_after": str(cert.not_valid_after),
                "hash_algo": cert.hash_algo,
                "signature_algo": cert.signature_hash_algo,
            })
    except Exception:
        pass
    return certs


# Framework prefixes whose callers are filtered out of the call graph.
# Calls FROM these namespaces are noise for app-level scope decisions
# (every method has java.lang.Object.<init> as a caller; that's useless).
# Calls TO these namespaces are kept — the LLM may want to know that
# proprietary code invokes android.* APIs.
_FRAMEWORK_CALLER_PREFIXES = (
    "java.", "javax.", "android.", "kotlin.", "androidx.",
)


def _dex_class_to_java(dex_class: str) -> str:
    """Convert Androguard's DEX-style class name (e.g. 'Lcom/foo/Bar;')
    to Java-style FQN (e.g. 'com.foo.Bar'). Returns the input unchanged
    if it doesn't match the expected DEX format."""
    if dex_class.startswith("L") and dex_class.endswith(";"):
        return dex_class[1:-1].replace("/", ".")
    return dex_class


def _method_fqn(method) -> str:
    """Build a Java-style 'class.method' FQN for an Androguard method
    object. Uses class.method granularity (no descriptor) — overloaded
    methods collapse into one node. This is intentional: the LLM doesn't
    need to disambiguate overloads to answer 'is this called from
    proprietary code?'"""
    class_name = _dex_class_to_java(method.class_name)
    return f"{class_name}.{method.name}"


def _is_framework_caller(fqn: str) -> bool:
    """True if the given FQN is in a framework namespace that should be
    excluded from the caller graph."""
    return any(fqn.startswith(prefix) for prefix in _FRAMEWORK_CALLER_PREFIXES)


def _extract_call_graph(dx) -> dict[str, list[str]]:
    """Build a caller→callees map from Androguard's xref data.

    For each method defined in the APK (i.e. not external framework
    methods), record the methods it directly calls. We invert this
    later at query time — the navigator's find_callers walks the graph
    backwards to answer 'who calls this?'.

    Returns a dict mapping caller FQN (Java-style 'class.method') to a
    deduplicated list of callee FQNs. Framework callers are excluded;
    framework callees are kept (the LLM may want to see them).
    """
    graph: dict[str, set[str]] = {}

    for method_analysis in dx.get_methods():
        # Skip ExternalMethod — those are framework methods we don't
        # have bytecode for. They appear as callees of internal methods,
        # which is captured below; we just don't iterate them as callers.
        if method_analysis.is_external():
            continue

        method = method_analysis.get_method()
        caller_fqn = _method_fqn(method)

        # Filter out framework-internal callers. Shouldn't happen for
        # internal methods (we already skipped external), but defensive
        # in case of edge cases like synthetic accessor methods.
        if _is_framework_caller(caller_fqn):
            continue

        callees: set[str] = set()
        for _, callee_method, _ in method_analysis.get_xref_to():
            callee_fqn = _method_fqn(callee_method)
            # Skip self-references (recursion) — they add noise without
            # helping reachability analysis.
            if callee_fqn == caller_fqn:
                continue
            callees.add(callee_fqn)

        if callees:
            # Merge with any existing entry — overloaded methods that
            # collapsed to the same FQN end up unioning their callees.
            existing = graph.setdefault(caller_fqn, set())
            existing.update(callees)

    # Convert sets to sorted lists for stable serialization
    return {caller: sorted(callees) for caller, callees in graph.items()}


def _filter_strings(strings: list[str]) -> list[str]:
    """
    Keep string constants that are likely security-relevant:
    URLs, file paths, suspicious keywords, long opaque strings (possible keys).
    Drops very short or purely numeric strings to reduce noise.
    """
    keywords = {
        "http", "https", "ftp", "jdbc",
        "password", "passwd", "secret", "token", "api_key", "apikey",
        "authorization", "bearer",
        "/data/", "/sdcard/", "/proc/",
        "su", "root", "superuser",
        "debug", "test", "staging",
    }
    result = []
    for s in strings:
        sl = s.lower()
        if len(s) < 6:
            continue
        if any(kw in sl for kw in keywords):
            result.append(s)
            continue
        # Long opaque strings — possible hardcoded keys or tokens
        if len(s) > 40 and s.isascii() and not s.isdigit():
            result.append(s)
    return result


def run_androguard(job_id: str, apk_path: Path) -> AndroguardResult:
    """
    Analyze an APK programmatically using Androguard.

    Produces:
      - App identity: package name, version, SDK levels
      - Permissions: declared and requested
      - Component lists (cross-check against Apktool ground truth)
      - All class names in the DEX
      - Filtered string constants (security-relevant subset)
      - Native library names
      - Obfuscation signals
      - Certificate metadata

    Androguard runs in-process (no subprocess) so there is no output directory —
    all data is returned as structured fields on AndroguardResult.

    Args:
        job_id:   Unique identifier for this analysis job.
        apk_path: Absolute path to the APK file.

    Returns:
        AndroguardResult with all extracted facts.
    """
    apk_path = Path(apk_path).resolve()

    try:
        apk, dex_list, dx = AnalyzeAPK(str(apk_path))
    except Exception as e:
        return AndroguardResult(
            success=False,
            job_id=job_id,
            error=f"androguard AnalyzeAPK failed: {e}",
        )

    try:
        # String constants — collected across all DEX files then filtered
        raw_strings: list[str] = []
        for dex in dex_list:
            raw_strings.extend(dex.get_strings())

        return AndroguardResult(
            success=True,
            job_id=job_id,
            package_name=apk.get_package(),
            version_name=apk.get_androidversion_name(),
            version_code=apk.get_androidversion_code(),
            min_sdk=apk.get_min_sdk_version(),
            target_sdk=apk.get_target_sdk_version(),
            declared_permissions=list(apk.get_declared_permissions()),
            requested_permissions=list(apk.get_permissions()),
            activities=list(apk.get_activities()),
            services=list(apk.get_services()),
            receivers=list(apk.get_receivers()),
            providers=list(apk.get_providers()),
            classes=[c.name for c in dx.get_classes()],
            string_constants=_filter_strings(raw_strings),
            native_libraries=list(apk.get_libraries()),
            obfuscation_signals=_obfuscation_signals(dx),
            certificates=_cert_info(apk),
            call_graph=_extract_call_graph(dx),
        )

    except Exception as e:
        return AndroguardResult(
            success=False,
            job_id=job_id,
            error=f"androguard extraction failed: {e}",
        )