import re

# Package prefixes considered third-party or generated
_SDK_PREFIXES = (
    "com.google.android.gms", "com.google.firebase",
    "com.facebook", "com.adjust", "com.appsflyer",
    "io.branch", "com.mixpanel", "com.amplitude",
    "com.stripe", "com.braintreepayments",
    "okhttp3", "retrofit2", "com.bumptech.glide",
    "com.squareup", "dagger", "io.sentry",
    "com.bugsnag", "io.intercom", "zendesk",
    "com.mopub", "com.applovin", "com.ironsource",
)

_KOTLIN_PREFIXES = ("kotlin.", "kotlinx.")
_PLAY_PREFIXES = ("com.google.android.gms.",)

_TEST_CLASS_RE = re.compile(
    r'(?:Test|Mock|Fake|Stub|Dummy|Fixture|Helper)(?:[A-Z]|$)',
    re.IGNORECASE,
)
_GENERATED_RE = re.compile(
    r'(?:_MembersInjector|_Factory|_Impl|Hilt_|$$|Generated)',
)
_DEBUG_PKG_RE = re.compile(r'\bdebug\b', re.IGNORECASE)


def detect(
    caller_class: str,
    caller_method: str | None = None,
    detected_sdk_packages: list[str] | None = None,
) -> list[dict]:
    """
    Detect noise signals for a code record.

    Returns a list of NoiseSignal-shaped dicts (not Pydantic models, to
    avoid circular imports). The builder converts these to NoiseSignal
    instances when constructing the record.

    Args:
        caller_class:          Fully qualified class name.
        caller_method:         Method name (optional).
        detected_sdk_packages: List of SDK package prefixes from
                               third_party_sdks.json, used to flag
                               in_third_party_sdk.

    Returns:
        List of dicts with keys: signal, confidence, notes.
    """
    signals = []
    cls = caller_class or ""
    method = caller_method or ""

    # In test code
    simple = cls.split(".")[-1]
    if _TEST_CLASS_RE.search(simple) or _TEST_CLASS_RE.search(method):
        signals.append({
            "signal": "in_test_code",
            "confidence": 0.82,
            "notes": f"Class or method name matches test heuristic: {simple}",
        })

    # In Kotlin stdlib
    if any(cls.startswith(p) for p in _KOTLIN_PREFIXES):
        signals.append({
            "signal": "in_kotlin_stdlib",
            "confidence": 0.97,
            "notes": None,
        })

    # In Play Services
    if any(cls.startswith(p) for p in _PLAY_PREFIXES):
        signals.append({
            "signal": "in_play_services",
            "confidence": 0.97,
            "notes": None,
        })

    # In known third-party SDK (from catalog)
    sdk_pkgs = detected_sdk_packages or []
    if any(cls.startswith(p + ".") or cls == p for p in sdk_pkgs):
        signals.append({
            "signal": "in_third_party_sdk",
            "confidence": 0.90,
            "notes": None,
        })
    elif any(cls.startswith(p) for p in _SDK_PREFIXES):
        signals.append({
            "signal": "in_third_party_sdk",
            "confidence": 0.85,
            "notes": None,
        })

    # In generated code
    if _GENERATED_RE.search(simple):
        signals.append({
            "signal": "in_generated_code",
            "confidence": 0.88,
            "notes": f"Class name matches generated code pattern: {simple}",
        })

    # In debug-only package
    parts = cls.split(".")
    if any(_DEBUG_PKG_RE.match(p) for p in parts):
        signals.append({
            "signal": "in_debug_only_class",
            "confidence": 0.75,
            "notes": "Class resides in a package named 'debug'",
        })

    return signals