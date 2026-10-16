import logging
from datetime import datetime, timezone

from ..helpers.ids import next_id
from ..models import GeneratedBy, SdkRecord, Source, ThirdPartySdksFile

logger = logging.getLogger(__name__)

EXTRACTOR = "sdk_detector_v1"
TOOL = "androguard-4.1.3"

# SDK detection catalog.
# Each entry: (display_name, vendor, categories, package_prefixes)
_SDK_CATALOG: list[tuple[str, str, list[str], list[str]]] = [
    ("Firebase Analytics",     "Google",   ["analytics"],                          ["com.google.firebase.analytics"]),
    ("Firebase Crashlytics",   "Google",   ["crash_reporting"],                    ["com.google.firebase.crashlytics", "com.crashlytics"]),
    ("Firebase Cloud Messaging","Google",  ["push_notifications"],                 ["com.google.firebase.messaging"]),
    ("Firebase Auth",          "Google",   ["authentication"],                     ["com.google.firebase.auth"]),
    ("Firebase Firestore",     "Google",   ["analytics"],                          ["com.google.firebase.firestore"]),
    ("Firebase",               "Google",   ["analytics"],                          ["com.google.firebase"]),
    ("Google Play Services",   "Google",   ["platform"],                           ["com.google.android.gms"]),
    ("Google Ads",             "Google",   ["advertising"],                        ["com.google.android.gms.ads"]),
    ("Google Maps",            "Google",   ["maps"],                               ["com.google.android.gms.maps"]),
    ("Facebook SDK",           "Meta",     ["social", "analytics"],                ["com.facebook"]),
    ("Adjust",                 "Adjust",   ["attribution", "analytics"],           ["com.adjust.sdk"]),
    ("AppsFlyer",              "AppsFlyer",["attribution", "analytics"],           ["com.appsflyer"]),
    ("Branch",                 "Branch",   ["attribution", "deep_linking"],        ["io.branch"]),
    ("Mixpanel",               "Mixpanel", ["analytics"],                          ["com.mixpanel"]),
    ("Amplitude",              "Amplitude",["analytics"],                          ["com.amplitude"]),
    ("Segment",                "Twilio",   ["analytics"],                          ["com.segment.analytics"]),
    ("Braze",                  "Braze",    ["push_notifications", "analytics"],    ["com.appboy", "com.braze"]),
    ("OneSignal",              "OneSignal",["push_notifications"],                 ["com.onesignal"]),
    ("Stripe",                 "Stripe",   ["payment"],                            ["com.stripe.android"]),
    ("PayPal",                 "PayPal",   ["payment"],                            ["com.paypal"]),
    ("Braintree",              "Braintree",["payment"],                            ["com.braintreepayments"]),
    ("OkHttp",                 "Square",   ["networking"],                         ["okhttp3"]),
    ("Retrofit",               "Square",   ["networking"],                         ["retrofit2"]),
    ("Glide",                  "Google",   ["image_loading"],                      ["com.bumptech.glide"]),
    ("Picasso",                "Square",   ["image_loading"],                      ["com.squareup.picasso"]),
    ("Gson",                   "Google",   ["serialization"],                      ["com.google.gson"]),
    ("Moshi",                  "Square",   ["serialization"],                      ["com.squareup.moshi"]),
    ("Room",                   "Google",   ["storage"],                            ["androidx.room"]),
    ("SQLCipher",              "Zetetic",  ["storage", "encryption"],              ["net.sqlcipher"]),
    ("Realm",                  "MongoDB",  ["storage"],                            ["io.realm"]),
    ("Sentry",                 "Sentry",   ["crash_reporting"],                    ["io.sentry"]),
    ("Bugsnag",                "Bugsnag",  ["crash_reporting"],                    ["com.bugsnag"]),
    ("Lottie",                 "Airbnb",   ["ui"],                                 ["com.airbnb.lottie"]),
    ("Dagger",                 "Google",   ["dependency_injection"],               ["dagger"]),
    ("Hilt",                   "Google",   ["dependency_injection"],               ["dagger.hilt"]),
    ("RxJava",                 "ReactiveX",["async"],                              ["io.reactivex"]),
    ("Coroutines",             "JetBrains",["async"],                              ["kotlinx.coroutines"]),
    ("Coil",                   "Coil",     ["image_loading"],                      ["coil"]),
    ("LeakCanary",             "Square",   ["debugging"],                          ["com.squareup.leakcanary"]),
    ("Timber",                 "Jake Wharton",["logging"],                         ["timber"]),
    ("WorkManager",            "Google",   ["background_work"],                    ["androidx.work"]),
    ("Intercom",               "Intercom", ["customer_support"],                   ["io.intercom"]),
    ("Zendesk",                "Zendesk",  ["customer_support"],                   ["zendesk"]),
    ("MoPub",                  "Twitter",  ["advertising"],                        ["com.mopub"]),
    ("AdMob",                  "Google",   ["advertising"],                        ["com.google.android.gms.ads"]),
    ("IronSource",             "IronSource",["advertising"],                       ["com.ironsource"]),
    ("AppLovin",               "AppLovin", ["advertising"],                        ["com.applovin"]),
]


def build(job_id: str, androguard_result) -> ThirdPartySdksFile:
    """
    Detect third-party SDKs from Androguard's class list.

    Detection is based on package prefix matching — each class name is checked
    against the catalog. Class counts are accurate; version detection is best-effort
    from string constants.

    Args:
        job_id:            Analysis job identifier.
        androguard_result: AndroguardResult from the extraction coordinator.

    Returns:
        Populated ThirdPartySdksFile.
    """
    classes = androguard_result.classes or []
    string_constants = androguard_result.string_constants or []

    # Convert DEX-style class names (Lcom/example/Foo;) to dotted package prefixes
    dotted_classes = {_dex_to_dotted(c) for c in classes if c}

    records: list[SdkRecord] = []
    seen_names: set[str] = set()

    for name, vendor, categories, prefixes in _SDK_CATALOG:
        if name in seen_names:
            continue

        matched_packages = []
        class_count = 0

        for prefix in prefixes:
            matches = [c for c in dotted_classes if c.startswith(prefix + ".") or c == prefix]
            if matches:
                matched_packages.append(prefix)
                class_count += len(matches)

        if not matched_packages:
            continue

        seen_names.add(name)
        version_hint = _detect_version(name, string_constants)

        records.append(SdkRecord(
            id=next_id(job_id, "sdk"),
            name=name,
            vendor=vendor,
            category=categories,
            detected_packages=matched_packages,
            class_count=class_count,
            version_hint=version_hint,
            confidence=0.92,
            related_ids=[],
            source=Source(
                artifact="dex",
                path="classes.dex",
                extractor=EXTRACTOR,
                tool=TOOL,
            ),
        ))

    return ThirdPartySdksFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=records,
    )


def _dex_to_dotted(class_name: str) -> str:
    """Convert Lcom/example/Foo; → com.example.Foo"""
    name = class_name.lstrip("L").rstrip(";")
    return name.replace("/", ".")


def _detect_version(sdk_name: str, strings: list[str]) -> str | None:
    """
    Try to find a version string for an SDK in the app's string constants.
    Looks for patterns like "2.3.1", "v4.0.0" near the SDK name.
    """
    sdk_lower = sdk_name.lower().replace(" ", "")
    version_re = __import__("re").compile(r"\bv?(\d+\.\d+(?:\.\d+)?)\b")

    for s in strings:
        if sdk_lower in s.lower():
            m = version_re.search(s)
            if m:
                return m.group(1)
    return None