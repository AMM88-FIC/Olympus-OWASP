"""
Shared regex patterns for JADX Java source extraction.

All patterns match against decompiled Java source lines. They are anchored
to framework API calls which are never obfuscated, so they remain reliable
regardless of how much the app's own code is renamed.

Each pattern group returns (line_number, match_object) when applied to
enumerate(lines).
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass
class Match:
    file: Path
    class_name: str
    method_name: str
    line: int
    snippet: str
    groups: dict[str, str]


# ---------------------------------------------------------------------------
# Crypto patterns
# ---------------------------------------------------------------------------

# Constant declarations harvested per file so that a transformation passed as a
# named constant can be resolved to its value.
#
# Why this exists: the four getInstance patterns below originally required a
# string LITERAL immediately after the paren. `Cipher.getInstance(ALGO)` with
# `static final String ALGO = "DES/ECB/PKCS5Padding"` therefore matched nothing
# and produced NO RECORD AT ALL — the call site was invisible, indistinguishable
# from "this file does no crypto". That is how a real DES/ECB cipher in
# com/xiaomi/utils/Commons.java went unreported and a verdict came back `pass`.
#
# Deliberately SAME-FILE ONLY, and deliberately constants only. An argument that
# is a method parameter or an arbitrary expression is left unmatched, exactly as
# before, so library wrappers like Bouncy Castle's
# `DefaultJcaJceHelper.createCipher(String str) { Cipher.getInstance(str); }`
# keep producing nothing. Those are unresolvable at this layer and would be pure
# noise: in a sample of 8,666 source files, 18 of 26 Cipher.getInstance sites
# took a parameter rather than a constant.
JAVA_STRING_CONST_RE = re.compile(
    r'(?:static\s+)?final\s+String\s+(?P<name>\w+)\s*=\s*"(?P<val>[^"]*)"'
)


def harvest_string_constants(content: str) -> dict[str, str]:
    """Map `final String` constant names to their literal values for one file."""
    return {m.group("name"): m.group("val")
            for m in JAVA_STRING_CONST_RE.finditer(content)}


def resolve_const_arg(expr: str, constants: dict[str, str]) -> str | None:
    """Resolve a getInstance argument that is a bare or qualified constant
    reference. Returns the literal value, or None when it is not a constant
    this layer can resolve (a parameter, a call, a cross-class field).

    `ThisClass.ALGO` resolves on its last segment, which is correct for a
    same-file constant and harmlessly misses a same-named constant in another
    class — a miss is the pre-existing behaviour, never a wrong value.
    """
    expr = (expr or "").strip()
    if not expr or not all(part.isidentifier() for part in expr.split(".")):
        return None
    return constants.get(expr.split(".")[-1])


CRYPTO_PATTERNS = [
    ("cipher_get_instance",
     re.compile(r'Cipher\.getInstance\(\s*(?:"(?P<transform>[^"]+)"'
                r'|(?P<transform_expr>[A-Za-z_$][\w$.]*)\s*[),])')),
    ("key_generator",
     re.compile(r'KeyGenerator\.getInstance\(\s*(?:"(?P<algo>[^"]+)"'
                r'|(?P<algo_expr>[A-Za-z_$][\w$.]*)\s*[),])')),
    ("secret_key_spec",
     re.compile(r'new\s+SecretKeySpec\s*\(')),
    ("message_digest",
     re.compile(r'MessageDigest\.getInstance\(\s*(?:"(?P<algo>[^"]+)"'
                r'|(?P<algo_expr>[A-Za-z_$][\w$.]*)\s*[),])')),
    ("secure_random_new",
     re.compile(r'new\s+SecureRandom\s*\(')),
    ("secure_random_get",
     re.compile(r'SecureRandom\.getInstance\s*\(')),
    ("keystore_get",
     re.compile(r'KeyStore\.getInstance\(')),
    ("key_gen_param",
     re.compile(r'KeyGenParameterSpec\.Builder\s*\(')),
    ("ssl_context",
     re.compile(r'SSLContext\.getInstance\(\s*(?:"(?P<proto>[^"]+)"'
                r'|(?P<proto_expr>[A-Za-z_$][\w$.]*)\s*[),])')),
]

# ---------------------------------------------------------------------------
# Network / TLS patterns
# ---------------------------------------------------------------------------

NETWORK_PATTERNS = [
    ("empty_trust_manager",
     re.compile(r'void\s+checkServerTrusted\s*\([^)]*\)\s*\{')),
    ("hostname_verifier",
     re.compile(r'HostnameVerifier|verify\s*\(\s*String\s+hostname')),
    ("verifier_returns_true",
     re.compile(r'return\s+true\s*;')),
    ("okhttp_builder",
     re.compile(r'OkHttpClient\.Builder\s*\(')),
    ("certificate_pinner",
     re.compile(r'CertificatePinner\.Builder\s*\(')),
    ("url_connection",
     re.compile(r'HttpURLConnection|HttpsURLConnection')),
    ("trust_all_hosts",
     re.compile(r'ALLOW_ALL_HOSTNAME_VERIFIER|acceptAllCertificates')),
    ("on_received_ssl_error",
     re.compile(r'onReceivedSslError\s*\(')),
    ("ssl_error_proceed",
     re.compile(r'handler\.proceed\s*\(')),
]

# ---------------------------------------------------------------------------
# Storage patterns
# ---------------------------------------------------------------------------

STORAGE_PATTERNS = [
    ("shared_prefs",
     re.compile(r'getSharedPreferences\s*\(\s*"?(?P<name>[^",)]+)"?')),
    ("shared_prefs_edit",
     re.compile(r'\.edit\s*\(\s*\)')),
    ("sqlite_raw_query",
     re.compile(r'\.rawQuery\s*\(')),
    ("sqlite_exec_sql",
     re.compile(r'\.execSQL\s*\(')),
    ("sqlite_open",
     re.compile(r'openOrCreateDatabase|SQLiteOpenHelper|getWritableDatabase|getReadableDatabase')),
    ("room_db",
     re.compile(r'Room\.databaseBuilder|@Database')),
    ("realm_open",
     re.compile(r'Realm\.getInstance|Realm\.getDefaultInstance')),
    ("external_storage",
     re.compile(r'getExternalStorageDirectory|getExternalFilesDir|Environment\.getExternal')),
    ("file_output",
     re.compile(r'new\s+FileOutputStream\s*\(|openFileOutput\s*\(')),
    ("datastore",
     re.compile(r'DataStore|dataStore\s*\(')),
    ("world_readable",
     re.compile(r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE')),
]

# ---------------------------------------------------------------------------
# WebView patterns
# ---------------------------------------------------------------------------

WEBVIEW_PATTERNS = [
    ("js_enabled",
     re.compile(r'setJavaScriptEnabled\s*\(\s*(?P<val>true|false)\s*\)')),
    ("file_access",
     re.compile(r'setAllowFileAccess\s*\(\s*(?P<val>true|false)\s*\)')),
    ("universal_access",
     re.compile(r'setAllowUniversalAccessFromFileURLs\s*\(\s*(?P<val>true|false)\s*\)')),
    ("content_access",
     re.compile(r'setAllowContentAccess\s*\(\s*(?P<val>true|false)\s*\)')),
    ("dom_storage",
     re.compile(r'setDomStorageEnabled\s*\(\s*(?P<val>true|false)\s*\)')),
    ("js_interface",
     re.compile(r'addJavascriptInterface\s*\(\s*(?P<obj>[^,]+),\s*"(?P<name>[^"]+)"')),
    ("load_url",
     re.compile(r'\.loadUrl\s*\(\s*(?P<url>[^)]+)\)')),
    ("load_data",
     re.compile(r'\.loadData(?:WithBaseURL)?\s*\(')),
    ("debugging_enabled",
     re.compile(r'setWebContentsDebuggingEnabled\s*\(\s*true\s*\)')),
    ("safe_browsing",
     re.compile(r'setSafeBrowsingEnabled\s*\(')),
    ("mixed_content",
     re.compile(r'setMixedContentMode\s*\(')),
    ("ssl_error_handler",
     re.compile(r'onReceivedSslError\s*\(')),
]

# ---------------------------------------------------------------------------
# API usage patterns (logging, IPC, auth, etc.)
# ---------------------------------------------------------------------------

API_USAGE_PATTERNS = {
    "logging": [
        re.compile(r'Log\s*\.\s*(?:d|i|e|w|v|wtf)\s*\('),
        re.compile(r'System\.out\.print'),
        re.compile(r'printStackTrace\s*\('),
        re.compile(r'Timber\s*\.\s*(?:d|i|e|w|v)\s*\('),
    ],
    "root_detection": [
        re.compile(r'"/system/(?:bin|xbin)/su"'),
        re.compile(r'"Superuser\.apk"|"supersu"', re.I),
        re.compile(r'RootBeer|isRooted|isDeviceRooted', re.I),
        re.compile(r'"magisk"', re.I),
        re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\(\s*"su"'),
    ],
    "debug_detection": [
        re.compile(r'isDebuggerConnected\s*\('),
        re.compile(r'Debug\.isDebuggerConnected'),
        re.compile(r'BuildConfig\.DEBUG'),
        re.compile(r'android\.os\.Debug\.waitingForDebugger'),
    ],
    "reflection": [
        re.compile(r'Class\.forName\s*\('),
        re.compile(r'getDeclaredMethod\s*\(|getMethod\s*\('),
        re.compile(r'\.invoke\s*\('),
    ],
    "dynamic_loading": [
        re.compile(r'DexClassLoader\s*\('),
        re.compile(r'PathClassLoader\s*\('),
        re.compile(r'InMemoryDexClassLoader\s*\('),
        re.compile(r'System\.load\s*\(|System\.loadLibrary\s*\('),
    ],
    "clipboard": [
        re.compile(r'ClipboardManager'),
        re.compile(r'setPrimaryClip\s*\(|getPrimaryClip\s*\('),
    ],
    "screenshots": [
        re.compile(r'FLAG_SECURE'),
        re.compile(r'setRecentsScreenshotEnabled\s*\('),
    ],
    "biometric": [
        re.compile(r'BiometricPrompt'),
        re.compile(r'FingerprintManager'),
        re.compile(r'setDeviceCredentialAllowed\s*\('),
    ],
    "notification": [
        re.compile(r'NotificationCompat\.Builder|NotificationManager'),
        re.compile(r'setContentText\s*\(|setContentTitle\s*\('),
    ],
    "ipc": [
        re.compile(r'new\s+Intent\s*\('),
        re.compile(r'startActivity\s*\(|startService\s*\('),
        re.compile(r'sendBroadcast\s*\(|sendOrderedBroadcast\s*\('),
        re.compile(r'getContentResolver\s*\(\s*\)\.(?:query|insert|update|delete)'),
        re.compile(r'PendingIntent\.get(?:Activity|Service|Broadcast)'),
    ],
    "auth": [
        re.compile(r'AccountManager\.get\s*\('),
        re.compile(r'getAuthToken\s*\('),
        re.compile(r'KeyguardManager'),
        re.compile(r'isDeviceSecure\s*\(|isKeyguardSecure\s*\('),
    ],
    "file_io": [
        re.compile(r'new\s+File\s*\('),
        re.compile(r'openFileInput\s*\(|openFileOutput\s*\('),
    ],
}

# ---------------------------------------------------------------------------
# Outgoing intent patterns
# ---------------------------------------------------------------------------

OUTGOING_INTENT_APIS = [
    ("startActivity",            re.compile(r'startActivity\s*\(')),
    ("startActivityForResult",   re.compile(r'startActivityForResult\s*\(')),
    ("sendBroadcast",            re.compile(r'sendBroadcast\s*\(')),
    ("sendOrderedBroadcast",     re.compile(r'sendOrderedBroadcast\s*\(')),
    ("sendStickyBroadcast",      re.compile(r'sendStickyBroadcast\s*\(')),
    ("startService",             re.compile(r'startService\s*\(')),
    ("bindService",              re.compile(r'bindService\s*\(')),
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def iter_java_files(source_dir: Path) -> Iterator[Path]:
    """Yield all .java files under source_dir, sorted for determinism."""
    yield from sorted(source_dir.rglob("*.java"))


def extract_class_name(java_file: Path, source_dir: Path) -> str:
    """
    Derive a dotted class name from the file path relative to the sources dir.
    e.g. sources/com/example/Foo.java → com.example.Foo
    """
    try:
        rel = java_file.relative_to(source_dir)
        return str(rel.with_suffix("")).replace("/", ".")
    except ValueError:
        return java_file.stem


def current_method(lines: list[str], line_idx: int) -> str:
    """
    Walk backwards from line_idx to find the nearest method signature.
    Returns the method name string or "unknown".
    """
    method_re = re.compile(
        r'(?:public|private|protected|static|final|synchronized|native|abstract)'
        r'[\w\s<>\[\]]+\s+(\w+)\s*\('
    )
    for i in range(line_idx, max(-1, line_idx - 60), -1):
        m = method_re.search(lines[i])
        if m:
            return m.group(1)
    return "unknown"


# ---------------------------------------------------------------------------
# Extended crypto patterns (v1.2 additions)
# ---------------------------------------------------------------------------

CRYPTO_PATTERNS_V12 = [
    ("mac_get_instance",
     re.compile(r'Mac\.getInstance\(\s*"(?P<algo>[^"]+)"')),
    ("signature_get_instance",
     re.compile(r'Signature\.getInstance\(\s*"(?P<algo>[^"]+)"')),
    ("key_pair_generator",
     re.compile(r'KeyPairGenerator\.getInstance\(\s*"(?P<algo>[^"]+)"')),
    ("pbe_key_spec",
     re.compile(r'new\s+PBEKeySpec\s*\(')),
    ("secret_key_factory",
     re.compile(r'SecretKeyFactory\.getInstance\(')),
    ("certificate_factory",
     re.compile(r'CertificateFactory\.getInstance\(')),
    ("trust_manager_factory",
     re.compile(r'TrustManagerFactory\.getInstance\(')),
    ("tink",
     re.compile(r'com\.google\.crypto\.tink')),
    ("jetpack_security",
     re.compile(
         r'androidx\.security\.crypto\.'
         r'(?:EncryptedSharedPreferences|EncryptedFile|MasterKey)'
     )),
    ("sqlcipher",
     re.compile(r'net\.sqlcipher')),
    ("bouncy_castle",
     re.compile(r'org\.bouncycastle')),
]

# Merge into main catalog
CRYPTO_PATTERNS = CRYPTO_PATTERNS + CRYPTO_PATTERNS_V12

# APIs that do not use a key — key_source must be "not_applicable"
KEYLESS_CRYPTO_APIS = frozenset({
    "java.security.MessageDigest.getInstance",
    "java.security.SecureRandom.<init>",
    "java.security.SecureRandom.getInstance",
})

# ---------------------------------------------------------------------------
# Extended storage patterns (v1.2 additions)
# ---------------------------------------------------------------------------

STORAGE_PATTERNS_V12 = [
    ("temp_file",
     re.compile(r'File\.createTempFile\s*\(')),
    ("file_writer",
     re.compile(r'new\s+(?:File|Buffered|Print)Writer\s*\(')),
    ("set_world_readable_file",
     re.compile(r'\.setReadable\s*\(\s*true\s*,\s*false\s*\)')),
    ("set_world_writable_file",
     re.compile(r'\.setWritable\s*\(\s*true\s*,\s*false\s*\)')),
    ("set_executable",
     re.compile(r'\.setExecutable\s*\(')),
    ("get_cache_dir",
     re.compile(r'getCacheDir\s*\(\s*\)')),
    ("get_external_cache",
     re.compile(r'getExternalCacheDir\s*\(\s*\)')),
    ("get_no_backup",
     re.compile(r'getNoBackupFilesDir\s*\(\s*\)')),
]

STORAGE_PATTERNS = STORAGE_PATTERNS + STORAGE_PATTERNS_V12