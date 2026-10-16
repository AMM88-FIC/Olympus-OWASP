"""
Sensitivity pattern catalog.

Two distinct categories — kept separate because they have different
verdict implications:

  CREDENTIAL: tokens, keys, passwords. Sensitivity is intrinsic to the
              data type. Storage in shared locations or transmission
              over cleartext is a fail regardless of consent.

  PII:        emails, phone numbers, identity numbers. Sensitivity is
              context-dependent. Storage is acceptable; specific uses
              (logging, sending to third parties) are problematic.

Each pattern carries a strength rating:
  high   — structural match leaves no reasonable doubt
  medium — strong signal but plausible false positives exist
  low    — heuristic match useful only in combination with other signals
"""

import re

# ---------------------------------------------------------------------------
# CREDENTIAL — unambiguous structural patterns
# ---------------------------------------------------------------------------

# Each entry: (regex, name, strength). The regex must match the whole token,
# not a substring, to keep false positives rare.

CREDENTIAL_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # Major cloud / service API keys with documented prefixes
    (re.compile(r"^AIza[0-9A-Za-z_\-]{30,40}$"), "google_api_key", "high"),
    (re.compile(r"^ya29\.[0-9A-Za-z_\-]+$"), "google_oauth_token", "high"),
    (re.compile(r"^AKIA[0-9A-Z]{16}$"), "aws_access_key_id", "high"),
    (re.compile(r"^ASIA[0-9A-Z]{16}$"), "aws_temporary_access_key", "high"),
    (re.compile(r"^sk_live_[0-9A-Za-z]{24,}$"), "stripe_live_secret_key", "high"),
    (re.compile(r"^sk_test_[0-9A-Za-z]{24,}$"), "stripe_test_secret_key", "high"),
    (re.compile(r"^pk_live_[0-9A-Za-z]{24,}$"), "stripe_live_publishable_key", "medium"),
    (re.compile(r"^xox[baprs]-[0-9A-Za-z\-]{10,}$"), "slack_token", "high"),
    (re.compile(r"^ghp_[0-9A-Za-z]{36}$"), "github_personal_access_token", "high"),
    (re.compile(r"^gho_[0-9A-Za-z]{36}$"), "github_oauth_token", "high"),
    (re.compile(r"^ghs_[0-9A-Za-z]{36}$"), "github_app_server_token", "high"),
    (re.compile(r"^npm_[0-9A-Za-z]{36}$"), "npm_token", "high"),
    (re.compile(r"^SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}$"),
     "sendgrid_api_key", "high"),
    (re.compile(r"^key-[0-9A-Za-z]{32}$"), "mailgun_api_key", "high"),

    # Generic structural patterns
    (re.compile(r"^eyJ[0-9A-Za-z_\-]+\.[0-9A-Za-z_\-]+\.[0-9A-Za-z_\-]+$"),
     "jwt_token", "high"),
    (re.compile(r"^Bearer\s+[A-Za-z0-9._\-]{16,}$"), "bearer_token", "high"),
    (re.compile(r"^Basic\s+[A-Za-z0-9+/=]{8,}$"), "http_basic_auth", "high"),

    # Private keys (PEM block markers — case-sensitive)
    (re.compile(r"-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----"),
     "private_key_block", "high"),
    (re.compile(r"-----BEGIN\s+ENCRYPTED\s+PRIVATE\s+KEY-----"),
     "encrypted_private_key_block", "high"),

    # Database connection strings with embedded password
    (re.compile(r"^[a-z]+://[^:/\s]+:[^@/\s]+@[^/\s]+"),
     "url_with_embedded_credentials", "high"),
    (re.compile(r"jdbc:[a-z]+://[^?\s]+\?.*[Pp]assword=[^&\s]+"),
     "jdbc_with_password", "high"),

    # Firebase / Google Cloud service account fragments
    (re.compile(r"^-----BEGIN\s+CERTIFICATE-----"),
     "certificate_block", "low"),  # cert alone is not a credential, but worth noting
]

# ---------------------------------------------------------------------------
# CREDENTIAL — keyword lists for variable / SharedPreferences key matching
# ---------------------------------------------------------------------------

# Three buckets by strength. Matched against tokens (variable names,
# preferences keys, JSON field names, file path components).

CREDENTIAL_KEYWORDS_HIGH: frozenset[str] = frozenset({
    "password", "passwd", "pwd",
    "passphrase",
    "secret_key", "secretkey",
    "private_key", "privatekey",
    "client_secret", "clientsecret",
    "api_secret", "apisecret",
    "auth_token", "authtoken",
    "access_token", "accesstoken",
    "refresh_token", "refreshtoken",
    "session_token", "sessiontoken",
    "id_token", "idtoken",
    "bearer_token", "bearertoken",
    "csrf_token", "csrftoken",
})

CREDENTIAL_KEYWORDS_MEDIUM: frozenset[str] = frozenset({
    "secret",
    "token",
    "credential", "credentials",
    "api_key", "apikey",
    "auth_key", "authkey",
    "encryption_key", "encryptionkey",
    "signing_key", "signingkey",
    "session_id", "sessionid",
    "auth", "authorization",
    "pin_code", "pincode", "pin",
    "passcode",
})

CREDENTIAL_KEYWORDS_LOW: frozenset[str] = frozenset({
    "key",
    "salt",
    "nonce",
    "challenge",
    "hash",
})

# ---------------------------------------------------------------------------
# PII — patterns
# ---------------------------------------------------------------------------

PII_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # SSN must come before generic phone number pattern (both can match
    # the digit-with-hyphen layout). High specificity wins.
    (re.compile(r"^\d{3}-\d{2}-\d{4}$"), "us_ssn", "high"),

    # Email addresses — common, but matching alone is just data, not a finding
    (re.compile(r"^[\w.+\-]+@[\w\-]+\.[a-zA-Z]{2,}$"), "email_address", "low"),

    # Credit card numbers — allow common separators; Luhn-validated downstream
    (re.compile(r"^[\d\-\s]{13,23}$"), "credit_card_candidate", "medium"),

    # Phone numbers (international or general format with separators)
    (re.compile(r"^\+[1-9]\d{1,14}$"), "phone_e164", "low"),
    (re.compile(r"^\+?[\d\s\-\(\)]{10,18}$"), "phone_general", "low"),

    # IP addresses (IPv4)
    (re.compile(r"^(\d{1,3}\.){3}\d{1,3}$"), "ipv4_address", "low"),

    # GPS coordinate pairs (rough heuristic)
    (re.compile(r"^-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}$"),
     "gps_coordinate_pair", "medium"),
]

# ---------------------------------------------------------------------------
# PII — keyword lists
# ---------------------------------------------------------------------------

PII_KEYWORDS_HIGH: frozenset[str] = frozenset({
    "ssn", "social_security",
    "passport_number", "passportnumber",
    "national_id", "nationalid",
    "drivers_license", "driverslicense",
    "credit_card", "creditcard", "card_number", "cardnumber",
    "cvv", "cvc",
    "iban", "swift_code",
    "tax_id", "taxid",
    "date_of_birth", "dateofbirth", "birth_date", "birthdate",
})

PII_KEYWORDS_MEDIUM: frozenset[str] = frozenset({
    "first_name", "firstname", "last_name", "lastname",
    "full_name", "fullname",
    "email", "email_address", "emailaddress",
    "phone", "phone_number", "phonenumber", "mobile",
    "address",
    "street_address", "streetaddress",
    "postal_code", "postalcode", "zip", "zipcode",
    "user_id", "userid",
    "device_id", "deviceid",
    "android_id", "androidid",
    "imei", "imsi",
    "mac_address", "macaddress",
    "advertising_id", "advertisingid", "ad_id",
})

PII_KEYWORDS_LOW: frozenset[str] = frozenset({
    "name", "username", "user_name",
    "city", "country",
    "latitude", "longitude", "location", "lat", "lng",
    "ip_address", "ipaddress",
    "age", "gender",
})

# ---------------------------------------------------------------------------
# Sensitive Android API patterns
# ---------------------------------------------------------------------------

# Calls to these APIs are direct evidence the app handles the
# corresponding category of sensitive data, regardless of variable naming.
# Format: (api_pattern, signal_name, category, strength)

SENSITIVE_API_CALLS: list[tuple[str, str, str, str]] = [
    # Credentials / cryptographic material
    ("java.security.KeyStore", "keystore_access", "credential", "high"),
    ("javax.crypto.SecretKey", "secret_key_handling", "credential", "high"),
    ("android.security.keystore", "android_keystore", "credential", "high"),
    ("android.accounts.AccountManager", "account_manager", "credential", "high"),

    # Biometric data
    ("androidx.biometric.BiometricPrompt", "biometric_prompt", "pii", "high"),
    ("android.hardware.biometrics.BiometricPrompt", "biometric_prompt", "pii", "high"),
    ("android.hardware.fingerprint", "fingerprint_api", "pii", "high"),

    # Location
    ("android.location.LocationManager", "location_manager", "pii", "high"),
    ("com.google.android.gms.location", "fused_location", "pii", "high"),

    # Contacts
    ("android.provider.ContactsContract", "contacts_provider", "pii", "high"),

    # Phone / device identity
    ("android.telephony.TelephonyManager", "telephony_manager", "pii", "medium"),
    ("Settings.Secure.ANDROID_ID", "android_id_read", "pii", "medium"),

    # Calendar
    ("android.provider.CalendarContract", "calendar_provider", "pii", "medium"),

    # SMS / call log
    ("android.provider.Telephony.Sms", "sms_provider", "pii", "high"),
    ("android.provider.CallLog", "call_log_provider", "pii", "high"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize_token(token: str) -> str:
    """
    Normalize a name for keyword matching.

    Strips type prefixes (m, s, k for member/static/constant in Hungarian
    notation), splits camelCase and ALL_CAPS into snake_case, lowercases
    the result, collapses runs of underscores, and trims leading/trailing
    underscores.
    """
    if not token:
        return ""
    # Strip common Hungarian-notation prefixes (mFoo, sBar, kBaz)
    if len(token) > 1 and token[0] in "msk" and token[1].isupper():
        token = token[1:]
    # Convert camelCase to snake_case (insert _ before each uppercase
    # that follows a lowercase character)
    result = []
    for i, ch in enumerate(token):
        if ch.isupper() and i > 0 and not token[i - 1].isupper() and token[i - 1] != "_":
            result.append("_")
        result.append(ch.lower())
    out = "".join(result)
    # Collapse runs of underscores and trim
    while "__" in out:
        out = out.replace("__", "_")
    return out.strip("_")


def luhn_check(number: str) -> bool:
    """
    Validate a candidate credit card number with the Luhn algorithm.

    Returns True for numbers that pass the checksum. Reduces false
    positives for the credit_card_candidate pattern.
    """
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def keyword_strength(normalized: str, category: str) -> str | None:
    """
    Look up a normalized name across all keyword tiers for the given category.
    Returns "high"/"medium"/"low" or None if no match.

    Matching is substring-based with word-boundary awareness. A
    compound name like "encryption_key_id" matches the tier whose
    keyword `encryption_key` appears as a substring. Higher tiers are
    checked first; the first match wins.

    To prevent over-matching, single-word LOW-tier keywords (`key`,
    `salt`, etc.) are matched against split parts only — `monkey` should
    not match `key`.
    """
    if not normalized:
        return None

    parts = set(normalized.split("_"))

    if category == "credential":
        # HIGH and MEDIUM use substring matching (compound keywords)
        if any(_substring_match(kw, normalized) for kw in CREDENTIAL_KEYWORDS_HIGH):
            return "high"
        if any(_substring_match(kw, normalized) for kw in CREDENTIAL_KEYWORDS_MEDIUM):
            return "medium"
        # LOW uses part-membership only to avoid false positives
        if any(p in CREDENTIAL_KEYWORDS_LOW for p in parts):
            return "low"
    elif category == "pii":
        if any(_substring_match(kw, normalized) for kw in PII_KEYWORDS_HIGH):
            return "high"
        if any(_substring_match(kw, normalized) for kw in PII_KEYWORDS_MEDIUM):
            return "medium"
        if any(p in PII_KEYWORDS_LOW for p in parts):
            return "low"
    return None


def _substring_match(keyword: str, normalized: str) -> bool:
    """
    Check whether `keyword` appears in `normalized` with word-boundary
    awareness in the snake_case namespace.

    Examples:
      _substring_match("api_key", "api_key_constant")     -> True
      _substring_match("api_key", "old_api_key_value")    -> True
      _substring_match("key", "api_key_constant")         -> True
      _substring_match("key", "monkey")                   -> False
    """
    # Wrap with underscores to enforce word-boundary in the normalized form
    haystack = "_" + normalized + "_"
    needle = "_" + keyword + "_"
    return needle in haystack