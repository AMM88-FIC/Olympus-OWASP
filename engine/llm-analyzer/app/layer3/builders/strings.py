import logging
import math
import re
from datetime import datetime, timezone

from ..helpers.ids import next_id
from ..models import GeneratedBy, Source, StringCaller, StringRecord, StringsFile

logger = logging.getLogger(__name__)

EXTRACTOR = "string_filter_v1"
TOOL = "androguard-4.1.3"

# Minimum string length — avoids noise from single chars and short tokens
_MIN_LENGTH = 6

# Entropy threshold above which a string is a possible secret candidate
_SECRET_ENTROPY_THRESHOLD = 3.5

# Patterns used to categorise strings
_URL_RE = re.compile(r"^https?://|^ftp://|^jdbc:", re.I)
_HTTP_RE = re.compile(r"^http://", re.I)
_FILE_PATH_RE = re.compile(r"^/(?:data|sdcard|storage|proc|sys|system)/", re.I)
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$")
_EMAIL_RE = re.compile(r"^[\w.+-]+@[\w-]+\.[a-z]{2,}$", re.I)
_JDBC_RE = re.compile(r"^jdbc:", re.I)
_IPC_ACTION_RE = re.compile(r"^[\w.]+\.(?:ACTION|BROADCAST|INTENT|EVENT)[\w.]*$")
_CONTENT_URI_RE = re.compile(r"^content://")

_SUSPICIOUS_KEYWORDS = frozenset({
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "authorization", "bearer", "credential", "private_key", "access_key",
    "auth_token", "client_secret",
})


def build(job_id: str, androguard_result) -> StringsFile:
    """
    Extract and categorise security-relevant string constants from Androguard.

    Each string is filtered, categorised, and linked to its callers where
    Androguard's cross-reference data allows.

    Args:
        job_id:            Analysis job identifier.
        androguard_result: AndroguardResult from the extraction coordinator.

    Returns:
        Populated StringsFile.
    """
    raw_strings = androguard_result.string_constants or []
    records: list[StringRecord] = []

    for idx, value in enumerate(raw_strings):
        if not isinstance(value, str) or len(value) < _MIN_LENGTH:
            continue

        category = _categorise(value)
        if category is None:
            continue

        is_cleartext = _HTTP_RE.match(value) is not None if category == "url" else None
        entropy = _entropy(value) if category == "possible_secret" else None

        records.append(StringRecord(
            id=next_id(job_id, "str"),
            category=category,
            value=value,
            is_cleartext=is_cleartext,
            entropy_bits=round(entropy, 3) if entropy is not None else None,
            referenced_in=[],   # populated in a future pass when call graph is available
            confidence=_confidence(category, value),
            related_ids=[],
            source=Source(
                artifact="dex",
                path="classes.dex",
                dex_string_id=idx,
                extractor=EXTRACTOR,
                tool=TOOL,
            ),
        ))

    return StringsFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=records,
    )


def _categorise(value: str) -> str | None:
    """Return a category string or None if the string is not security-relevant."""
    vl = value.lower()

    if _URL_RE.match(value):
        return "url"
    if _JDBC_RE.match(value):
        return "jdbc_string"
    if _CONTENT_URI_RE.match(value):
        return "content_uri"
    if _FILE_PATH_RE.match(value):
        return "file_path"
    if _IP_RE.match(value):
        return "ip_address"
    if _EMAIL_RE.match(value):
        return "email"
    if _IPC_ACTION_RE.match(value):
        return "ipc_action"
    if any(kw in vl for kw in _SUSPICIOUS_KEYWORDS):
        return "suspicious_keyword"
    if len(value) > 40 and _is_possible_secret(value):
        return "possible_secret"

    return None


def _is_possible_secret(value: str) -> bool:
    """Heuristic: high-entropy ASCII string that isn't a sentence."""
    if not value.isascii():
        return False
    if " " in value and len(value.split()) > 4:
        return False
    return _entropy(value) >= _SECRET_ENTROPY_THRESHOLD


def _entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _confidence(category: str, value: str) -> float:
    if category in ("url", "jdbc_string", "content_uri", "ip_address", "email"):
        return 0.97
    if category == "file_path":
        return 0.95
    if category == "ipc_action":
        return 0.88
    if category == "suspicious_keyword":
        return 0.80
    if category == "possible_secret":
        ent = _entropy(value)
        return min(0.95, 0.60 + (ent / 8.0) * 0.35)
    return 0.75