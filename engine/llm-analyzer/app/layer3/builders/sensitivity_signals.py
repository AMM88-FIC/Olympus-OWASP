"""
Sensitivity signals builder.

Walks code-bearing evidence records and emits one or more
SensitivitySignalRecord entries when patterns or keywords from the
catalog match. Two categories tracked separately:

  credential — tokens, keys, passwords (intrinsic sensitivity)
  pii        — personal identifiers (context-dependent sensitivity)

The builder is purely derivative — it reads other evidence files, runs
pattern matching, and emits new records. No file I/O against the APK.

Provenance filter: signals from records marked with `in_third_party_sdk`,
`in_test_code`, or `in_generated_code` (via `noise_signals`) are
emitted but flagged with `in_proprietary_code: false`. Verdict prompts
should weight first-party signals more heavily, since third-party code
is typically not actionable for the developer.

This builder runs after all primary builders, in the same phase as
`app_capabilities`.
"""

import logging
import re
from datetime import datetime, timezone

from ..helpers.ids import next_id
from ..helpers.record_hash import compute_record_hash
from ..models import (
    GeneratedBy, SensitivitySignalRecord, SensitivitySignalsFile, Source,
)
from . import _sensitivity_patterns as _pats

logger = logging.getLogger(__name__)

EXTRACTOR = "sensitivity_signals_v1"
TOOL = "layer3-aggregator"

# Records with these noise signals are non-proprietary
_NON_PROPRIETARY_NOISE = {
    "in_third_party_sdk", "in_test_code", "in_generated_code",
}


def build(
    job_id: str,
    storage_usage_file=None,
    api_usages_file=None,
    network_usage_file=None,
    crypto_usage_file=None,
    strings_file=None,
    outgoing_intents_file=None,
) -> SensitivitySignalsFile:
    """
    Aggregate sensitivity signals from existing evidence.

    Each input is optional; when missing, the corresponding category of
    signals simply isn't emitted. The builder never raises on missing
    inputs.
    """
    signals: list[SensitivitySignalRecord] = []

    if storage_usage_file is not None:
        signals.extend(_scan_storage(job_id, storage_usage_file))
    if api_usages_file is not None:
        signals.extend(_scan_api_usages(job_id, api_usages_file))
    if network_usage_file is not None:
        signals.extend(_scan_network_usage(job_id, network_usage_file))
    if crypto_usage_file is not None:
        signals.extend(_scan_crypto_usage(job_id, crypto_usage_file))
    if strings_file is not None:
        signals.extend(_scan_strings(job_id, strings_file))
    if outgoing_intents_file is not None:
        signals.extend(_scan_outgoing_intents(job_id, outgoing_intents_file))

    return SensitivitySignalsFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=signals,
        credential_signal_count=sum(
            1 for s in signals if s.category == "credential"
        ),
        pii_signal_count=sum(
            1 for s in signals if s.category == "pii"
        ),
        proprietary_signal_count=sum(
            1 for s in signals if s.in_proprietary_code
        ),
        third_party_signal_count=sum(
            1 for s in signals if not s.in_proprietary_code
        ),
    )


# ---------------------------------------------------------------------------
# Per-file scanners
# ---------------------------------------------------------------------------

def _scan_storage(job_id, storage_file):
    """Scan storage_usage records for credential/PII keyword matches."""
    out = []
    for rec in storage_file.records:
        proprietary = _is_proprietary(getattr(rec, "noise_signals", []))

        # The storage target name is the most direct signal —
        # SharedPreferences key, file path component, etc.
        target_name = ""
        if hasattr(rec, "storage_target") and rec.storage_target:
            target_name = rec.storage_target.name or ""

        # Also check the snippet for credentials passed to the storage call
        snippet = getattr(rec, "snippet", "") or ""

        for token, source_kind in _yield_tokens(target_name, snippet):
            for category in ("credential", "pii"):
                signal = _check_keyword(
                    job_id=job_id,
                    cited_id=rec.id,
                    token=token,
                    source_kind=source_kind,
                    category=category,
                    proprietary=proprietary,
                    rec_source=rec.source,
                )
                if signal:
                    out.append(signal)
    return out


def _scan_api_usages(job_id, api_file):
    """Scan api_usages records for sensitive API calls and keyword matches."""
    out = []
    for rec in api_file.records:
        proprietary = _is_proprietary(getattr(rec, "noise_signals", []))

        # Sensitive API call detection
        api_call = getattr(rec, "api_call", "") or ""
        for api_pattern, signal_name, category, strength in _pats.SENSITIVE_API_CALLS:
            if api_pattern in api_call:
                out.append(SensitivitySignalRecord(
                    id=next_id(job_id, "sens"),
                    confidence=_strength_to_confidence(strength),
                    related_ids=[rec.id],
                    source=rec.source,
                    record_hash=compute_record_hash(
                        api_call="sensitivity_api",
                        extra=f"{rec.id}:{signal_name}",
                    ),
                    cited_evidence_id=rec.id,
                    category=category,
                    signal_type=f"sensitive_api_call:{signal_name}",
                    signal_strength=strength,
                    matched_token=api_call,
                    rationale=(
                        f"API call {api_call!r} accesses sensitive "
                        f"data ({signal_name}). This is a direct signal "
                        f"that the app handles {category} data."
                    ),
                    in_proprietary_code=proprietary,
                ))
                break  # one API match per record is enough

        # Keyword scan on the snippet for variable names referenced
        snippet = getattr(rec, "snippet", "") or ""
        for token, source_kind in _yield_tokens(api_call, snippet):
            for category in ("credential", "pii"):
                signal = _check_keyword(
                    job_id=job_id,
                    cited_id=rec.id,
                    token=token,
                    source_kind=source_kind,
                    category=category,
                    proprietary=proprietary,
                    rec_source=rec.source,
                )
                if signal:
                    out.append(signal)
    return out


def _scan_network_usage(job_id, network_file):
    """Scan network_usage records for keyword matches in URLs and snippets."""
    out = []
    for rec in network_file.records:
        proprietary = _is_proprietary(getattr(rec, "noise_signals", []))
        snippet = getattr(rec, "snippet", "") or ""
        url = ""
        if hasattr(rec, "url_target") and rec.url_target:
            url = getattr(rec.url_target, "url", "") or ""

        for token, source_kind in _yield_tokens(url, snippet):
            for category in ("credential", "pii"):
                signal = _check_keyword(
                    job_id=job_id,
                    cited_id=rec.id,
                    token=token,
                    source_kind=source_kind,
                    category=category,
                    proprietary=proprietary,
                    rec_source=rec.source,
                )
                if signal:
                    out.append(signal)
    return out


def _scan_crypto_usage(job_id, crypto_file):
    """Scan crypto_usage for credential keywords near key sources."""
    out = []
    for rec in crypto_file.records:
        proprietary = _is_proprietary(getattr(rec, "noise_signals", []))
        snippet = getattr(rec, "snippet", "") or ""

        for token, source_kind in _yield_tokens("", snippet):
            signal = _check_keyword(
                job_id=job_id,
                cited_id=rec.id,
                token=token,
                source_kind=source_kind,
                category="credential",
                proprietary=proprietary,
                rec_source=rec.source,
            )
            if signal:
                out.append(signal)
    return out


def _scan_strings(job_id, strings_file):
    """Scan string constants against credential and PII regex catalogs."""
    out = []
    for rec in strings_file.records:
        proprietary = _is_proprietary(getattr(rec, "noise_signals", []))
        value = getattr(rec, "value", "") or ""
        if not value or len(value) < 8:
            continue

        # Credential structural patterns
        for pattern, name, strength in _pats.CREDENTIAL_PATTERNS:
            if pattern.match(value) or pattern.search(value):
                out.append(_pattern_signal(
                    job_id=job_id, cited_id=rec.id,
                    category="credential", signal_name=name,
                    strength=strength, matched=value[:80],
                    rationale=(
                        f"String value matches the {name} structural "
                        f"pattern. This is direct evidence of hardcoded "
                        f"credential material."
                    ),
                    proprietary=proprietary, rec_source=rec.source,
                ))
                break  # one pattern per string is enough

        # PII structural patterns
        for pattern, name, strength in _pats.PII_PATTERNS:
            if pattern.match(value):
                # Apply Luhn check for credit card candidates
                if name == "credit_card_candidate":
                    if not _pats.luhn_check(value):
                        continue
                    name = "credit_card_number"
                    strength = "high"
                out.append(_pattern_signal(
                    job_id=job_id, cited_id=rec.id,
                    category="pii", signal_name=name,
                    strength=strength, matched=value[:80],
                    rationale=(
                        f"String value matches the {name} pattern."
                    ),
                    proprietary=proprietary, rec_source=rec.source,
                ))
                break
    return out


def _scan_outgoing_intents(job_id, intents_file):
    """Scan outgoing_intents for credential/PII keywords in intent extras."""
    out = []
    for rec in intents_file.records:
        proprietary = _is_proprietary(getattr(rec, "noise_signals", []))
        extras = getattr(rec, "extras", []) or []
        snippet = getattr(rec, "snippet", "") or ""

        # Each extra has a key — that's our most reliable token source
        for extra in extras:
            key = getattr(extra, "key", "") or ""
            if not key:
                continue
            for category in ("credential", "pii"):
                signal = _check_keyword(
                    job_id=job_id,
                    cited_id=rec.id,
                    token=key,
                    source_kind="intent_extra_key",
                    category=category,
                    proprietary=proprietary,
                    rec_source=rec.source,
                )
                if signal:
                    out.append(signal)

        # Also scan the snippet for any extra keys hidden in code
        for token, source_kind in _yield_tokens("", snippet):
            for category in ("credential", "pii"):
                signal = _check_keyword(
                    job_id=job_id,
                    cited_id=rec.id,
                    token=token,
                    source_kind=source_kind,
                    category=category,
                    proprietary=proprietary,
                    rec_source=rec.source,
                )
                if signal:
                    out.append(signal)
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Match identifiers in code: word characters, at least 4 long
_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{3,}\b")
# Match string-literal keys passed to APIs like getString("auth_token")
_STRING_LITERAL_RE = re.compile(r'"([A-Za-z_][A-Za-z0-9_]{3,})"')


def _yield_tokens(direct_name: str, snippet: str):
    """
    Yield (token, source_kind) tuples extracted from a record's name
    and snippet.

    We yield two kinds of tokens:
      - direct_name (storage target, API name, URL): high-precision source
      - identifiers extracted from snippet: lower-precision, more matches
      - string literals from snippet: medium-precision, often the key
        passed to SharedPreferences/Bundle/Intent
    """
    seen = set()

    if direct_name and direct_name not in seen:
        yield direct_name, "direct_name"
        seen.add(direct_name)

    if snippet:
        for match in _STRING_LITERAL_RE.finditer(snippet):
            literal = match.group(1)
            if literal not in seen:
                yield literal, "string_literal"
                seen.add(literal)

        for match in _IDENT_RE.finditer(snippet):
            ident = match.group(0)
            if ident not in seen:
                yield ident, "identifier"
                seen.add(ident)


def _check_keyword(
    job_id, cited_id, token, source_kind, category, proprietary, rec_source
):
    """
    Look up a token in the keyword catalog. Return a SensitivitySignalRecord
    if it matches, None otherwise.

    Source-kind affects strength:
      - direct_name and string_literal matches keep their catalog strength
      - identifier matches are downgraded one level (more false positives)
    """
    normalized = _pats.normalize_token(token)
    if not normalized:
        return None

    strength = _pats.keyword_strength(normalized, category)
    if strength is None:
        return None

    # Identifier matches are noisier — downgrade by one level
    if source_kind == "identifier":
        strength = _downgrade(strength)
        if strength is None:
            return None

    return SensitivitySignalRecord(
        id=next_id(job_id, "sens"),
        confidence=_strength_to_confidence(strength),
        related_ids=[cited_id],
        source=rec_source,
        record_hash=compute_record_hash(
            api_call="sensitivity_keyword",
            extra=f"{cited_id}:{category}:{normalized}",
        ),
        cited_evidence_id=cited_id,
        category=category,
        signal_type=f"{category}_keyword:{source_kind}",
        signal_strength=strength,
        matched_token=token,
        rationale=(
            f"{source_kind.replace('_', ' ').capitalize()} "
            f"{token!r} matches a {category} keyword "
            f"({strength} strength). Suggests this evidence may "
            f"involve {category} data."
        ),
        in_proprietary_code=proprietary,
    )


def _pattern_signal(
    job_id, cited_id, category, signal_name, strength, matched,
    rationale, proprietary, rec_source,
):
    """Construct a SensitivitySignalRecord from a regex pattern match."""
    return SensitivitySignalRecord(
        id=next_id(job_id, "sens"),
        confidence=_strength_to_confidence(strength),
        related_ids=[cited_id],
        source=rec_source,
        record_hash=compute_record_hash(
            api_call="sensitivity_pattern",
            extra=f"{cited_id}:{signal_name}:{matched}",
        ),
        cited_evidence_id=cited_id,
        category=category,
        signal_type=f"{category}_pattern:{signal_name}",
        signal_strength=strength,
        matched_token=matched,
        rationale=rationale,
        in_proprietary_code=proprietary,
    )


def _is_proprietary(noise_signals: list[str]) -> bool:
    """A record is proprietary code unless its noise_signals say otherwise."""
    return not any(sig in _NON_PROPRIETARY_NOISE for sig in (noise_signals or []))


def _strength_to_confidence(strength: str) -> float:
    """Map signal strength to a Pydantic confidence float."""
    return {"high": 0.92, "medium": 0.75, "low": 0.55}.get(strength, 0.5)


def _downgrade(strength: str) -> str | None:
    """One-level downgrade. low downgrades to None (don't emit)."""
    return {"high": "medium", "medium": "low"}.get(strength)