"""
App capabilities builder.

Detects OS-contracted behavioral capabilities by reading evidence from
other Layer 3 builders. Produces facts only — no appropriateness
judgments, no category labels.

The capabilities here are the ones that can be detected reliably from
static analysis:

  Reliable (OS-enforced contracts):
    - implements_vpn_service
    - implements_autofill_service
    - uses_accessibility_service
    - implements_input_method_service
    - implements_device_admin
    - implements_notification_listener
    - declares_browsable_https_links

  Moderately reliable (taint-traced or pattern-matched):
    - loads_url_from_user_input
    - writes_to_downloads_directory
    - reads_from_external_storage
    - has_file_provider

Each capability record includes:
    detected         (bool)            whether the capability is present
    confidence       (float 0.0-1.0)   how reliable the detection is
    evidence_ids     (list[str])       cross-references to source evidence
    rationale        (str | None)      brief why-this-was-detected note

The builder runs after all primary builders. It does NOT call out to
the network or invoke any LLM. It is pure derivation from existing
evidence.
"""

import logging
from datetime import datetime, timezone

from ..helpers.record_hash import compute_record_hash
from ..models import (
    AppCapabilitiesFile, CapabilityFlag, GeneratedBy, Source,
)

logger = logging.getLogger(__name__)

EXTRACTOR = "app_capabilities_v1"
TOOL = "layer3-aggregator"

# OS-contracted intent actions that prove a capability
# Source: Android framework documentation
_VPN_SERVICE_ACTIONS = {"android.net.VpnService"}
_AUTOFILL_SERVICE_ACTIONS = {"android.service.autofill.AutofillService"}
_ACCESSIBILITY_SERVICE_ACTIONS = {"android.accessibilityservice.AccessibilityService"}
_INPUT_METHOD_ACTIONS = {"android.view.InputMethod"}
_DEVICE_ADMIN_ACTIONS = {"android.app.action.DEVICE_ADMIN_ENABLED"}
_NOTIFICATION_LISTENER_ACTIONS = {"android.service.notification.NotificationListenerService"}

# OS-enforced permissions that gate these capabilities
_VPN_PERMISSION = "android.permission.BIND_VPN_SERVICE"
_AUTOFILL_PERMISSION = "android.permission.BIND_AUTOFILL_SERVICE"
_ACCESSIBILITY_PERMISSION = "android.permission.BIND_ACCESSIBILITY_SERVICE"
_INPUT_METHOD_PERMISSION = "android.permission.BIND_INPUT_METHOD"
_DEVICE_ADMIN_PERMISSION = "android.permission.BIND_DEVICE_ADMIN"
_NOTIFICATION_LISTENER_PERMISSION = "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"


def build(
    job_id: str,
    components_file=None,
    permissions_file=None,
    deep_links_file=None,
    webview_usage_file=None,
    storage_usage_file=None,
    api_usages_file=None,
    manifest_findings_file=None,
) -> AppCapabilitiesFile:
    """
    Aggregate behavioral capability flags from existing evidence.

    All arguments are optional — when an evidence file is missing
    (because its builder failed), the corresponding capabilities are
    flagged as unknown rather than detected/not-detected.

    Args:
        job_id:                  Analysis job identifier.
        components_file:         ComponentsFile.
        permissions_file:        PermissionsFile.
        deep_links_file:         DeepLinksFile.
        webview_usage_file:      WebViewUsageFile.
        storage_usage_file:      StorageUsageFile.
        api_usages_file:         ApiUsagesFile.
        manifest_findings_file:  ManifestFindingsFile.

    Returns:
        Populated AppCapabilitiesFile.
    """
    capabilities: dict[str, CapabilityFlag] = {}

    # OS-contracted services
    capabilities["implements_vpn_service"] = _detect_service_capability(
        job_id=job_id,
        components_file=components_file,
        permissions_file=permissions_file,
        intent_actions=_VPN_SERVICE_ACTIONS,
        gate_permission=_VPN_PERMISSION,
        capability_label="VPN service",
    )

    capabilities["implements_autofill_service"] = _detect_service_capability(
        job_id=job_id,
        components_file=components_file,
        permissions_file=permissions_file,
        intent_actions=_AUTOFILL_SERVICE_ACTIONS,
        gate_permission=_AUTOFILL_PERMISSION,
        capability_label="Autofill service",
    )

    capabilities["uses_accessibility_service"] = _detect_service_capability(
        job_id=job_id,
        components_file=components_file,
        permissions_file=permissions_file,
        intent_actions=_ACCESSIBILITY_SERVICE_ACTIONS,
        gate_permission=_ACCESSIBILITY_PERMISSION,
        capability_label="Accessibility service",
    )

    capabilities["implements_input_method_service"] = _detect_service_capability(
        job_id=job_id,
        components_file=components_file,
        permissions_file=permissions_file,
        intent_actions=_INPUT_METHOD_ACTIONS,
        gate_permission=_INPUT_METHOD_PERMISSION,
        capability_label="Input method (keyboard) service",
    )

    capabilities["implements_device_admin"] = _detect_service_capability(
        job_id=job_id,
        components_file=components_file,
        permissions_file=permissions_file,
        intent_actions=_DEVICE_ADMIN_ACTIONS,
        gate_permission=_DEVICE_ADMIN_PERMISSION,
        capability_label="Device administration",
    )

    capabilities["implements_notification_listener"] = _detect_service_capability(
        job_id=job_id,
        components_file=components_file,
        permissions_file=permissions_file,
        intent_actions=_NOTIFICATION_LISTENER_ACTIONS,
        gate_permission=_NOTIFICATION_LISTENER_PERMISSION,
        capability_label="Notification listener service",
    )

    # Manifest-declared deep link reach
    capabilities["declares_browsable_https_links"] = _detect_browsable_https_links(
        job_id=job_id,
        deep_links_file=deep_links_file,
    )

    # Behavioral signals (lower confidence — inferred from code)
    capabilities["loads_url_from_user_input"] = _detect_user_url_loads(
        job_id=job_id,
        webview_usage_file=webview_usage_file,
    )

    capabilities["writes_to_downloads_directory"] = _detect_downloads_writes(
        job_id=job_id,
        storage_usage_file=storage_usage_file,
        api_usages_file=api_usages_file,
    )

    capabilities["reads_from_external_storage"] = _detect_external_storage_reads(
        job_id=job_id,
        storage_usage_file=storage_usage_file,
        permissions_file=permissions_file,
    )

    capabilities["has_file_provider"] = _detect_file_provider(
        job_id=job_id,
        components_file=components_file,
        manifest_findings_file=manifest_findings_file,
    )

    return AppCapabilitiesFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        capabilities=capabilities,
    )


# ---------------------------------------------------------------------------
# OS-contracted service detection
# ---------------------------------------------------------------------------

def _detect_service_capability(
    job_id: str,
    components_file,
    permissions_file,
    intent_actions: set[str],
    gate_permission: str,
    capability_label: str,
) -> CapabilityFlag:
    """
    Detect an OS-contracted service capability.

    A capability is considered detected when:
      1. A <service> component declares an intent-filter with one of
         the required actions, AND
      2. The component or app declares the corresponding BIND_* permission.

    Both conditions are OS-enforced — without them, Android refuses to
    bind to the service. Detection is therefore high-confidence (1.0).
    """
    if components_file is None or permissions_file is None:
        return _unknown_flag(
            job_id=job_id,
            capability_label=capability_label,
            reason="components or permissions evidence unavailable",
        )

    # Find services declaring any of the required actions
    matching_components: list[str] = []
    for comp in components_file.records:
        if comp.type != "service":
            continue
        for ifilter in comp.intent_filters:
            if any(action in intent_actions for action in ifilter.actions):
                matching_components.append(comp.id)
                break

    # Check if the gate permission is declared OR set on the matching service
    has_permission_declared = any(
        p.name == gate_permission for p in permissions_file.declared
    )
    has_permission_on_service = any(
        comp.permission == gate_permission
        for comp in components_file.records
        if comp.id in matching_components
    )

    if matching_components and (has_permission_declared or has_permission_on_service):
        return CapabilityFlag(
            detected=True,
            confidence=1.0,
            evidence_ids=matching_components,
            rationale=(
                f"{capability_label} declared with intent action and "
                f"{gate_permission} permission gate."
            ),
            record_hash=compute_record_hash(
                api_call="capability",
                extra=f"{capability_label}:detected",
            ),
        )

    if matching_components and not (has_permission_declared or has_permission_on_service):
        # Action declared but no permission gate — unusual, possibly malicious
        return CapabilityFlag(
            detected=True,
            confidence=0.6,
            evidence_ids=matching_components,
            rationale=(
                f"{capability_label} action declared but {gate_permission} "
                f"permission gate is missing. The OS may refuse to bind. "
                f"Treat with caution."
            ),
            record_hash=compute_record_hash(
                api_call="capability",
                extra=f"{capability_label}:partial",
            ),
        )

    return CapabilityFlag(
        detected=False,
        confidence=1.0,
        evidence_ids=[],
        rationale=None,
        record_hash=compute_record_hash(
            api_call="capability",
            extra=f"{capability_label}:absent",
        ),
    )


# ---------------------------------------------------------------------------
# Manifest-derived capabilities
# ---------------------------------------------------------------------------

def _detect_browsable_https_links(
    job_id: str,
    deep_links_file,
) -> CapabilityFlag:
    """
    Detect whether the app declares browsable https deep links.

    This is a strong signal that the app legitimately receives
    user-clicked or externally-shared URLs. Reliable because deep links
    are declared in the manifest.
    """
    if deep_links_file is None:
        return _unknown_flag(
            job_id=job_id,
            capability_label="Browsable HTTPS deep links",
            reason="deep_links evidence unavailable",
        )

    matching = [
        dl.id
        for dl in deep_links_file.records
        if dl.scheme == "https" and dl.is_browsable
    ]
    if matching:
        return CapabilityFlag(
            detected=True,
            confidence=1.0,
            evidence_ids=matching,
            rationale=(
                f"App declares {len(matching)} browsable HTTPS deep link(s). "
                f"It is reachable from web links and external sharing flows."
            ),
            record_hash=compute_record_hash(
                api_call="capability",
                extra="browsable_https_links:detected",
            ),
        )

    return CapabilityFlag(
        detected=False,
        confidence=1.0,
        evidence_ids=[],
        rationale=None,
        record_hash=compute_record_hash(
            api_call="capability",
            extra="browsable_https_links:absent",
        ),
    )


def _detect_file_provider(
    job_id: str,
    components_file,
    manifest_findings_file,
) -> CapabilityFlag:
    """
    Detect whether the app declares a FileProvider.

    A FileProvider is the standard way for an app to legitimately share
    files with other apps via content URIs. Presence is informational.
    """
    if components_file is None:
        return _unknown_flag(
            job_id=job_id,
            capability_label="FileProvider",
            reason="components evidence unavailable",
        )

    file_provider_classes = (
        "androidx.core.content.FileProvider",
        "android.support.v4.content.FileProvider",
    )
    matching = [
        comp.id
        for comp in components_file.records
        if comp.type == "provider"
        and any(comp.name.endswith(cls) or comp.name == cls for cls in file_provider_classes)
    ]
    if matching:
        return CapabilityFlag(
            detected=True,
            confidence=0.95,
            evidence_ids=matching,
            rationale="Standard Android FileProvider declared.",
            record_hash=compute_record_hash(
                api_call="capability",
                extra="file_provider:detected",
            ),
        )

    return CapabilityFlag(
        detected=False,
        confidence=0.85,
        evidence_ids=[],
        rationale=None,
        record_hash=compute_record_hash(
            api_call="capability",
            extra="file_provider:absent",
        ),
    )


# ---------------------------------------------------------------------------
# Code-derived behavioral capabilities
# ---------------------------------------------------------------------------

def _detect_user_url_loads(
    job_id: str,
    webview_usage_file,
) -> CapabilityFlag:
    """
    Detect WebView URL loads where the URL came from user input.

    This is the strongest single signal that the app legitimately
    handles user-controlled URLs (browser-like behavior). Detection
    relies on the intra-procedural taint marker on URL load records.

    Confidence is bounded by the limits of intra-procedural taint
    analysis — false negatives are likely when URLs flow through
    helpers, SharedPreferences, or service callbacks.
    """
    if webview_usage_file is None:
        return _unknown_flag(
            job_id=job_id,
            capability_label="Loads URL from user input",
            reason="webview_usage evidence unavailable",
        )

    user_url_sources = {"intent_extra", "intent_data", "user_input"}
    matching: list[str] = []

    for wv in webview_usage_file.records:
        # Check direct url_loads with user-derived sources
        for url_load in wv.url_loads:
            if url_load.url_source in user_url_sources:
                matching.append(wv.id)
                break

        # Or any taint source on the WebView record itself
        if wv.id not in matching:
            for ts in wv.taint_sources:
                if ts.source_type in {"intent_extra", "intent_data",
                                      "uri_parse", "user_input",
                                      "webview_input"}:
                    matching.append(wv.id)
                    break

    if matching:
        return CapabilityFlag(
            detected=True,
            confidence=0.75,
            evidence_ids=matching,
            rationale=(
                f"At least {len(matching)} WebView load(s) have URLs "
                f"originating from user-controlled sources (intent extras, "
                f"intent data, or user input). The app handles "
                f"user-controlled web content."
            ),
            record_hash=compute_record_hash(
                api_call="capability",
                extra="user_url_loads:detected",
            ),
        )

    if webview_usage_file.records:
        return CapabilityFlag(
            detected=False,
            confidence=0.6,
            evidence_ids=[],
            rationale=(
                "WebView usage detected but no user-controlled URL loads "
                "found. Note: intra-procedural taint analysis may miss "
                "URLs that flow through helpers or persistent storage."
            ),
            record_hash=compute_record_hash(
                api_call="capability",
                extra="user_url_loads:not_detected",
            ),
        )

    return CapabilityFlag(
        detected=False,
        confidence=0.95,
        evidence_ids=[],
        rationale="No WebView usage detected in the app.",
        record_hash=compute_record_hash(
            api_call="capability",
            extra="user_url_loads:no_webview",
        ),
    )


def _detect_downloads_writes(
    job_id: str,
    storage_usage_file,
    api_usages_file,
) -> CapabilityFlag:
    """
    Detect writes to the public Downloads directory or DownloadManager use.

    Reliable when DownloadManager is used (standard Android contract).
    Less reliable when the app writes to Environment.DIRECTORY_DOWNLOADS
    directly because that path may be referenced without being written to.
    """
    if storage_usage_file is None and api_usages_file is None:
        return _unknown_flag(
            job_id=job_id,
            capability_label="Writes to downloads directory",
            reason="storage_usage and api_usages evidence unavailable",
        )

    matching: list[str] = []
    confidence = 0.65

    # Strong signal: DownloadManager.enqueue
    if api_usages_file is not None:
        for api in api_usages_file.records:
            if "DownloadManager" in api.api_call or "enqueue" in api.snippet.lower():
                matching.append(api.id)
                confidence = max(confidence, 0.92)

    # Medium signal: storage_usage records targeting external/file_external
    # with paths suggesting Downloads
    if storage_usage_file is not None:
        for stor in storage_usage_file.records:
            if stor.category != "file_external":
                continue
            target_path = stor.storage_target.name if stor.storage_target else None
            if target_path and "download" in target_path.lower():
                matching.append(stor.id)
                confidence = max(confidence, 0.75)

    if matching:
        return CapabilityFlag(
            detected=True,
            confidence=confidence,
            evidence_ids=matching,
            rationale=(
                f"App has code that writes to the Downloads directory or "
                f"uses DownloadManager. {len(matching)} call site(s)."
            ),
            record_hash=compute_record_hash(
                api_call="capability",
                extra="downloads:detected",
            ),
        )

    return CapabilityFlag(
        detected=False,
        confidence=0.7,
        evidence_ids=[],
        rationale=None,
        record_hash=compute_record_hash(
            api_call="capability",
            extra="downloads:not_detected",
        ),
    )


def _detect_external_storage_reads(
    job_id: str,
    storage_usage_file,
    permissions_file,
) -> CapabilityFlag:
    """
    Detect reads from external (shared) storage.

    Combines code patterns with declared permissions. Apps that request
    READ_EXTERNAL_STORAGE or READ_MEDIA_* are signaling intent regardless
    of where the actual reads happen in code.
    """
    if storage_usage_file is None and permissions_file is None:
        return _unknown_flag(
            job_id=job_id,
            capability_label="Reads from external storage",
            reason="storage_usage and permissions evidence unavailable",
        )

    storage_matches: list[str] = []
    permission_matches: list[str] = []

    if storage_usage_file is not None:
        for stor in storage_usage_file.records:
            if stor.category == "file_external":
                storage_matches.append(stor.id)

    if permissions_file is not None:
        relevant_perms = {
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.MANAGE_EXTERNAL_STORAGE",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.READ_MEDIA_VIDEO",
            "android.permission.READ_MEDIA_AUDIO",
        }
        for perm in permissions_file.requested:
            if perm.name in relevant_perms:
                permission_matches.append(perm.id)

    if storage_matches and permission_matches:
        return CapabilityFlag(
            detected=True,
            confidence=0.95,
            evidence_ids=storage_matches + permission_matches,
            rationale=(
                "External storage read declared in permissions and used in code."
            ),
            record_hash=compute_record_hash(
                api_call="capability",
                extra="external_reads:strong",
            ),
        )

    if storage_matches or permission_matches:
        return CapabilityFlag(
            detected=True,
            confidence=0.75,
            evidence_ids=storage_matches + permission_matches,
            rationale=(
                "Partial signal: external storage either declared or used "
                "in code, but not both."
            ),
            record_hash=compute_record_hash(
                api_call="capability",
                extra="external_reads:partial",
            ),
        )

    return CapabilityFlag(
        detected=False,
        confidence=0.85,
        evidence_ids=[],
        rationale=None,
        record_hash=compute_record_hash(
            api_call="capability",
            extra="external_reads:not_detected",
        ),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _unknown_flag(job_id: str, capability_label: str, reason: str) -> CapabilityFlag:
    """Build a CapabilityFlag for cases where evidence is unavailable."""
    return CapabilityFlag(
        detected=False,
        confidence=0.0,
        evidence_ids=[],
        rationale=f"Cannot determine: {reason}",
        record_hash=compute_record_hash(
            api_call="capability",
            extra=f"{capability_label}:unknown",
        ),
    )