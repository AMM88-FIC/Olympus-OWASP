import logging
from datetime import datetime, timezone

from ..helpers import file_status as fs_registry
from ..models import (
    AnalysisScope, CoverageFile, EvidenceFileCounts,
    FileStatus, GeneratedBy, ToolsSucceeded,
)

logger = logging.getLogger(__name__)

EXTRACTOR = "coverage_summarizer_v1"
TOOL = "layer3-aggregator"

_DEFAULT_LIMITATIONS = [
    "Server-side logic cannot be verified from APK alone.",
    "Runtime certificate pinning behavior requires dynamic testing.",
    "Taint tracking does not follow variables across method boundaries.",
    "Native library internals (.so files) are not decompiled.",
    "Dynamically registered JNI methods (RegisterNatives) may bind to "
    "symbols invisible to static analysis.",
    "Runtime behavior of resilience controls (root detection, anti-debugging) "
    "requires dynamic testing to verify effectiveness.",
]

_DOMAIN_LIMITATIONS: dict[str, list[str]] = {
    "MASVS-STORAGE": [
        "Files created at runtime are not inventoried.",
        "Encrypted database contents are not analyzed.",
    ],
    "MASVS-CRYPTO": [
        "Native crypto libraries are not analyzed.",
        "Dynamically loaded DEX is not analyzed.",
    ],
    "MASVS-AUTH": [
        "Auth decision logic is not modeled; LLM must read source.",
        "Session management at runtime is not observable statically.",
    ],
    "MASVS-NETWORK": [
        "Native networking code is not analyzed.",
        "Request destinations not fully resolved when computed at runtime.",
        "Actual traffic is not intercepted; TLS verification requires dynamic testing.",
    ],
    "MASVS-PLATFORM": [
        "Cross-procedural intent flows are not traced.",
        "Runtime IPC behavior is not observed.",
    ],
    "MASVS-CODE": [],
    "MASVS-RESILIENCE": [
        "Effectiveness of root/debug detection requires runtime testing.",
        "Anti-tamper internals in native libraries are not analyzed.",
    ],
    "MASVS-PRIVACY": [
        "Third-party SDK runtime data flows are not modeled.",
        "Data sent to remote endpoints is not observed.",
    ],
}


def build(
    job_id: str,
    apktool_result,
    jadx_result,
    androguard_result,
    obfuscation_file=None,
    components_file=None,
    permissions_file=None,
    deep_links_file=None,
    api_usages_file=None,
    crypto_usage_file=None,
    webview_usage_file=None,
    network_usage_file=None,
    storage_usage_file=None,
    outgoing_intents_file=None,
    strings_file=None,
    third_party_sdks_file=None,
    assets_file=None,
    native_methods_file=None,
    manifest_findings_file=None,
) -> CoverageFile:
    """
    Aggregate tool success/failure, extraction track, evidence counts,
    per-file scan status, and domain limitations into a single coverage
    summary that accompanies every LLM prompt.
    """
    tools_succeeded = ToolsSucceeded(
        apktool=apktool_result.success,
        jadx=jadx_result.success,
        androguard=androguard_result.success,
    )

    tools_failed = [
        name for name, ok in [
            ("apktool", apktool_result.success),
            ("jadx", jadx_result.success),
            ("androguard", androguard_result.success),
        ]
        if not ok
    ]

    extraction_track = "readable"
    if obfuscation_file and obfuscation_file.is_obfuscated:
        extraction_track = "bytecode"

    analysis_scope = AnalysisScope(
        reachability_performed=False,
        taint_analysis_performed=True,
        taint_analysis_scope="intraprocedural_only",
        native_code_analyzed=False,
        jni_bridge_mapped=bool(
            native_methods_file and native_methods_file.records
        ),
        snippet_context_lines=5,
    )

    limitations = list(_DEFAULT_LIMITATIONS)
    if obfuscation_file:
        limitations.extend(obfuscation_file.coverage_notes)
    if not jadx_result.success:
        limitations.append(
            f"JADX decompilation failed ({jadx_result.error}). "
            "Java source analysis unavailable — smali only."
        )
    if not androguard_result.success:
        limitations.append(
            f"Androguard analysis failed ({androguard_result.error}). "
            "Call graph, string constants, and SDK detection unavailable."
        )

    counts = EvidenceFileCounts(
        components=len(components_file.records) if components_file else 0,
        permissions_requested=len(permissions_file.requested) if permissions_file else 0,
        permissions_declared=len(permissions_file.declared) if permissions_file else 0,
        deep_links=len(deep_links_file.records) if deep_links_file else 0,
        api_usages=len(api_usages_file.records) if api_usages_file else 0,
        crypto_usage=len(crypto_usage_file.records) if crypto_usage_file else 0,
        webview_usage=len(webview_usage_file.records) if webview_usage_file else 0,
        network_usage=len(network_usage_file.records) if network_usage_file else 0,
        storage_usage=len(storage_usage_file.records) if storage_usage_file else 0,
        outgoing_intents=len(outgoing_intents_file.records) if outgoing_intents_file else 0,
        strings=len(strings_file.records) if strings_file else 0,
        third_party_sdks=len(third_party_sdks_file.records) if third_party_sdks_file else 0,
        assets_inventory=len(assets_file.records) if assets_file else 0,
        native_methods=len(native_methods_file.records) if native_methods_file else 0,
        meta_data=len(manifest_findings_file.meta_data) if manifest_findings_file else 0,
    )

    # Retrieve registered file statuses from the registry
    raw_statuses = fs_registry.get_all(job_id)
    file_status = {
        k: FileStatus(**v)
        for k, v in raw_statuses.items()
    }

    # Build domain limitations — extend defaults with native/dynamic coverage notes
    domain_lims = {k: list(v) for k, v in _DOMAIN_LIMITATIONS.items()}
    if obfuscation_file and obfuscation_file.is_obfuscated:
        for domain in ("MASVS-CRYPTO", "MASVS-NETWORK", "MASVS-STORAGE"):
            domain_lims.setdefault(domain, []).append(
                "App is obfuscated; bytecode extraction may miss patterns."
            )
    if obfuscation_file and not native_methods_file:
        for domain in ("MASVS-CRYPTO", "MASVS-NETWORK", "MASVS-RESILIENCE"):
            domain_lims.setdefault(domain, []).append(
                "Native libraries present but JNI bridge mapping failed or was skipped."
            )

    return CoverageFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        tools_succeeded=tools_succeeded,
        tools_failed=tools_failed,
        extraction_track=extraction_track,
        analysis_scope=analysis_scope,
        static_analysis_limitations=limitations,
        evidence_file_counts=counts,
        file_status=file_status,
        domain_limitations=domain_lims,
    )