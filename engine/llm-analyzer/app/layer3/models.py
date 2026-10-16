"""
Pydantic v2 models for all Layer 3 evidence files.
Schema version: 1.1

Every evidence record inherits from BaseRecord.
Every code-derived record inherits from CodeRecord.
Every top-level evidence file inherits from EvidenceFile.
"""

from __future__ import annotations
from typing import Literal, Any
from pydantic import BaseModel, Field


SCHEMA_VERSION = "1.2.2"

# ---------------------------------------------------------------------------
# Common substructures
# ---------------------------------------------------------------------------

class Source(BaseModel):
    artifact: Literal[
        "manifest", "java", "smali", "nsc_xml",
        "resource", "asset", "dex", "native_lib"
    ]
    path: str
    line_start: int | None = None
    line_end: int | None = None
    xpath: str | None = None
    dex_string_id: int | None = None
    extractor: str
    tool: str


class SnippetContext(BaseModel):
    before: list[str] = Field(default_factory=list)
    after: list[str] = Field(default_factory=list)
    window_lines: int = 5


class TaintSource(BaseModel):
    source_type: Literal[
        "intent_extra", "intent_data", "uri_parse", "broadcast_receive",
        "provider_query", "webview_input", "network_input", "clipboard",
        "file_read", "user_input", "unknown"
    ]
    expression: str
    parameter_position: int
    intraprocedural_only: bool = True
    confidence: float = Field(ge=0.0, le=1.0)


class GeneratedBy(BaseModel):
    extractor: str
    tool: str


# ---------------------------------------------------------------------------
# Base record types
# ---------------------------------------------------------------------------

class BaseRecord(BaseModel):
    id: str
    confidence: float = Field(ge=0.0, le=1.0)
    related_ids: list[str] = Field(default_factory=list)
    source: Source
    record_hash: str = ""   # SHA-256 of canonical fields; populated by builder


class NoiseSignal(BaseModel):
    signal: Literal[
        "in_test_code",
        "in_debug_only_class",
        "in_third_party_sdk",
        "in_generated_code",
        "in_kotlin_stdlib",
        "in_play_services"
    ]
    confidence: float = Field(ge=0.0, le=1.0)
    notes: str | None = None


class CodeRecord(BaseRecord):
    """Base for any record derived from Java or smali source."""
    caller_class: str
    caller_method: str
    snippet: str
    snippet_context: SnippetContext
    taint_sources: list[TaintSource] = Field(default_factory=list)
    reachable_from: list[str] = Field(default_factory=list)
    extraction_track: Literal["readable", "bytecode"]
    noise_signals: list[NoiseSignal] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Top-level evidence file base
# ---------------------------------------------------------------------------

class EvidenceFile(BaseModel):
    schema_version: str = SCHEMA_VERSION
    job_id: str
    generated_at: str        # ISO-8601
    generated_by: GeneratedBy


# ---------------------------------------------------------------------------
# 1. app_metadata.json
# ---------------------------------------------------------------------------

class DexFile(BaseModel):
    path: str
    size_bytes: int
    class_count: int


class NativeLibrary(BaseModel):
    name: str
    abis: list[str] = Field(default_factory=list)
    path: str
    size_bytes: int | None = None
    sha256: str | None = None


class Certificate(BaseModel):
    signer_index: int                                # 1-based, "Signer #N"
    distinguished_name: str | None = None            # full DN string
    sha256_fingerprint: str | None = None            # cert SHA-256 (hex)
    sha1_fingerprint: str | None = None              # cert SHA-1 (hex)
    md5_fingerprint: str | None = None               # cert MD5 (hex)
    key_algorithm: str | None = None                 # e.g. "RSA"
    key_size_bits: int | None = None                 # e.g. 2048
    public_key_sha256: str | None = None             # public-key SHA-256 (hex)
    public_key_sha1: str | None = None               # public-key SHA-1 (hex)
    public_key_md5: str | None = None                # public-key MD5 (hex)
    is_debug_cert: bool = False                      # derived from DN


class SigningScheme(BaseModel):
    """
    APK signing scheme presence flags.

    An APK can be signed with multiple schemes simultaneously. v1-only
    signing is vulnerable to the Janus attack (CVE-2017-13156); v2+ is
    required for security-relevant deployments. v4 is the incremental
    signing scheme (Android 11+).
    """
    version: str                # "1", "2", "3", "3.1", "4", "SourceStamp"
    verified: bool


class AppInfo(BaseModel):
    package_name: str
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    compile_sdk: int | None = None
    apk_sha256: str
    apk_size_bytes: int | None = None


class AppContext(BaseModel):
    category: Literal[
        "browser", "vpn", "password_manager", "banking", "health",
        "developer_tool", "messaging", "social", "ecommerce",
        "media", "productivity", "game", "generic", "unknown"
    ] = "unknown"
    category_source: Literal[
        "user_provided", "inferred_from_package", "default"
    ] = "default"
    interpretation_notes: list[str] = Field(default_factory=list)


class AppMetadataFile(EvidenceFile):
    app: AppInfo
    dex_files: list[DexFile] = Field(default_factory=list)
    native_libraries: list[NativeLibrary] = Field(default_factory=list)
    certificates: list[Certificate] = Field(default_factory=list)
    certificates_status: Literal[
        "extracted", "none_found", "extraction_failed", "unavailable", "unsigned"
    ] = "unavailable"
    signing_schemes: list[SigningScheme] = Field(default_factory=list)
    signatures_verified: bool | None = None
    app_context: AppContext = Field(default_factory=AppContext)
    extraction_track: Literal["readable", "bytecode"]
    source: Source


# ---------------------------------------------------------------------------
# 2. manifest_findings.json
# ---------------------------------------------------------------------------

class ManifestFlags(BaseModel):
    debuggable: bool | None = None
    allow_backup: bool | None = None
    uses_cleartext_traffic: bool | None = None
    network_security_config_ref: str | None = None
    target_sandbox_version: int | None = None
    extract_native_libs: bool | None = None
    full_backup_content_ref: str | None = None
    data_extraction_rules_ref: str | None = None
    task_affinity: str | None = None
    large_heap: bool | None = None
    allow_task_reparenting: bool | None = None
    test_only: bool | None = None


class MetaDataRecord(BaseRecord):
    name: str
    value: str | None = None
    resource_ref: str | None = None
    scope: Literal["application", "activity", "service", "receiver", "provider"]


class BackupRule(BaseModel):
    domain: Literal[
        "root", "file", "database", "sharedpref",
        "external", "device_only"
    ]
    path: str | None = None
    rule: Literal["include", "exclude"]
    requires_flag: str | None = None


class BackupPolicy(BaseModel):
    allow_backup_app_flag: bool | None = None
    full_backup_content_path: str | None = None
    data_extraction_rules_path: str | None = None
    cloud_backup_rules: list[BackupRule] = Field(default_factory=list)
    device_transfer_rules: list[BackupRule] = Field(default_factory=list)
    parsed: bool = False


class ManifestFindingsFile(EvidenceFile):
    flags: ManifestFlags
    meta_data: list[MetaDataRecord] = Field(default_factory=list)
    backup_policy: BackupPolicy = Field(default_factory=BackupPolicy)
    source: Source


# ---------------------------------------------------------------------------
# 3. components.json
# ---------------------------------------------------------------------------

class ExportedStatus(BaseModel):
    declared: bool | None = None        # None when attribute is absent
    implicit_from_intent_filter: bool = False
    effective: bool


class IntentFilterData(BaseModel):
    scheme: str | None = None
    host: str | None = None
    port: str | None = None
    path: str | None = None
    path_pattern: str | None = None
    path_prefix: str | None = None
    mime_type: str | None = None


class IntentFilter(BaseModel):
    actions: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    data: list[IntentFilterData] = Field(default_factory=list)
    auto_verify: bool = False
    priority: int = 0


class PathPermission(BaseModel):
    path: str | None = None
    path_pattern: str | None = None
    path_prefix: str | None = None
    read_permission: str | None = None
    write_permission: str | None = None


class ProviderSpecific(BaseModel):
    authorities: list[str] = Field(default_factory=list)
    read_permission: str | None = None
    write_permission: str | None = None
    grant_uri_permissions: bool = False
    path_permissions: list[PathPermission] = Field(default_factory=list)


class ComponentRecord(BaseRecord):
    type: Literal["activity", "service", "receiver", "provider"]
    name: str
    exported: ExportedStatus
    enabled: bool = True
    permission: str | None = None
    launch_mode: str | None = None
    task_affinity: str | None = None
    process: str | None = None
    intent_filters: list[IntentFilter] = Field(default_factory=list)
    meta_data: list[dict[str, Any]] = Field(default_factory=list)
    provider_specific: ProviderSpecific | None = None


class ComponentsFile(EvidenceFile):
    records: list[ComponentRecord] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 4. permissions.json
# ---------------------------------------------------------------------------

class PermissionRecord(BaseRecord):
    name: str
    protection_level: str | None = None
    is_dangerous: bool = False
    is_signature_only: bool = False
    max_sdk_version: int | None = None
    usage_min_sdk_version: int | None = None


class DeclaredPermissionRecord(BaseRecord):
    name: str
    protection_level: str | None = None
    label: str | None = None
    description: str | None = None


class PermissionsFile(EvidenceFile):
    requested: list[PermissionRecord] = Field(default_factory=list)
    declared: list[DeclaredPermissionRecord] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 5. network_security.json
# ---------------------------------------------------------------------------

class TrustAnchor(BaseModel):
    src: str
    override_pins: bool = False
    resolved_asset_id: str | None = None


class CertPin(BaseModel):
    digest: str
    value: str


class PinSet(BaseModel):
    expiration: str | None = None
    pins: list[CertPin] = Field(default_factory=list)


class BaseConfig(BaseModel):
    cleartext_traffic_permitted: bool | None = None
    trust_anchors: list[TrustAnchor] = Field(default_factory=list)


class DomainEntry(BaseModel):
    name: str
    include_subdomains: bool = False


class DomainConfigRecord(BaseRecord):
    domains: list[DomainEntry] = Field(default_factory=list)
    cleartext_traffic_permitted: bool | None = None
    trust_anchors: list[TrustAnchor] = Field(default_factory=list)
    pin_set: PinSet | None = None


class DebugOverrides(BaseModel):
    present: bool = False
    trust_anchors: list[TrustAnchor] = Field(default_factory=list)


class NetworkSecurityFile(EvidenceFile):
    nsc_present: bool
    nsc_path: str | None = None
    base_config: BaseConfig | None = None
    domain_configs: list[DomainConfigRecord] = Field(default_factory=list)
    debug_overrides: DebugOverrides = Field(default_factory=DebugOverrides)
    inferred_from_manifest: bool = False


# ---------------------------------------------------------------------------
# 6. deep_links.json
# ---------------------------------------------------------------------------

class DeepLinkRecord(BaseRecord):
    activity_id: str
    activity_name: str
    scheme: str | None = None
    host: str | None = None
    port: str | None = None
    path: str | None = None
    path_pattern: str | None = None
    path_prefix: str | None = None
    mime_type: str | None = None
    auto_verify: bool = False
    is_browsable: bool = False
    is_app_link: bool = False


class DeepLinksFile(EvidenceFile):
    records: list[DeepLinkRecord] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 7. api_usages.json
# ---------------------------------------------------------------------------

class ApiParameter(BaseModel):
    position: int
    type: str | None = None
    literal_value: str | None = None
    source_expression: str | None = None


class ApiUsageRecord(CodeRecord):
    domain: Literal[
        "ipc", "auth", "logging", "clipboard", "screenshots",
        "biometric", "dynamic_loading", "reflection", "root_detection",
        "debug_detection", "file_io", "notification"
    ]
    api_call: str
    caller_descriptor: str | None = None
    parameters: list[ApiParameter] = Field(default_factory=list)


class ApiUsagesFile(EvidenceFile):
    records: list[ApiUsageRecord] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 8. crypto_usage.json
# ---------------------------------------------------------------------------

class CryptoUsageRecord(CodeRecord):
    api_call: str
    algorithm: str | None = None
    mode: str | None = None
    padding: str | None = None
    key_size_bits: int | None = None
    provider: str | None = None
    iv_source: Literal[
        "hardcoded", "random", "derived", "reused", "unknown"
    ] | None = None
    key_source: Literal[
        "hardcoded", "keystore", "derived", "random",
        "unknown", "not_applicable"
    ] | None = None


class CryptoUsageFile(EvidenceFile):
    records: list[CryptoUsageRecord] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 9. webview_usage.json
# ---------------------------------------------------------------------------

class WebViewSettings(BaseModel):
    javascript_enabled: bool | None = None
    allow_file_access: bool | None = None
    allow_universal_access_from_file_urls: bool | None = None
    allow_content_access: bool | None = None
    dom_storage_enabled: bool | None = None
    database_enabled: bool | None = None
    mixed_content_mode: int | None = None
    safe_browsing_enabled: bool | None = None


class ExposedMethod(BaseModel):
    name: str
    descriptor: str | None = None
    annotated_javascript_interface: bool = False


class JavascriptInterface(BaseModel):
    bridge_object_class: str
    exposed_name: str
    exposed_methods: list[ExposedMethod] = Field(default_factory=list)


class UrlLoad(BaseModel):
    api: str
    url_source: Literal[
        "literal", "intent_extra", "intent_data",
        "shared_prefs", "network", "user_input", "unknown"
    ]
    literal_url: str | None = None
    snippet: str | None = None
    snippet_context: SnippetContext | None = None
    line: int | None = None


class WebViewRecord(BaseRecord):
    caller_class: str
    caller_method: str
    settings: WebViewSettings = Field(default_factory=WebViewSettings)
    javascript_interfaces: list[JavascriptInterface] = Field(default_factory=list)
    url_loads: list[UrlLoad] = Field(default_factory=list)
    taint_sources: list[TaintSource] = Field(default_factory=list)
    reachable_from: list[str] = Field(default_factory=list)
    extraction_track: Literal["readable", "bytecode"] = "readable"


class WebViewUsageFile(EvidenceFile):
    records: list[WebViewRecord] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 10. network_usage.json
# ---------------------------------------------------------------------------

class NetworkRequest(BaseModel):
    url_source: Literal[
        "literal", "string_ref", "intent_extra",
        "user_input", "config", "native", "unknown"
    ] = "unknown"
    scheme: Literal["https", "http", "dynamic", "unknown"] | None = None
    host: str | None = None
    path: str | None = None
    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH", "unknown"] | None = None
    literal_url: str | None = None
    related_string_id: str | None = None
    sends_sensitive_data: Literal["true", "false", "unknown"] = "unknown"


class NetworkUsageRecord(CodeRecord):
    category: Literal[
        "trust_manager", "hostname_verifier", "ssl_context",
        "pinning", "http_client", "url_connection"
    ]
    api_call: str
    pattern_detected: str | None = None
    returns_without_validation: bool | None = None
    request: NetworkRequest | None = None


class NetworkUsageFile(EvidenceFile):
    records: list[NetworkUsageRecord] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 11. storage_usage.json
# ---------------------------------------------------------------------------

class StorageTarget(BaseModel):
    name: str | None = None
    mode: str | None = None
    mode_is_world_readable: bool = False
    mode_is_world_writable: bool = False


class StorageUsageRecord(CodeRecord):
    category: Literal[
        "shared_preferences", "sqlite", "room", "realm",
        "file_internal", "file_external", "datastore",
        "cache_internal", "cache_external", "no_backup",
        "temp_file"
    ]
    api_call: str
    storage_target: StorageTarget | None = None
    contains_sensitive_keys_heuristic: list[str] = Field(default_factory=list)


class StorageUsageFile(EvidenceFile):
    records: list[StorageUsageRecord] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 12. outgoing_intents.json
# ---------------------------------------------------------------------------

class IntentExtra(BaseModel):
    key: str
    type_hint: str | None = None
    source_expression: str | None = None


class OutgoingIntentRecord(CodeRecord):
    api_call: Literal[
        "startActivity", "startActivityForResult", "sendBroadcast",
        "sendOrderedBroadcast", "sendStickyBroadcast",
        "startService", "bindService"
    ]
    intent_type: Literal["explicit", "implicit", "unknown"]
    target_component: str | None = None
    target_package: str | None = None
    action: str | None = None
    categories: list[str] = Field(default_factory=list)
    data_uri: str | None = None
    mime_type: str | None = None
    has_permission_guard: bool = False
    permission_guard: str | None = None
    extras_summary: list[IntentExtra] = Field(default_factory=list)
    flags: list[str] = Field(default_factory=list)


class OutgoingIntentsFile(EvidenceFile):
    records: list[OutgoingIntentRecord] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 13. strings.json
# ---------------------------------------------------------------------------

class StringCaller(BaseModel):
    caller_class: str
    caller_method: str
    source: Source


class StringRecord(BaseRecord):
    category: Literal[
        "url", "file_path", "suspicious_keyword", "possible_secret",
        "ip_address", "email", "jdbc_string", "ipc_action", "content_uri"
    ]
    value: str
    is_cleartext: bool | None = None
    entropy_bits: float | None = None
    referenced_in: list[StringCaller] = Field(default_factory=list)


class StringsFile(EvidenceFile):
    records: list[StringRecord] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 14. third_party_sdks.json
# ---------------------------------------------------------------------------

class SdkRecord(BaseRecord):
    name: str
    vendor: str | None = None
    category: list[str] = Field(default_factory=list)
    detected_packages: list[str] = Field(default_factory=list)
    class_count: int = 0
    version_hint: str | None = None


class ThirdPartySdksFile(EvidenceFile):
    records: list[SdkRecord] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 15. assets_inventory.json
# ---------------------------------------------------------------------------

class AssetRecord(BaseRecord):
    path: str
    size_bytes: int | None = None
    sha256: str | None = None
    mime_type: str | None = None
    kind: Literal[
        "config", "certificate", "certificate_store", "database",
        "javascript", "html", "private_key", "binary", "other"
    ]
    extension: str | None = None
    contains_sensitive_keys_heuristic: list[str] = Field(default_factory=list)
    referenced_by_nsc: bool = False


class AssetsInventoryFile(EvidenceFile):
    records: list[AssetRecord] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 16. native_methods.json
# ---------------------------------------------------------------------------

class JavaCaller(BaseModel):
    caller_class: str
    caller_method: str
    source: Source


class RegisterNativesLocation(BaseModel):
    caller_class: str
    caller_method: str
    source: Source


class NativeMethodRecord(BaseRecord):
    java_class: str
    java_method: str
    java_signature: str | None = None
    java_modifiers: list[str] = Field(default_factory=list)
    expected_jni_symbol: str | None = None
    found_in_library: str | None = None
    library_path: str | None = None
    symbol_present: bool = False
    symbol_type: str | None = None
    registered_dynamically: bool = False
    register_natives_location: RegisterNativesLocation | None = None
    java_callers: list[JavaCaller] = Field(default_factory=list)
    reachable_from: list[str] = Field(default_factory=list)


class NativeMethodsFile(EvidenceFile):
    records: list[NativeMethodRecord] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 17. obfuscation.json
# ---------------------------------------------------------------------------

class ObfuscationSignal(BaseModel):
    signal: str
    evidence_count: int = 0
    notes: str | None = None


class ObfuscationMetrics(BaseModel):
    short_class_name_ratio: float | None = None
    short_class_name_threshold: int = 3
    total_classes: int = 0
    packer_detected: str | None = None
    string_encryption_detected: bool = False
    control_flow_obfuscation_detected: bool = False


class ObfuscationFile(EvidenceFile):
    is_obfuscated: bool
    extraction_track: Literal["readable", "bytecode"]
    signals: list[ObfuscationSignal] = Field(default_factory=list)
    metrics: ObfuscationMetrics = Field(default_factory=ObfuscationMetrics)
    native_analysis_available: bool = False
    coverage_notes: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 18. coverage.json
# ---------------------------------------------------------------------------

class FileStatus(BaseModel):
    scan_completed: bool
    records_emitted: int
    extractor: str
    tool: str
    duration_ms: int | None = None
    errors: list[str] = Field(default_factory=list)
    blind_spots: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 19. _validation_errors.json
# ---------------------------------------------------------------------------

class ValidationError(BaseModel):
    builder: str
    file: str
    record_partial: dict = Field(default_factory=dict)
    error_type: str
    error_message: str
    timestamp: str


class ValidationErrorsFile(EvidenceFile):
    errors: list[ValidationError] = Field(default_factory=list)
    silently_skipped_count: int = 0


class ToolsSucceeded(BaseModel):
    apktool: bool = False
    jadx: bool = False
    androguard: bool = False


class AnalysisScope(BaseModel):
    reachability_performed: bool = False
    taint_analysis_performed: bool = False
    taint_analysis_scope: str = "intraprocedural_only"
    native_code_analyzed: bool = False
    jni_bridge_mapped: bool = False
    snippet_context_lines: int = 5


class EvidenceFileCounts(BaseModel):
    components: int = 0
    permissions_requested: int = 0
    permissions_declared: int = 0
    deep_links: int = 0
    api_usages: int = 0
    crypto_usage: int = 0
    webview_usage: int = 0
    network_usage: int = 0
    storage_usage: int = 0
    outgoing_intents: int = 0
    strings: int = 0
    third_party_sdks: int = 0
    assets_inventory: int = 0
    native_methods: int = 0
    meta_data: int = 0


class CoverageFile(EvidenceFile):
    tools_succeeded: ToolsSucceeded = Field(default_factory=ToolsSucceeded)
    tools_failed: list[str] = Field(default_factory=list)
    extraction_track: Literal["readable", "bytecode"]
    analysis_scope: AnalysisScope = Field(default_factory=AnalysisScope)
    static_analysis_limitations: list[str] = Field(default_factory=list)
    evidence_file_counts: EvidenceFileCounts = Field(default_factory=EvidenceFileCounts)
    file_status: dict[str, FileStatus] = Field(default_factory=dict)
    domain_limitations: dict[str, list[str]] = Field(default_factory=dict)



# ---------------------------------------------------------------------------
# 20. app_capabilities.json (added v1.2.1)
# ---------------------------------------------------------------------------

class CapabilityFlag(BaseModel):
    """
    A single behavioral capability flag derived from other evidence.

    detected:     True when the capability is present.
    confidence:   How reliable the detection is. 1.0 for OS-contracted
                  capabilities (VpnService, AutofillService, etc.).
                  0.6-0.8 for taint-traced or pattern-matched capabilities.
                  0.0 when evidence to detect was unavailable.
    evidence_ids: Cross-references to the records that support this flag.
    rationale:    Brief human-readable note explaining the detection,
                  or null when no rationale is needed.
    record_hash:  Content-based identity for caching and diffing.
    """
    detected: bool
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)
    rationale: str | None = None
    record_hash: str = ""


class AppCapabilitiesFile(EvidenceFile):
    """
    Top-level evidence file holding behavioral capability flags.

    capabilities is a dict keyed by capability name. The set of keys is
    fixed by the builder — adding a new capability requires updating
    both the builder and any test instructions that consume them.

    Verdict-time reasoning treats each capability as a fact. The verdict
    LLM does not infer additional capabilities; it only reads what is
    here.
    """
    capabilities: dict[str, CapabilityFlag] = Field(default_factory=dict)



# ---------------------------------------------------------------------------
# 21. native_binaries.json (added v1.2.2)
# ---------------------------------------------------------------------------

class SecurityFeatures(BaseModel):
    """ELF-level security feature flags. Directly answers MASTG-TEST-0044."""
    pie: bool = False
    nx: bool = False
    relro: Literal["none", "partial", "full"] = "none"
    stack_canary: bool = False
    fortify_source: bool = False
    symbols_stripped: bool = False


class InterestingImport(BaseModel):
    """An imported symbol that matched one of the curated categories."""
    name: str
    category: Literal[
        "crypto", "tls", "network", "process",
        "file_io", "dynamic", "debug_detection",
        "root_detection", "jni",
    ]
    source_library: str | None = None


class NativeImports(BaseModel):
    """
    Curated categorization of imported symbols.

    Categories with no matches are present as empty lists for schema
    consistency — verdict prompts can rely on `.get(key, [])` without
    runtime existence checks.
    """
    total_count: int = 0
    by_category: dict[str, list[str]] = Field(default_factory=dict)
    interesting_imports: list[InterestingImport] = Field(default_factory=list)


class JniEntryPoint(BaseModel):
    """A native function exported under the JNI Java_<class>_<method> convention."""
    symbol: str
    java_class: str
    java_method: str
    related_native_method_id: str | None = None


class NativeExports(BaseModel):
    total_count: int = 0
    jni_entry_points: list[JniEntryPoint] = Field(default_factory=list)
    registered_natives: bool = False


class NativeStringRecord(BaseRecord):
    """
    Filtered string from a native library's .rodata or .data sections.

    Only categorized strings are retained — uncategorized C runtime
    noise is dropped to keep file size bounded.
    """
    category: Literal[
        "url", "cleartext_url", "file_path", "suspicious_keyword",
        "possible_secret", "ip_address", "email", "jdbc_string",
        "ipc_action", "content_uri", "jni_signature",
        "hardcoded_api_key", "hardcoded_password", "bearer_token",
        "certificate_pin", "high_entropy_unknown",
    ]
    value: str
    is_cleartext: bool | None = None
    entropy_bits: float | None = None
    offset: int = 0
    section: Literal["rodata", "data", "unknown"] = "unknown"
    secret_detection_reason: Literal[
        "entropy", "keyword", "regex_match",
        "assignment_context", "api_context", "filename_context", "n/a",
    ] | None = None
    false_positive_likelihood: Literal["low", "medium", "high"] | None = None


class NativeBinaryRecord(BaseRecord):
    """
    One distinct native library binary, deduplicated by sha256 across ABIs.

    The `paths` and `abis` lists capture every location and ABI under
    which this exact binary content appears. Two libraries with the same
    name but different sha256 produce two records.
    """
    name: str
    paths: list[str] = Field(default_factory=list)
    abis: list[str] = Field(default_factory=list)
    size_bytes: int = 0
    sha256: str
    elf_class: Literal["ELF32", "ELF64", "unknown"] = "unknown"
    machine: Literal[
        "AArch64", "ARM", "x86", "x86_64",
        "MIPS", "RISC-V", "unknown",
    ] = "unknown"
    stripped: bool = False
    security_features: SecurityFeatures = Field(default_factory=SecurityFeatures)
    imports: NativeImports = Field(default_factory=NativeImports)
    exports: NativeExports = Field(default_factory=NativeExports)
    needed_libraries: list[str] = Field(default_factory=list)
    strings: list[NativeStringRecord] = Field(default_factory=list)
    suspicious_patterns: list[str] = Field(default_factory=list)


class NativeBinariesFile(EvidenceFile):
    records: list[NativeBinaryRecord] = Field(default_factory=list)
    total_libraries: int = 0
    total_records: int = 0
    total_strings: int = 0


# ---------------------------------------------------------------------------
# 22. sensitivity_signals.json (added v1.2.3)
# ---------------------------------------------------------------------------
 
class SensitivitySignalRecord(BaseRecord):
    """
    A single sensitivity signal pointing back at evidence elsewhere.
 
    The builder walks code-bearing records (storage_usage, api_usages,
    network_usage, crypto_usage, strings, outgoing_intents) and emits
    one SensitivitySignalRecord per match against the pattern catalog.
 
    cited_evidence_id:  the record this signal annotates
    category:           "credential" or "pii" — these are kept distinct
                        because they have different verdict implications
    signal_type:        which detection rule fired
                        (e.g. "credential_keyword", "google_api_key",
                        "us_ssn", "sensitive_api_call")
    signal_strength:    "high" | "medium" | "low" — calibrated by the
                        catalog and adjusted for code provenance
    matched_token:      what specifically matched (variable name,
                        regex group, API name)
    rationale:          human-readable explanation for the rationale
                        the LLM can quote
    in_proprietary_code: bool — True when the originating record is in
                        first-party code; False when it's in third-party
                        SDK / generated / test code. Verdict prompts
                        should weight signals from first-party code more
                        heavily.
    """
    cited_evidence_id: str
    category: Literal["credential", "pii"]
    signal_type: str
    signal_strength: Literal["high", "medium", "low"]
    matched_token: str
    rationale: str
    in_proprietary_code: bool = True
 
 
class SensitivitySignalsFile(EvidenceFile):
    """
    Top-level evidence file holding sensitivity signal records.
 
    Records are organized as a flat list. Verdict prompts that need
    signals for a specific evidence record can filter by
    `cited_evidence_id`.
 
    The two summary counts at the top are pre-computed to save the LLM
    from counting them itself, which is useful for prompts that need
    high-level context like "does this app handle credentials at all?"
    """
    records: list[SensitivitySignalRecord] = Field(default_factory=list)
    credential_signal_count: int = 0
    pii_signal_count: int = 0
    proprietary_signal_count: int = 0
    third_party_signal_count: int = 0


# ---------------------------------------------------------------------------
# 23. detected_libraries.json
# ---------------------------------------------------------------------------

class DetectedLibraryRecord(BaseModel):
    id: str
    obfuscated_name: str            # the package as it appears in the APK, e.g. "y0"
    detected_package: str           # LibScout's library attribution, e.g.
                                    # "androidx.interpolator::interpolator"
    confidence: float               # LibScout's simScore, 0.0-1.0


class DetectedLibrariesFile(EvidenceFile):
    records: list[DetectedLibraryRecord] = Field(default_factory=list)


class CallGraphFile(EvidenceFile):
    """Callee→callers index for the APK.
    Stores an inverted call graph: for each method that has at least one
    caller, the list of methods that invoke it. Used by the L4
    find_callers tool to answer 'is this method reachable from
    proprietary code?' and similar reachability questions.

    The caller→callees direction is what Androguard exposes natively; we
    invert it once at L3 build time so the L4 tool can query by callee
    without scanning the whole graph.

    Method FQNs use Java-style 'package.Class.method' notation with
    class.method granularity (overloaded methods collapse to one node).
    Framework callers (java.*, javax.*, android.*, kotlin.*, androidx.*)
    are excluded at L2 extraction time.
    """
    package_name: str | None = None
    callers: dict[str, list[str]] = {}
    total_methods_with_callers: int = 0
    total_edges: int = 0