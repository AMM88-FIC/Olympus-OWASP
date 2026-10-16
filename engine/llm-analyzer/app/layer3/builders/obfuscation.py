import logging
from datetime import datetime, timezone

from ..models import (
    GeneratedBy, ObfuscationFile, ObfuscationMetrics, ObfuscationSignal,
)

logger = logging.getLogger(__name__)

EXTRACTOR = "obfuscation_analyzer_v1"
TOOL = "androguard-4.1.3"

_SHORT_NAME_THRESHOLD = 3
_OBFUSCATION_RATIO_THRESHOLD = 0.30


def build(job_id: str, androguard_result, apktool_result) -> ObfuscationFile:
    """
    Analyze obfuscation signals from Androguard output and produce
    the obfuscation evidence file.

    Args:
        job_id:            Analysis job identifier.
        androguard_result: AndroguardResult from the extraction coordinator.
        apktool_result:    ApktoolResult — used to detect native libraries.

    Returns:
        Populated ObfuscationFile.
    """
    ar = androguard_result
    signals_raw = ar.obfuscation_signals or []
    classes = ar.classes or []

    metrics = _compute_metrics(classes, signals_raw)
    signals = _build_signals(signals_raw, classes, metrics)
    is_obfuscated = _determine_obfuscated(metrics, signals_raw)
    extraction_track = "bytecode" if is_obfuscated else "readable"

    native_libs = ar.native_libraries or []
    has_dynamic_loading = "dynamic_dex_loading" in signals_raw

    coverage_notes = []
    if native_libs:
        lib_names = ", ".join(
            lib if isinstance(lib, str) else lib.get("name", "?")
            for lib in native_libs
        )
        coverage_notes.append(
            f"Native libraries detected: {lib_names}. "
            "Security logic inside .so files is not visible to static analysis."
        )
    if has_dynamic_loading:
        coverage_notes.append(
            "Dynamic DEX loading detected. "
            "Runtime-loaded code is not visible to static analysis."
        )
    if is_obfuscated:
        coverage_notes.append(
            "App appears obfuscated. Extraction track switched to bytecode. "
            "JADX Java output may be incomplete or misleading for obfuscated classes."
        )

    return ObfuscationFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        is_obfuscated=is_obfuscated,
        extraction_track=extraction_track,
        signals=signals,
        metrics=metrics,
        native_analysis_available=False,
        coverage_notes=coverage_notes,
    )


def _compute_metrics(classes: list[str], signals: list[str]) -> ObfuscationMetrics:
    total = len(classes)
    short = 0
    if total:
        short = sum(
            1 for name in classes
            if len(name.split("/")[-1].rstrip(";")) <= _SHORT_NAME_THRESHOLD
        )

    return ObfuscationMetrics(
        short_class_name_ratio=round(short / total, 4) if total else 0.0,
        short_class_name_threshold=_SHORT_NAME_THRESHOLD,
        total_classes=total,
        packer_detected=None,
        string_encryption_detected=False,
        control_flow_obfuscation_detected=False,
    )


def _build_signals(
    raw_signals: list[str],
    classes: list[str],
    metrics: ObfuscationMetrics,
) -> list[ObfuscationSignal]:
    result = []

    if metrics.short_class_name_ratio > _OBFUSCATION_RATIO_THRESHOLD:
        result.append(ObfuscationSignal(
            signal="short_class_names",
            evidence_count=int(
                metrics.short_class_name_ratio * metrics.total_classes
            ),
            notes=(
                f"{metrics.short_class_name_ratio:.0%} of {metrics.total_classes} "
                f"classes have names of {_SHORT_NAME_THRESHOLD} chars or fewer"
            ),
        ))

    if "uses_reflection" in raw_signals:
        result.append(ObfuscationSignal(
            signal="uses_reflection",
            evidence_count=1,
            notes="One or more call sites invoke java.lang.reflect.Method.invoke",
        ))

    if "dynamic_dex_loading" in raw_signals:
        result.append(ObfuscationSignal(
            signal="dynamic_dex_loading",
            evidence_count=1,
            notes="DexClassLoader or InMemoryDexClassLoader detected",
        ))

    return result


def _determine_obfuscated(
    metrics: ObfuscationMetrics,
    raw_signals: list[str],
) -> bool:
    return (
        metrics.short_class_name_ratio > _OBFUSCATION_RATIO_THRESHOLD
        or "dynamic_dex_loading" in raw_signals
    )