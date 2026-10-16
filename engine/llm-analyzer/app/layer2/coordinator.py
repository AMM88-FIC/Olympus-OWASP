import asyncio
from pathlib import Path
from dataclasses import dataclass
from typing import Iterable

from .apktool_runner import run_apktool, ApktoolResult
from .jadx_runner import run_jadx, JadxResult
from .androguard_runner import run_androguard, AndroguardResult
from .libscout_runner import run_libscout, LibScoutResult
from .apksigner_runner import run_apksigner, ApksignerResult


@dataclass
class ExtractionResult:
    job_id: str
    apk_path: Path
    apktool: ApktoolResult
    jadx: JadxResult
    androguard: AndroguardResult
    libscout: LibScoutResult
    apksigner: ApksignerResult

    @property
    def success(self) -> bool:
        """
        True only if Apktool succeeded — it provides the manifest which is
        required for all downstream analysis. JADX and Androguard failures
        are partial — analysis can continue with reduced coverage.
        """
        return self.apktool.success

    @property
    def coverage_notes(self) -> list[str]:
        """
        Human-readable notes about what coverage was lost due to tool failures.
        Passed into the LLM layer so it can qualify its findings appropriately.
        """
        notes = []
        if not self.jadx.success:
            notes.append(
                f"JADX decompilation failed ({self.jadx.error}). "
                "Semantic Java analysis unavailable — smali only."
            )
        if not self.androguard.success:
            notes.append(
                f"Androguard analysis failed ({self.androguard.error}). "
                "Call graph, string constants, and obfuscation signals unavailable."
            )
        if self.androguard.success and self.androguard.native_libraries:
            libs = ", ".join(self.androguard.native_libraries)
            notes.append(
                f"Native libraries detected: {libs}. "
                "Security logic inside .so files is not visible to static analysis."
            )
        if self.androguard.success and "dynamic_dex_loading" in self.androguard.obfuscation_signals:
            notes.append(
                "Dynamic DEX loading detected. "
                "Runtime-loaded code is not visible to static analysis."
            )
        return notes


async def _run_apktool_async(job_id, apk_path, artifacts_dir):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, run_apktool, job_id, apk_path, artifacts_dir
    )


async def _run_jadx_async(job_id, apk_path, artifacts_dir):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, run_jadx, job_id, apk_path, artifacts_dir
    )


async def _run_androguard_async(job_id, apk_path):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, run_androguard, job_id, apk_path
    )

async def _run_libscout_async(job_id, apk_path, artifacts_dir):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, run_libscout, job_id, apk_path, artifacts_dir
    )

async def _run_apksigner_async(job_id, apk_path, artifacts_dir):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, run_apksigner, job_id, apk_path, artifacts_dir
    )


async def run_extraction(
    job_id: str,
    apk_path: Path,
    artifacts_dir: Path,
    required_extractors: Iterable[str] | None = None,
) -> ExtractionResult:
    """
    Run Apktool, JADX, and Androguard in parallel and return all results.

    Apktool and JADX write to disk under {artifacts_dir}/{job_id}/.
    Androguard runs in-process and returns structured data directly.

    All three run concurrently — total time is bounded by the slowest tool
    (usually JADX on large apps).

    Args:
        job_id:       Unique identifier for this analysis job.
        apk_path:     Absolute path to the APK file.
        artifacts_dir: Root directory for all job artifact output.

    Returns:
        ExtractionResult containing results from all three tools.
    """
    apk_path = Path(apk_path)
    artifacts_dir = Path(artifacts_dir)
    requested = set(required_extractors or ["apktool", "jadx", "androguard", "libscout", "apksigner"])

    tasks: dict[str, asyncio.Task] = {}
    if "apktool" in requested:
        tasks["apktool"] = asyncio.create_task(_run_apktool_async(job_id, apk_path, artifacts_dir))
    if "jadx" in requested:
        tasks["jadx"] = asyncio.create_task(_run_jadx_async(job_id, apk_path, artifacts_dir))
    if "androguard" in requested:
        tasks["androguard"] = asyncio.create_task(_run_androguard_async(job_id, apk_path))
    if "libscout" in requested:
        tasks["libscout"] = asyncio.create_task(_run_libscout_async(job_id, apk_path, artifacts_dir))
    if "apksigner" in requested:
        tasks["apksigner"] = asyncio.create_task(_run_apksigner_async(job_id, apk_path, artifacts_dir))

    if tasks:
        await asyncio.gather(*tasks.values())

    apktool_result = tasks["apktool"].result() if "apktool" in tasks else ApktoolResult(
        success=False,
        job_id=job_id,
        output_dir=(artifacts_dir / job_id / "apktool"),
        error="skipped: not required",
    )
    jadx_result = tasks["jadx"].result() if "jadx" in tasks else JadxResult(
        success=False,
        job_id=job_id,
        output_dir=(artifacts_dir / job_id / "jadx"),
        error="skipped: not required",
    )
    androguard_result = tasks["androguard"].result() if "androguard" in tasks else AndroguardResult(
        success=False,
        job_id=job_id,
        error="skipped: not required",
    )
    libscout_result = tasks["libscout"].result() if "libscout" in tasks else LibScoutResult(
        success=False,
        job_id=job_id,
        output_dir=(artifacts_dir / job_id / "libscout"),
        error="skipped: not required",
    )
    apksigner_result = tasks["apksigner"].result() if "apksigner" in tasks else ApksignerResult(
        success=False,
        job_id=job_id,
        output_dir=(artifacts_dir / job_id / "apksigner"),
        error="skipped: not required",
    )

    return ExtractionResult(
        job_id=job_id,
        apk_path=apk_path,
        apktool=apktool_result,
        jadx=jadx_result,
        androguard=androguard_result,
        libscout=libscout_result,
        apksigner=apksigner_result
    )


def run_extraction_sync(
    job_id: str,
    apk_path: Path,
    artifacts_dir: Path,
    required_extractors: Iterable[str] | None = None,
) -> ExtractionResult:
    """Synchronous wrapper for use outside an async context (e.g. tests, CLI)."""
    return asyncio.run(run_extraction(job_id, apk_path, artifacts_dir, required_extractors=required_extractors))