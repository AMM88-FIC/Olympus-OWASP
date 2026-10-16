import subprocess
import shutil
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class JadxResult:
    success: bool
    job_id: str
    output_dir: Path
    source_dir: Path | None = None       # sources/  — Java-like decompiled code
    resources_dir: Path | None = None    # resources/ — JADX's own resource copy
    java_files: list[Path] = field(default_factory=list)
    error: str | None = None


def _collect_java_files(source_dir: Path) -> list[Path]:
    """Return all .java files produced by JADX, sorted for determinism."""
    return sorted(source_dir.rglob("*.java"))


def run_jadx(job_id: str, apk_path: Path, artifacts_dir: Path) -> JadxResult:
    """
    Decompile an APK to Java-like source using JADX CLI.

    Produces:
      - sources/   Java decompiled source tree, organized by package
      - resources/ JADX's copy of resources (secondary; Apktool is ground truth)

    The Java source tree is the primary input for LLM semantic reasoning.
    Smali (from Apktool) is used for verification when JADX output is ambiguous.

    Args:
        job_id:       Unique identifier for this analysis job.
        apk_path:     Absolute path to the APK file.
        artifacts_dir: Root directory where job artifacts are stored.
                       JADX output lands in {artifacts_dir}/{job_id}/jadx/.

    Returns:
        JadxResult with paths to decompiled source and a flat list of .java files.
    """
    apk_path = Path(apk_path).resolve()
    output_dir = (Path(artifacts_dir) / job_id / "jadx").resolve()

    if output_dir.exists():
        shutil.rmtree(output_dir)

    cmd = [
        "jadx",
        "--output-dir", str(output_dir),
        "--threads-count", "4",
        "--no-debug-info",       # cleaner output without debug metadata
        "--show-bad-code",       # include partially decompiled code rather than dropping it
        str(apk_path),
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=1200,         # large apps can take a while
        )
    except subprocess.TimeoutExpired:
        return JadxResult(
            success=False,
            job_id=job_id,
            output_dir=output_dir,
            error="jadx timed out after 300s",
        )
    except FileNotFoundError:
        return JadxResult(
            success=False,
            job_id=job_id,
            output_dir=output_dir,
            error="jadx binary not found — is it on PATH?",
        )

    # Filter Java options noise
    stderr = "\n".join(
        line for line in proc.stderr.splitlines()
        if "Picked up _JAVA_OPTIONS" not in line
    ).strip()

    # JADX exits 1 even on partial decompilation success — check for source output
    # rather than relying solely on the return code
    source_dir = output_dir / "sources"
    resources_dir = output_dir / "resources"

    if not source_dir.exists():
        return JadxResult(
            success=False,
            job_id=job_id,
            output_dir=output_dir,
            error=stderr or f"jadx produced no sources/ directory (exit {proc.returncode})",
        )

    java_files = _collect_java_files(source_dir)

    if not java_files:
        return JadxResult(
            success=False,
            job_id=job_id,
            output_dir=output_dir,
            error="jadx produced no .java files — app may be heavily obfuscated or native-only",
        )

    return JadxResult(
        success=True,
        job_id=job_id,
        output_dir=output_dir,
        source_dir=source_dir,
        resources_dir=resources_dir if resources_dir.exists() else None,
        java_files=java_files,
    )