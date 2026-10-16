import ujson
import subprocess
import shutil
from pathlib import Path
from dataclasses import dataclass
from app.utils import config


@dataclass
class LibScoutResult:
    success: bool
    job_id: str
    output_dir: Path
    output_json: Path | None = None    # the libscout_<versionCode>.json file
    matched_libraries: int | None = None  # count from the JSON, for quick logging
    error: str | None = None


def _find_output_json(output_dir: Path) -> Path | None:
    """
    LibScout's `-j` flag writes one JSON file per APK into the output dir,
    with a name like 'duolingo_2113.json'. There should be exactly one;
    if multiple exist (e.g. from a previous run that wasn't cleaned),
    pick the most recently modified.
    """
    candidates = sorted(
        output_dir.rglob("*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def run_libscout(job_id: str, apk_path: Path, artifacts_dir: Path) -> LibScoutResult:
    """
    Detect bundled third-party libraries in an APK using LibScout.

    LibScout matches the APK's bytecode against a pre-built profile database
    of known libraries. The output identifies which obfuscated packages
    correspond to which libraries (e.g. 'y0' → 'androidx.interpolator 1.0.0'),
    which downstream L3 builders use to filter SDK code out of scope.

    LibScout requires:
      - The LibScout JAR (configurable at config.LIBSCOUT_JAR)
      - A directory of pre-built library profiles (config.LIBSCOUT_PROFILES_DIR)
      - An Android SDK root with platforms/android-XX/android.jar
        (config.ANDROID_SDK_DIR)

    Produces:
      - {artifacts_dir}/{job_id}/libscout/<apkname>_<versionCode>.json
        — LibScout's native output, kept for traceability.
      - LibScoutResult.output_json points at that file so downstream
        builders can consume it.

    Args:
        job_id:        Unique identifier for this analysis job.
        apk_path:      Absolute path to the APK file.
        artifacts_dir: Root directory where job artifacts are stored.
                       LibScout output lands in
                       {artifacts_dir}/{job_id}/libscout/.

    Returns:
        LibScoutResult with the path to the produced JSON.
    """
    apk_path = Path(apk_path).resolve()
    output_dir = (Path(artifacts_dir) / job_id / "libscout").resolve()

    # Clean any previous run for this job
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        "java", "-jar", config.LIBSCOUT_JAR,
        "-o", "match",                          # operation: match against profiles
        "-a", str(config.ANDROID_SDK_DIR),       # android SDK root (for android.jar)
        "-p", str(config.LIBSCOUT_PROFILES_DIR), # profile DB
        "-c", str(config.LIBSCOUT_CONFIG),
        "-j", str(output_dir),                   # write JSON output to this dir
        str(apk_path),
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )

    except subprocess.TimeoutExpired:
        return LibScoutResult(
            success=False,
            job_id=job_id,
            output_dir=output_dir,
            error="libscout timed out after 600s",
        )
    except FileNotFoundError:
        return LibScoutResult(
            success=False,
            job_id=job_id,
            output_dir=output_dir,
            error="java not found on PATH — is a JDK installed?",
        )

    # Filter out the _JAVA_OPTIONS noise from stderr
    stderr = "\n".join(
        line for line in proc.stderr.splitlines()
        if "Picked up _JAVA_OPTIONS" not in line
    ).strip()

    if proc.returncode != 0:
        return LibScoutResult(
            success=False,
            job_id=job_id,
            output_dir=output_dir,
            error=stderr or f"libscout exited with code {proc.returncode}",
        )

    output_json = _find_output_json(output_dir)
    if output_json is None:
        return LibScoutResult(
            success=False,
            job_id=job_id,
            output_dir=output_dir,
            error=(
                "libscout reported success but no JSON output was found "
                f"in {output_dir}. stdout (last 500 chars): "
                f"{proc.stdout[-500:] if proc.stdout else '(empty)'}"
            ),
        )

    # Peek at the JSON to populate matched_libraries — useful for logging
    # without requiring callers to re-parse. Failure here is non-fatal:
    # the JSON exists, the run succeeded, the count is just nice-to-have.
    matched_libraries = None
    try:
        with open(output_json) as f:
            data =ujson.load(f)
        matched_libraries = len(data.get("lib_matches", []))
    except Exception:
        pass

    return LibScoutResult(
        success=True,
        job_id=job_id,
        output_dir=output_dir,
        output_json=output_json,
        matched_libraries=matched_libraries,
    )