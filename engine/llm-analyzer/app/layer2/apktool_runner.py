import subprocess
import shutil
import hashlib
import xml.etree.ElementTree as ET
from pathlib import Path
from dataclasses import dataclass, field
from app.utils import config


@dataclass
class ApktoolResult:
    success: bool
    job_id: str
    output_dir: Path
    manifest_path: Path | None = None
    nsc_path: Path | None = None         # network_security_config.xml
    smali_dirs: list[Path] = field(default_factory=list)
    assets_dir: Path | None = None
    res_dir: Path | None = None
    apk_sha256: str | None = None
    error: str | None = None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _find_nsc(output_dir: Path, manifest_path: Path) -> Path | None:
    """
    Parse the manifest to find the declared networkSecurityConfig resource,
    then locate the corresponding XML file in res/xml/.
    """
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        app_el = root.find("application")
        if app_el is None:
            return None
        ns = "http://schemas.android.com/apk/res/android"
        nsc_attr = app_el.get(f"{{{ns}}}networkSecurityConfig")
        if not nsc_attr:
            return None
        # nsc_attr is like "@xml/network_security_config"
        filename = nsc_attr.split("/")[-1] + ".xml"
        candidate = output_dir / "res" / "xml" / filename
        return candidate if candidate.exists() else None
    except ET.ParseError:
        return None


def run_apktool(job_id: str, apk_path: Path, artifacts_dir: Path) -> ApktoolResult:
    """
    Decode an APK using Apktool and return structured paths to all outputs.

    Produces:
      - AndroidManifest.xml (decoded from binary XML)
      - res/  (decoded resources including network_security_config.xml)
      - assets/
      - smali/, smali_classes2/, smali_classes3/, ... (one dir per DEX)

    Args:
        job_id:       Unique identifier for this analysis job.
        apk_path:     Absolute path to the APK file.
        artifacts_dir: Root directory where job artifacts are stored.
                       Apktool output lands in {artifacts_dir}/{job_id}/apktool/.

    Returns:
        ApktoolResult with paths to all extracted artifacts.
    """
    apk_path = Path(apk_path).resolve()
    output_dir = (Path(artifacts_dir) / job_id / "apktool").resolve()

    # Clean any previous run for this job
    if output_dir.exists():
        shutil.rmtree(output_dir)

    cmd = [
        "java", "-jar", config.APKTOOL_JAR,
        "decode",
        "--output", str(output_dir),
        "--force",
        str(apk_path),
    ]

    try:
        #print("Output dir exists before run:", output_dir.exists())
        
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=20000,
        )

    except subprocess.TimeoutExpired:
        return ApktoolResult(
            success=False,
            job_id=job_id,
            output_dir=output_dir,
            error="apktool timed out after 120s",
        )
    except FileNotFoundError:
        return ApktoolResult(
            success=False,
            job_id=job_id,
            output_dir=output_dir,
            error="apktool binary not found — is it on PATH?",
        )

    # Filter out the _JAVA_OPTIONS noise from stderr
    stderr = "\n".join(
        line for line in proc.stderr.splitlines()
        if "Picked up _JAVA_OPTIONS" not in line
    ).strip()

    if proc.returncode != 0:
        return ApktoolResult(
            success=False,
            job_id=job_id,
            output_dir=output_dir,
            error=stderr or f"apktool exited with code {proc.returncode}",
        )

    # Locate manifest
    manifest_path = output_dir / "AndroidManifest.xml"
    if not manifest_path.exists():
        return ApktoolResult(
            success=False,
            job_id=job_id,
            output_dir=output_dir,
            error="AndroidManifest.xml not found in apktool output",
        )

    # Collect smali directories (smali, smali_classes2, smali_classes3, ...)
    smali_dirs = sorted(output_dir.glob("smali*"))

    # Optional dirs — may not exist in all APKs
    assets_dir = output_dir / "assets"
    res_dir = output_dir / "res"

    nsc_path = _find_nsc(output_dir, manifest_path)

    return ApktoolResult(
        success=True,
        job_id=job_id,
        output_dir=output_dir,
        manifest_path=manifest_path,
        nsc_path=nsc_path,
        smali_dirs=smali_dirs,
        assets_dir=assets_dir if assets_dir.exists() else None,
        res_dir=res_dir if res_dir.exists() else None,
        apk_sha256=_sha256(apk_path),
    )