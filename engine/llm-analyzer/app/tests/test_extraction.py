from pathlib import Path
from app.extraction.coordinator import run_extraction_sync
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


result = run_extraction_sync(
job_id="test-001",
      apk_path=Path("/media/sf_KaliShared/Shared-Tools/llm-android-analyzer/DivaApplication.apk"),
      artifacts_dir=Path("storage/artifacts"),
    )

print("Apktool:", result.apktool.success)
print("  manifest:", result.apktool.manifest_path)
print("  nsc:", result.apktool.nsc_path)
print("  smali dirs:", result.apktool.smali_dirs)
print("  sha256:", result.apktool.apk_sha256)
print("Apktool error:", result.apktool.error)

print("JADX:", result.jadx.success)
print("  java files:", len(result.jadx.java_files))
print("  source dir:", result.jadx.source_dir)

print("Androguard:", result.androguard.success)
print("  package:", result.androguard.package_name)
print("  version:", result.androguard.version_name)
print("  min_sdk:", result.androguard.min_sdk)
print("  target_sdk:", result.androguard.target_sdk)
print("  permissions:", result.androguard.requested_permissions)
print("  obfuscation:", result.androguard.obfuscation_signals)
print("  native libs:", result.androguard.native_libraries)
print("  strings (sample):", result.androguard.string_constants[:5])

print("Coverage notes:", result.coverage_notes)
