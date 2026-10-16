import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from app.utils import config


@dataclass
class SignatureScheme:
    """One signature scheme entry from apksigner --verbose output.

    `version` is the scheme identifier: '1', '2', '3', '3.1', '4', or
    'SourceStamp'. `verified` is the boolean parsed from the line.
    """
    version: str
    verified: bool


@dataclass
class Signer:
    """One signer entry from apksigner --verbose output. All fields
    optional because not every signer reports every field — some APKs
    have only one digest type, some lack the algorithm info, etc."""
    index: int                                  # 1-based, matches "Signer #N"
    distinguished_name: str | None = None       # full DN string
    sha256: str | None = None                   # certificate SHA-256 digest (hex)
    sha1: str | None = None                     # certificate SHA-1 digest (hex)
    md5: str | None = None                      # certificate MD5 digest (hex)
    key_algorithm: str | None = None            # e.g. "RSA"
    key_size_bits: int | None = None            # e.g. 2048
    public_key_sha256: str | None = None        # public-key SHA-256 (hex)
    public_key_sha1: str | None = None          # public-key SHA-1 (hex)
    public_key_md5: str | None = None           # public-key MD5 (hex)


@dataclass
class ApksignerResult:
    success: bool
    job_id: str
    output_dir: Path
    verified_overall: bool | None = None        # True / False / None on parse failure
    schemes: list[SignatureScheme] = field(default_factory=list)
    signers: list[Signer] = field(default_factory=list)
    num_signers_reported: int | None = None     # from "Number of signers: N"
    # Lines apksigner emits below the scheme list. Useful even on success
    # because some warnings indicate weak hashes, missing schemes, etc.
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    raw_output_path: Path | None = None
    error: str | None = None                    # tool-level error, not verification error


# Per-scheme verification line. Captures both numbered schemes and
# SourceStamp, in the same loop. SourceStamp is an auxiliary signing
# mechanism for tracking distribution channel; included here for
# completeness even though it isn't a "primary" signing scheme.
_SCHEME_LINE_RE = re.compile(
    r"Verified\s+(?:using\s+v(?P<version>[0-9.]+)\s+scheme|for\s+(?P<sourcestamp>SourceStamp))"
    r"[^:]*:\s*(?P<verified>true|false)",
    re.IGNORECASE,
)

# Top-level verdict markers.
_VERIFIES_RE = re.compile(r"^Verifies$", re.MULTILINE)
_DOES_NOT_VERIFY_RE = re.compile(r"^DOES NOT VERIFY$", re.MULTILINE)

# Number of signers banner that appears before the per-signer block.
_NUM_SIGNERS_RE = re.compile(r"^Number of signers:\s*(\d+)$", re.MULTILINE)

# Per-signer field patterns. The "Signer #N" prefix attributes each line
# to a specific signer entry, so we group results by N.
_SIGNER_DN_RE = re.compile(
    r"^Signer\s+#(?P<num>\d+)\s+certificate DN:\s*(?P<dn>.+)$",
    re.MULTILINE,
)
_SIGNER_SHA256_RE = re.compile(
    r"^Signer\s+#(?P<num>\d+)\s+certificate SHA-256 digest:\s*(?P<digest>[0-9a-fA-F]+)$",
    re.MULTILINE,
)
_SIGNER_SHA1_RE = re.compile(
    r"^Signer\s+#(?P<num>\d+)\s+certificate SHA-1 digest:\s*(?P<digest>[0-9a-fA-F]+)$",
    re.MULTILINE,
)
_SIGNER_MD5_RE = re.compile(
    r"^Signer\s+#(?P<num>\d+)\s+certificate MD5 digest:\s*(?P<digest>[0-9a-fA-F]+)$",
    re.MULTILINE,
)
_SIGNER_KEY_ALGO_RE = re.compile(
    r"^Signer\s+#(?P<num>\d+)\s+key algorithm:\s*(?P<algo>.+)$",
    re.MULTILINE,
)
_SIGNER_KEY_SIZE_RE = re.compile(
    r"^Signer\s+#(?P<num>\d+)\s+key size \(bits\):\s*(?P<bits>\d+)$",
    re.MULTILINE,
)
_SIGNER_PK_SHA256_RE = re.compile(
    r"^Signer\s+#(?P<num>\d+)\s+public key SHA-256 digest:\s*(?P<digest>[0-9a-fA-F]+)$",
    re.MULTILINE,
)
_SIGNER_PK_SHA1_RE = re.compile(
    r"^Signer\s+#(?P<num>\d+)\s+public key SHA-1 digest:\s*(?P<digest>[0-9a-fA-F]+)$",
    re.MULTILINE,
)
_SIGNER_PK_MD5_RE = re.compile(
    r"^Signer\s+#(?P<num>\d+)\s+public key MD5 digest:\s*(?P<digest>[0-9a-fA-F]+)$",
    re.MULTILINE,
)

# Warning and error lines that apksigner emits below the scheme list.
_WARNING_RE = re.compile(r"^WARNING:\s*(.+)$", re.MULTILINE)
_ERROR_RE = re.compile(r"^ERROR:\s*(.+)$", re.MULTILINE)


def _resolve_apksigner_binary() -> str | None:
    """Resolve the apksigner binary path. Prefer the config setting if
    provided; otherwise look on PATH. Returns None if neither yields a
    usable path."""
    configured = getattr(config, "APKSIGNER_BIN", None)
    if configured:
        return configured
    return shutil.which("apksigner")


def _parse_schemes(stdout: str) -> list[SignatureScheme]:
    schemes: list[SignatureScheme] = []
    for m in _SCHEME_LINE_RE.finditer(stdout):
        version = m.group("version") or m.group("sourcestamp")
        verified = m.group("verified").lower() == "true"
        schemes.append(SignatureScheme(version=version, verified=verified))
    return schemes


def _parse_signers(stdout: str) -> list[Signer]:
    """Build per-signer records by walking each pattern and grouping
    results by signer index. Some fields are present for every signer
    (DN, SHA-256); others (key algorithm, public-key digests) may be
    absent depending on the apksigner version and APK contents."""
    by_index: dict[int, dict] = {}

    field_patterns = [
        (_SIGNER_DN_RE, "dn", "distinguished_name", str.strip),
        (_SIGNER_SHA256_RE, "digest", "sha256", str.lower),
        (_SIGNER_SHA1_RE, "digest", "sha1", str.lower),
        (_SIGNER_MD5_RE, "digest", "md5", str.lower),
        (_SIGNER_KEY_ALGO_RE, "algo", "key_algorithm", str.strip),
        (_SIGNER_KEY_SIZE_RE, "bits", "key_size_bits", int),
        (_SIGNER_PK_SHA256_RE, "digest", "public_key_sha256", str.lower),
        (_SIGNER_PK_SHA1_RE, "digest", "public_key_sha1", str.lower),
        (_SIGNER_PK_MD5_RE, "digest", "public_key_md5", str.lower),
    ]

    for pattern, capture_group, attr, transform in field_patterns:
        for m in pattern.finditer(stdout):
            num = int(m.group("num"))
            value = m.group(capture_group)
            try:
                value = transform(value)
            except (ValueError, TypeError):
                # If transform fails (e.g. int() on garbage), keep the
                # raw string so the caller still sees something.
                pass
            by_index.setdefault(num, {})[attr] = value

    return [
        Signer(index=num, **fields)
        for num, fields in sorted(by_index.items())
    ]


def run_apksigner(job_id: str, apk_path: Path, artifacts_dir: Path) -> ApksignerResult:
    """
    Verify an APK's signatures using apksigner and parse all available
    fields from the verbose output.

    Produces:
      - Top-level verified_overall flag from the "Verifies" / "DOES NOT
        VERIFY" line.
      - Per-scheme results (v1, v2, v3, v3.1, v4, SourceStamp) with
        each scheme's verified flag.
      - Per-signer records with DN, SHA-256/SHA-1/MD5 certificate
        digests, key algorithm, key size, and public-key digests where
        present.
      - Warnings and errors apksigner emits below the scheme list.
      - The raw apksigner output saved at
        {artifacts_dir}/{job_id}/apksigner/output.txt for audit.

    Args:
        job_id:        Unique identifier for this analysis job.
        apk_path:      Absolute path to the APK file.
        artifacts_dir: Root directory where job artifacts are stored.

    Returns:
        ApksignerResult.

    Notes:
        - "Verification failed" is not the same as "tool failed". An APK
          that fails verification produces success=True with
          verified_overall=False; the per-scheme schemes list may also
          be populated, and errors will contain apksigner's complaints.
        - Tool failures (binary missing, malformed APK that crashes
          apksigner, timeout) produce success=False with the error
          field set.
    """
    apk_path = Path(apk_path).resolve()
    output_dir = (Path(artifacts_dir) / job_id / "apksigner").resolve()

    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    binary = _resolve_apksigner_binary()
    if not binary:
        return ApksignerResult(
            success=False,
            job_id=job_id,
            output_dir=output_dir,
            error=(
                "apksigner binary not found. Install Android build-tools "
                "and ensure 'apksigner' is on PATH, or set "
                "config.APKSIGNER_BIN to its absolute path."
            ),
        )

    # --verbose enables the per-scheme breakdown (Verified using vN
    # scheme: true/false). --print-certs enables the per-signer block
    # (Signer #N certificate DN, SHA-256/SHA-1/MD5 digests, key algo,
    # key size, public-key digests). Without --print-certs, apksigner
    # reports verification status but no signer info — empty
    # certificates list even on signed APKs.
    cmd = [binary, "verify", "--verbose", "--print-certs", str(apk_path)]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return ApksignerResult(
            success=False,
            job_id=job_id,
            output_dir=output_dir,
            error="apksigner timed out after 120s",
        )
    except FileNotFoundError:
        return ApksignerResult(
            success=False,
            job_id=job_id,
            output_dir=output_dir,
            error=f"apksigner binary not executable at {binary}",
        )

    # Save the raw output regardless of return code — parse results may
    # be useful even on non-zero exits, and the saved file gives auditors
    # something to inspect when behaviour seems off.
    raw_output_path = output_dir / "output.txt"
    raw_output_path.write_text(
        f"# stdout\n{proc.stdout}\n# stderr\n{proc.stderr}\n",
        encoding="utf-8",
    )

    # Filter _JAVA_OPTIONS noise from stderr the same way apktool_runner
    # does — these lines appear on every JVM invocation and aren't useful.
    stderr = "\n".join(
        line for line in proc.stderr.splitlines()
        if "Picked up _JAVA_OPTIONS" not in line
    ).strip()

    # Parse everything we can find in stdout, regardless of return code.
    verified_overall = (
        True if _VERIFIES_RE.search(proc.stdout)
        else False if _DOES_NOT_VERIFY_RE.search(proc.stdout)
        else None
    )
    schemes = _parse_schemes(proc.stdout)
    signers = _parse_signers(proc.stdout)
    warnings = [m.group(1).strip() for m in _WARNING_RE.finditer(proc.stdout)]
    errors_parsed = [m.group(1).strip() for m in _ERROR_RE.finditer(proc.stdout)]

    num_signers_match = _NUM_SIGNERS_RE.search(proc.stdout)
    num_signers_reported = (
        int(num_signers_match.group(1)) if num_signers_match else None
    )

    if proc.returncode != 0:
        # Non-zero with "DOES NOT VERIFY" in stdout is the documented
        # apksigner exit for verification failure. That's a successful
        # tool run reporting a failed verdict.
        if verified_overall is False:
            return ApksignerResult(
                success=True,
                job_id=job_id,
                output_dir=output_dir,
                verified_overall=False,
                schemes=schemes,
                signers=signers,
                num_signers_reported=num_signers_reported,
                warnings=warnings,
                errors=errors_parsed,
                raw_output_path=raw_output_path,
            )
        # Any other non-zero exit is a real tool failure (malformed APK,
        # missing keystore, etc.). Surface stderr as the error.
        return ApksignerResult(
            success=False,
            job_id=job_id,
            output_dir=output_dir,
            error=stderr or f"apksigner exited with code {proc.returncode}",
            raw_output_path=raw_output_path,
        )

    # Exit 0 + parser unable to determine verdict is unusual but possible
    # if apksigner's output format changes in a future version.
    if verified_overall is None:
        return ApksignerResult(
            success=False,
            job_id=job_id,
            output_dir=output_dir,
            error=(
                "apksigner exited successfully but neither 'Verifies' nor "
                "'DOES NOT VERIFY' was found in the output. Output format "
                "may have changed; see raw output for details."
            ),
            raw_output_path=raw_output_path,
        )

    return ApksignerResult(
        success=True,
        job_id=job_id,
        output_dir=output_dir,
        verified_overall=verified_overall,
        schemes=schemes,
        signers=signers,
        num_signers_reported=num_signers_reported,
        warnings=warnings,
        errors=errors_parsed,
        raw_output_path=raw_output_path,
    )