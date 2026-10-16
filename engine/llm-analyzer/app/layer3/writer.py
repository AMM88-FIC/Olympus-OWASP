import ujson
import logging
from datetime import datetime, timezone
from pathlib import Path

from .models import EvidenceFile

logger = logging.getLogger(__name__)


def write(
    evidence: EvidenceFile,
    output_dir: Path,
    filename: str,
) -> Path | None:
    """
    Validate and serialize an EvidenceFile to JSON in output_dir.

    Validation is handled by Pydantic on the model itself. This function
    serializes and writes — it does not re-validate.

    Args:
        evidence:   A fully populated EvidenceFile subclass instance.
        output_dir: Directory to write into. Created if it doesn't exist.
        filename:   Output filename, e.g. "app_metadata.json".

    Returns:
        Path to the written file, or None on failure.
    """
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / filename

        payload = evidence.model_dump(exclude_none=False)

        # Inject generated_at timestamp if not already set
        if not payload.get("generated_at"):
            payload["generated_at"] = datetime.now(timezone.utc).isoformat()

        output_path.write_text(
           ujson.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.debug("Wrote %s (%d bytes)", output_path, output_path.stat().st_size)
        return output_path

    except Exception as exc:
        logger.error("Failed to write %s/%s: %s", output_dir, filename, exc)
        return None


def evidence_dir(artifacts_dir: Path, job_id: str) -> Path:
    """Return the standard evidence output directory for a job."""
    return Path(artifacts_dir) / job_id / "evidence"