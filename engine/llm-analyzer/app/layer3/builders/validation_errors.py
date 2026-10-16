import logging
from datetime import datetime, timezone

from ..helpers import validation_errors as ve_registry
from ..models import GeneratedBy, ValidationError, ValidationErrorsFile

logger = logging.getLogger(__name__)

EXTRACTOR = "validation_error_collector_v1"
TOOL = "layer3-aggregator"


def build(job_id: str) -> ValidationErrorsFile:
    """
    Collect all validation and extraction errors registered during this
    job's Layer 3 run and write them to _validation_errors.json.

    This builder must be called last, after all other builders have run.

    Args:
        job_id: Analysis job identifier.

    Returns:
        Populated ValidationErrorsFile.
    """
    raw_errors = ve_registry.all_errors(job_id)
    errors = [ValidationError(**e) for e in raw_errors]

    return ValidationErrorsFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        errors=errors,
        silently_skipped_count=0,
    )