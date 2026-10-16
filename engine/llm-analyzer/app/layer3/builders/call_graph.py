import logging
from datetime import datetime, timezone

from ..models import CallGraphFile, GeneratedBy

logger = logging.getLogger(__name__)

EXTRACTOR = "call_graph_builder_v1"
TOOL = "androguard-4.1.3"


def build(job_id: str, androguard_result) -> CallGraphFile:
    """
    Build call_graph.json from Androguard's pre-extracted call graph.

    Inverts the caller→callees map produced by L2 into a callee→callers
    index. The L4 find_callers tool queries by callee ("who calls this
    method?"), so we do the inversion once at build time.

    Args:
        job_id:            Analysis job identifier.
        androguard_result: AndroguardResult — uses .call_graph and
                           .package_name fields.

    Returns:
        Populated CallGraphFile.
    """
    ar = androguard_result
    call_graph = ar.call_graph or {}

    # Invert: callee_fqn → list of caller_fqns
    callers_of: dict[str, set[str]] = {}
    edge_count = 0
    for caller, callees in call_graph.items():
        for callee in callees:
            callers_of.setdefault(callee, set()).add(caller)
            edge_count += 1

    # Stable serialization: sort callers per callee, sort top-level by callee
    inverted_sorted = {
        callee: sorted(callers)
        for callee, callers in sorted(callers_of.items())
    }

    logger.debug(
        "Built call graph: %d methods with callers, %d total edges",
        len(inverted_sorted), edge_count,
    )

    return CallGraphFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        package_name=ar.package_name,
        callers=inverted_sorted,
        total_methods_with_callers=len(inverted_sorted),
        total_edges=edge_count,
    )