import logging
from datetime import datetime, timezone

from ..helpers.ids import next_id
from ..models import DeepLinkRecord, DeepLinksFile, GeneratedBy, Source

logger = logging.getLogger(__name__)

EXTRACTOR = "deep_link_aggregator_v1"
TOOL = "apktool-2.12.1"

_BROWSABLE = "android.intent.category.BROWSABLE"
_VIEW = "android.intent.action.VIEW"


def build(job_id: str, components_file) -> DeepLinksFile:
    """
    Aggregate all deep link entries from the already-built ComponentsFile.

    Deep links are activities with intent filters that have both a data
    scheme/host and the BROWSABLE category. This builder derives its output
    from the components evidence rather than re-parsing the manifest.

    Args:
        job_id:          Analysis job identifier.
        components_file: ComponentsFile produced by the components builder.

    Returns:
        Populated DeepLinksFile.
    """
    records: list[DeepLinkRecord] = []

    for comp in components_file.records:
        if comp.type != "activity":
            continue

        for intent_filter in comp.intent_filters:
            if not _is_deep_link_filter(intent_filter):
                continue

            for data in intent_filter.data:
                if not data.scheme:
                    continue

                is_browsable = _BROWSABLE in intent_filter.categories
                is_app_link = (
                    data.scheme == "https"
                    and intent_filter.auto_verify
                    and is_browsable
                )

                records.append(DeepLinkRecord(
                    id=next_id(job_id, "dl"),
                    activity_id=comp.id,
                    activity_name=comp.name,
                    scheme=data.scheme,
                    host=data.host,
                    port=data.port,
                    path=data.path,
                    path_pattern=data.path_pattern,
                    path_prefix=data.path_prefix,
                    mime_type=data.mime_type,
                    auto_verify=intent_filter.auto_verify,
                    is_browsable=is_browsable,
                    is_app_link=is_app_link,
                    confidence=1.0,
                    related_ids=[comp.id],
                    source=Source(
                        artifact="manifest",
                        path="AndroidManifest.xml",
                        xpath=comp.source.xpath,
                        extractor=EXTRACTOR,
                        tool=TOOL,
                    ),
                ))

    return DeepLinksFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=records,
    )


def _is_deep_link_filter(intent_filter) -> bool:
    """
    A filter qualifies as a deep link when it has:
    - VIEW action (or no actions, which implies general data handling)
    - At least one data element with a scheme
    """
    has_view = not intent_filter.actions or _VIEW in intent_filter.actions
    has_data = any(d.scheme for d in intent_filter.data)
    return has_view and has_data