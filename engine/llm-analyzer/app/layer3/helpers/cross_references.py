"""
Second-pass cross-reference resolution.

After all primary builders have run, this module populates related_ids
across evidence files. It is intentionally a post-processing step so
builders don't need to know about each other's output order.
"""

import logging

logger = logging.getLogger(__name__)


def resolve_all(
    components_file,
    deep_links_file,
    permissions_file,
    strings_file,
    network_usage_file,
    webview_usage_file,
    storage_usage_file,
    crypto_usage_file,
    outgoing_intents_file,
    assets_inventory_file,
    native_methods_file,
    native_binaries_file,
    network_security_file,
) -> None:
    """
    Mutate `related_ids` fields in-place across all evidence files.

    This must be called after every primary builder has produced its output.
    Failures are logged and skipped — a missing cross-reference never crashes
    the pipeline.
    """
    try:
        _link_components_to_deep_links(components_file, deep_links_file)
    except Exception as e:
        logger.debug("cross_ref components→deep_links failed: %s", e)

    try:
        _link_deep_links_to_components(deep_links_file, components_file)
    except Exception as e:
        logger.debug("cross_ref deep_links→components failed: %s", e)

    try:
        _link_permissions_to_components(permissions_file, components_file)
    except Exception as e:
        logger.debug("cross_ref permissions→components failed: %s", e)

    try:
        _link_webview_to_components(webview_usage_file, components_file)
    except Exception as e:
        logger.debug("cross_ref webview→components failed: %s", e)

    try:
        _link_outgoing_to_components(outgoing_intents_file, components_file)
    except Exception as e:
        logger.debug("cross_ref outgoing_intents→components failed: %s", e)

    try:
        _link_assets_to_nsc(assets_inventory_file, network_security_file)
    except Exception as e:
        logger.debug("cross_ref assets→nsc failed: %s", e)

    try:
        _link_storage_to_strings(storage_usage_file, strings_file)
    except Exception as e:
        logger.debug("cross_ref storage→strings failed: %s", e)

    try:
        _link_network_to_strings(network_usage_file, strings_file)
    except Exception as e:
        logger.debug("cross_ref network→strings failed: %s", e)


# ---------------------------------------------------------------------------
# Individual link functions
# ---------------------------------------------------------------------------

def _link_components_to_deep_links(components_file, deep_links_file) -> None:
    if not components_file or not deep_links_file:
        return
    # Build map: activity_name → [dl-ids]
    dl_by_activity: dict[str, list[str]] = {}
    for dl in deep_links_file.records:
        dl_by_activity.setdefault(dl.activity_name, []).append(dl.id)

    for comp in components_file.records:
        if comp.name in dl_by_activity:
            _add_related(comp, dl_by_activity[comp.name])


def _link_deep_links_to_components(deep_links_file, components_file) -> None:
    if not deep_links_file or not components_file:
        return
    comp_by_name = {c.name: c.id for c in components_file.records}
    for dl in deep_links_file.records:
        if dl.activity_name in comp_by_name:
            _add_related(dl, [comp_by_name[dl.activity_name]])


def _link_permissions_to_components(permissions_file, components_file) -> None:
    if not permissions_file or not components_file:
        return
    # Link permission records to components that guard with that permission
    for perm in permissions_file.requested:
        for comp in components_file.records:
            if comp.permission == perm.name:
                _add_related(perm, [comp.id])


def _link_webview_to_components(webview_usage_file, components_file) -> None:
    if not webview_usage_file or not components_file:
        return
    comp_by_name = {c.name: c.id for c in components_file.records}
    for wv in webview_usage_file.records:
        cid = comp_by_name.get(wv.caller_class)
        if cid:
            _add_related(wv, [cid])


def _link_outgoing_to_components(outgoing_intents_file, components_file) -> None:
    if not outgoing_intents_file or not components_file:
        return
    comp_by_name = {c.name: c.id for c in components_file.records}

    for oint in outgoing_intents_file.records:
        # Link to sender's own component
        sender_id = comp_by_name.get(oint.caller_class)
        if sender_id:
            _add_related(oint, [sender_id])

        # If explicit intent, link to target component
        if oint.target_component and oint.target_component in comp_by_name:
            _add_related(oint, [comp_by_name[oint.target_component]])

        # If implicit, try to match by action string
        if oint.action and oint.intent_type == "implicit":
            for comp in components_file.records:
                for f in comp.intent_filters:
                    if oint.action in f.actions:
                        _add_related(oint, [comp.id])
                        break


def _link_assets_to_nsc(assets_inventory_file, network_security_file) -> None:
    if not assets_inventory_file or not network_security_file:
        return
    nsc_by_name: dict[str, str] = {}
    for dc in network_security_file.domain_configs:
        for ta in dc.trust_anchors:
            if ta.src and ta.src.startswith("@raw/"):
                filename = ta.src.split("/")[-1]
                nsc_by_name[filename] = dc.id

    for asset in assets_inventory_file.records:
        fname = asset.path.split("/")[-1]
        nsc_id = nsc_by_name.get(fname)
        if nsc_id:
            _add_related(asset, [nsc_id])


def _link_storage_to_strings(storage_usage_file, strings_file) -> None:
    if not storage_usage_file or not strings_file:
        return
    str_by_value: dict[str, str] = {s.value: s.id for s in strings_file.records}

    for stor in storage_usage_file.records:
        if stor.storage_target and stor.storage_target.name:
            sid = str_by_value.get(stor.storage_target.name)
            if sid:
                _add_related(stor, [sid])


def _link_network_to_strings(network_usage_file, strings_file) -> None:
    if not network_usage_file or not strings_file:
        return
    str_by_value: dict[str, str] = {s.value: s.id for s in strings_file.records}

    for net in network_usage_file.records:
        req = getattr(net, "request", None)
        if req and req.literal_url:
            sid = str_by_value.get(req.literal_url)
            if sid:
                _add_related(net, [sid])
                req.related_string_id = sid


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _add_related(record, ids: list[str]) -> None:
    """Add IDs to a record's related_ids without duplicating."""
    existing = set(record.related_ids)
    for rid in ids:
        if rid and rid not in existing:
            record.related_ids.append(rid)
            existing.add(rid)