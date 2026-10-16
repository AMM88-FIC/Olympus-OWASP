def compute_reachable_from(
    caller_class: str,
    exported_components: list[dict],
) -> list[str]:
    """
    Return a list of exported component IDs whose class name matches the
    caller class exactly. This is a name-match heuristic — not a full call
    graph traversal. Full reachability analysis is a v2 concern.

    Args:
        caller_class:        Fully qualified class name of the code containing
                             the API call (e.g. "jakhar.aseem.diva.MainActivity").
        exported_components: List of component dicts from the components builder,
                             each with keys: id, name, exported.effective.

    Returns:
        List of component IDs where the component name matches caller_class
        and exported.effective is True.
    """
    results = []
    for comp in exported_components:
        if (
            comp.get("name") == caller_class
            and comp.get("exported", {}).get("effective") is True
        ):
            results.append(comp["id"])
    return results


def resolve_related_ids(
    record_id: str,
    related_class: str | None,
    all_records: list[dict],
    id_field: str = "id",
    class_field: str = "name",
) -> list[str]:
    """
    Find IDs of records in all_records whose class_field matches related_class.
    Used to build cross-references between evidence items.

    Returns an empty list when related_class is None or no match is found.
    The record_id itself is always excluded from the result.
    """
    if not related_class:
        return []
    return [
        r[id_field]
        for r in all_records
        if r.get(class_field) == related_class and r.get(id_field) != record_id
    ]