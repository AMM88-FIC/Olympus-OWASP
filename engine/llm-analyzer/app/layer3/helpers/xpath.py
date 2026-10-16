import xml.etree.ElementTree as ET


def build_xpath(element: ET.Element, tree: ET.ElementTree) -> str | None:
    """
    Build a stable XPath string for an element within a parsed manifest tree.
    Returns a string like /manifest/application/activity[2] or None if not found.

    Uses positional predicates so the path is unambiguous even when sibling
    elements share the same tag name.
    """
    root = tree.getroot()
    path = _find_path(root, element, [])
    if path is None:
        return None
    return "/" + "/".join(path)


def _find_path(
    current: ET.Element,
    target: ET.Element,
    ancestors: list[str],
) -> list[str] | None:
    if current is target:
        return ancestors

    tag_counts: dict[str, int] = {}
    for child in current:
        tag = child.tag
        tag_counts[tag] = tag_counts.get(tag, 0) + 1

    tag_seen: dict[str, int] = {}
    for child in current:
        tag = child.tag
        tag_seen[tag] = tag_seen.get(tag, 0) + 1

        # Use positional predicate only when siblings share the same tag
        if tag_counts[tag] > 1:
            segment = f"{tag}[{tag_seen[tag]}]"
        else:
            segment = tag

        result = _find_path(child, target, ancestors + [segment])
        if result is not None:
            return result

    return None