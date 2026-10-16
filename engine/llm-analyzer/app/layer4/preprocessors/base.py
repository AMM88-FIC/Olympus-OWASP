"""
preprocessors/base.py — Strategy pattern interface for evidence-file
preprocessing.

Each preprocessor transforms one parsed evidence file before it is delivered
to the model. The verdict engine parses raw evidence text into a Python
object once, applies a chain of preprocessors, then serializes the result
exactly once at the end.

Preprocessors fall into two kinds:

  - Object preprocessors (process_object): receive a parsed dict/list,
    return a transformed dict/list. Most strategies are this kind:
    slim_strings, drop noisy fields, cap snippet lengths, etc.

  - Terminal preprocessors (process_object + override is_terminal):
    receive a parsed object, produce a string. They MUST be the last step
    in a chain because the next preprocessor would have nothing to parse.
    The to_yaml strategy is terminal — once you've turned a dict into a
    minified YAML string, downstream object-shaped preprocessors can't run.

The chain is enforced left-to-right; ConfigError is raised at chain-build
time if a terminal preprocessor isn't last.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class EvidencePreprocessor(ABC):
    """One step in the evidence preprocessing chain."""

    # Class-level identifier used in config files (e.g. 'slim_strings').
    # Subclasses must override.
    name: str = ""

    # Override to True for preprocessors whose output is a string, not a
    # parsed object. Terminal preprocessors must be the last entry in any
    # chain that includes them.
    is_terminal: bool = False

    @abstractmethod
    def applies_to(self, evidence_name: str) -> bool:
        """Return True if this preprocessor should run for the given evidence
        filename (e.g. 'strings.json'). Allows scoping to specific files."""

    @abstractmethod
    def process_object(self, evidence_name: str, parsed: object) -> object:
        """Transform a parsed object. For non-terminal preprocessors, returns
        a parsed object (dict/list/etc.). For terminal preprocessors, returns
        a string."""


class ChainBuildError(ValueError):
    """Raised when a preprocessor chain is misconfigured."""


def parse_inline_params(spec: str) -> tuple[str, dict[str, str]]:
    """Parse a chain entry like 'slim_records(drop=foo,bar;compact_source=true)'
    into ('slim_records', {'drop': 'foo,bar', 'compact_source': 'true'}).

    A bare name like 'minify_json' returns ('minify_json', {}).

    The parameter syntax uses semicolons between key=value pairs because
    commas already separate preprocessor entries in a chain string."""
    spec = spec.strip()
    if "(" not in spec:
        return spec, {}
    if not spec.endswith(")"):
        raise ChainBuildError(
            f"Malformed preprocessor spec {spec!r}: "
            f"missing closing parenthesis."
        )
    name, _, params_str = spec[:-1].partition("(")
    name = name.strip()
    params_str = params_str.strip()
    if not params_str:
        return name, {}
    params: dict[str, str] = {}
    for pair in params_str.split(";"):
        pair = pair.strip()
        if not pair:
            continue
        if "=" not in pair:
            raise ChainBuildError(
                f"Malformed parameter {pair!r} in {spec!r}: "
                f"expected 'key=value'."
            )
        key, _, value = pair.partition("=")
        params[key.strip()] = value.strip()
    return name, params


def build_chain(
    preprocessor_specs: list[str],
    registry: dict,
) -> list[EvidencePreprocessor]:
    """Resolve a list of preprocessor specs against the registry. Each spec
    is either a bare name ('minify_json') or a name with inline parameters
    ('slim_records(drop=snippet_context;compact_source=true)').

    Verifies that any terminal preprocessor appears only as the final entry.
    Preprocessor classes that accept parameters must define a `from_params`
    classmethod; classes without one are constructed with no arguments."""
    chain: list[EvidencePreprocessor] = []
    for i, spec in enumerate(preprocessor_specs):
        name, params = parse_inline_params(spec)
        cls = registry.get(name)
        if cls is None:
            raise ChainBuildError(
                f"Unknown preprocessor: {name!r}. "
                f"Known: {sorted(registry.keys())}"
            )
        if params:
            from_params = getattr(cls, "from_params", None)
            if from_params is None:
                raise ChainBuildError(
                    f"Preprocessor {name!r} does not accept parameters "
                    f"(got {list(params.keys())})."
                )
            try:
                instance = from_params(params)
            except (ValueError, TypeError) as e:
                raise ChainBuildError(
                    f"Invalid parameters for {name!r}: {e}"
                ) from e
        else:
            instance = cls()
        if instance.is_terminal and i != len(preprocessor_specs) - 1:
            raise ChainBuildError(
                f"Terminal preprocessor {name!r} must be last in the chain "
                f"(found at position {i + 1} of {len(preprocessor_specs)})."
            )
        chain.append(instance)
    return chain


def apply_chain(
    chain: list[EvidencePreprocessor],
    evidence_name: str,
    raw_text: str,
) -> str:
    """Apply a chain to raw evidence text. Returns the final serialized form.

    If the chain is empty, raw_text is returned unchanged (no parse-and-
    reserialize round-trip — preserves the original formatting exactly).

    If no terminal preprocessor is present, the chain ends with a parsed
    object that we serialize back to JSON withujson.dumps (no indentation,
    minimal whitespace) — matching the engine's existing inline delivery
    semantics.
    """
    import ujson

    if not chain:
        return raw_text

    # Filter to preprocessors that apply to this file
    active = [p for p in chain if p.applies_to(evidence_name)]
    if not active:
        return raw_text

    # Parse once at the start
    try:
        current: object =ujson.loads(raw_text)
    except ujson.JSONDecodeError:
        # If the file isn't JSON, we can't preprocess it — pass through
        # unchanged rather than failing.
        return raw_text

    # Apply each step
    for preprocessor in active:
        current = preprocessor.process_object(evidence_name, current)
        if preprocessor.is_terminal:
            # Terminal output is already a string; return as-is
            if not isinstance(current, str):
                raise ChainBuildError(
                    f"Terminal preprocessor {preprocessor.name!r} returned "
                    f"non-string ({type(current).__name__}); this is a bug."
                )
            return current

    # No terminal step ran — re-serialize the object to compact JSON
    return ujson.dumps(current, separators=(",", ":"), ensure_ascii=False)