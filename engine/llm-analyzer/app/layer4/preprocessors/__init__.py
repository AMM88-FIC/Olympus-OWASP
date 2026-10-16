"""
preprocessors/__init__.py — Registry of available evidence preprocessors.

To add a new preprocessor:
    1. Create a new module under app/layer4/preprocessors/
    2. Subclass EvidencePreprocessor with a unique class-level `name`
    3. Add it to REGISTRY below
"""

from app.layer4.preprocessors.base import (
    EvidencePreprocessor,
    ChainBuildError,
    build_chain,
    apply_chain,
)
from app.layer4.preprocessors.slim_strings import SlimStringsPreprocessor
from app.layer4.preprocessors.minify_json import MinifyJsonPreprocessor
from app.layer4.preprocessors.slim_records import SlimRecordsPreprocessor


# Registry of preprocessor name → class. Names are referenced in config.ini.
REGISTRY: dict[str, type[EvidencePreprocessor]] = {
    SlimStringsPreprocessor.name: SlimStringsPreprocessor,
    MinifyJsonPreprocessor.name: MinifyJsonPreprocessor,
    SlimRecordsPreprocessor.name : SlimRecordsPreprocessor,
}


__all__ = [
    "EvidencePreprocessor",
    "ChainBuildError",
    "REGISTRY",
    "build_chain",
    "apply_chain",
]