"""
app.olympus — the boundary between this engine and Olympus.

Olympus is the GUI that already performs the APK static analysis; this engine
embeds into it. Its output format is not finalised yet (files or CLI text
today, JSON expected), so EVERY assumption about Olympus lives behind this
package and nowhere else. When the real format lands, `normalize_olympus_output`
is the function that changes.

    OlympusClient          protocol every client satisfies
    MockOlympusClient      reads fixture JSON from disk — lets the whole
                           validation path be built and tested with no GUI
    OlympusTestOutput      normalised view the rest of the engine consumes
    normalize_olympus_output(raw)  the single mapping point
"""

from app.olympus.client import (
    MockOlympusClient,
    OlympusClient,
    OlympusError,
    OlympusTestOutput,
    normalize_olympus_output,
)

__all__ = [
    "OlympusClient",
    "MockOlympusClient",
    "OlympusTestOutput",
    "OlympusError",
    "normalize_olympus_output",
]
