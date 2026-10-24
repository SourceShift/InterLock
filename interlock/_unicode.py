"""Unicode normalization shared by detectors that match Python identifiers.

Python normalizes identifiers to NFKC before compiling source: ``ｅｖａｌ``
(the fullwidth spelling) is the same name as ``eval`` to the interpreter. A
guard that matches raw argument text therefore has to match what Python reads,
or a payload can spell a blocked identifier in a compatibility form and walk
past a pattern that only knows the ASCII spelling.
"""
from __future__ import annotations

import unicodedata


def nfkc(value: str) -> str:
    """Return ``value`` in NFKC form, or ``value`` itself when it already is.

    The helper is for ``str`` arguments; ``unicodedata.normalize`` does not
    raise on any string, so a detector scanning argument text can call it
    without a guard. Returning the original object when nothing changes keeps
    callers from doing a second scan for no reason.
    """
    normalized = unicodedata.normalize("NFKC", value)
    return normalized if normalized != value else value
