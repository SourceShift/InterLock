"""Taint a delivered tool result whose text carried an injected instruction.

Provenance (see :mod:`interlock.flow`) answers *which tool* a value came from.
That is not enough when the tool returned hostile text: a page fetched by an
attacker-controlled URL and a page fetched from a trusted wiki are both
``tool:fetch_url`` to a ``flow`` or ``block_origins`` selector, so one rule
cannot separate them. The missing bit is not the source but the *condition of
the source*: this result carried an instruction-override signature.

When a boundary sees such a signature in a result, it records the delivered
text under both its usual origins and :data:`TAINT_INJECTION`. A later call
that copies that text then carries the taint label, and an egress policy can
refuse "send what a poisoned page told you" without refusing the trusted page::

    {"id": "no-tainted-egress", "detector": "data_egress.network_egress_guard",
     "with": {"allowed_hosts": ["api.acme.com"], "block_origins": ["taint:*"]}}

The scan is the same signature set the result-injection detectors use, so one
list decides what the boundary calls poisoned. It is a substring scanner, not a
classifier: it catches known override phrasings, and a paraphrase is not
labelled. That is the honest limit - the label is a suspicion attached to text,
not a proof, and it never blocks on its own.

Detection reads the result *before* a sanitizer rewrote it (the boundary passes
the inbound payload separately), because a sanitized line cannot be copied but
the rest of a poisoned document still can. The label is attached to the
delivered text, which is what the model actually reads.
"""
from __future__ import annotations

import itertools
from typing import Any, Iterable, List

from .detectors.tool_result_injection_sanitizer import BUILTIN_PATTERNS
from .flow import MAX_SCAN_CHARS, _strings

#: Label a result's text carries when the result contained an instruction
#: override. Selectors match it like any other origin label (``taint:*``).
TAINT_INJECTION = "taint:injection"

#: How many signature comparisons one result may cost, so a large document
#: cannot turn the boundary into a quadratic scan.
MAX_SIGNATURES_CHECKED = 4096


def contains_instruction_override(value: Any) -> bool:
    """Whether any string under *value* carries a known override signature.

    Walks the same bounded shape ``flow`` walks - top-level strings, nested
    strings via dotted paths, keys never - and stops at the first hit. Each
    string is lowercased once and tested against the shared signature list;
    the total work is bounded by ``MAX_SIGNATURES_CHECKED`` comparisons and
    ``MAX_SCAN_CHARS`` characters. A non-string, empty, or None *value* is not
    a hit.
    """
    checked = 0
    budget = MAX_SCAN_CHARS
    for _path, text in _strings(value, ""):
        if budget <= 0 or checked >= MAX_SIGNATURES_CHECKED:
            return False
        used = min(len(text), budget)
        budget -= used
        lowered = text[:used].lower()
        for pattern in itertools.islice(BUILTIN_PATTERNS,
                                        MAX_SIGNATURES_CHECKED - checked):
            checked += 1
            if pattern in lowered:
                return True
    return False


def tainted_labels(
    labels: Iterable[str],
    delivered: Any,
    inbound: Any = None,
) -> List[str]:
    """*labels*, plus :data:`TAINT_INJECTION` when the result was poisoned.

    *inbound* is the payload as the tool returned it; when it is omitted the
    delivered payload is scanned. *delivered* is recorded by the caller, so the
    label rides on text the model can actually copy. Duplicate labels collapse
    and order is preserved.
    """
    out = [label for label in labels if isinstance(label, str) and label]
    probe = delivered if inbound is None else inbound
    if contains_instruction_override(probe) and TAINT_INJECTION not in out:
        out.append(TAINT_INJECTION)
    return out


__all__ = ["TAINT_INJECTION", "contains_instruction_override", "tainted_labels"]
