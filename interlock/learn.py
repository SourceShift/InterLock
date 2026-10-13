"""``interlock learn``: draft a reviewable policy from observed behaviour (R24).

A receipt log records what the guard actually did. This module reads a window
of those receipts and reduces them to the *observed allow envelope* - the set
of actions that were allowed - and turns that into a declarative policy whose
lone rule escalates anything else.

The draft is never enforcement. It is a file a person reads, edits and then
installs on purpose: this module writes no ``block`` rule and marks nothing
``locked``, so the worst a careless install can do is ask a human about the
unseen - it can never refuse a call on its own. That is the whole point of a
*reviewable* baseline (kickoff constraint c:0).

Design notes:

- *Only ``ALLOW`` receipts count.* A receipt whose verdict is ``BLOCK``,
  ``ESCALATE`` or ``MODIFY`` is not part of the envelope; it is reported back
  in :attr:`Baseline.excluded` so a refused action can never be laundered into
  "observed and fine". Verdicts are matched case-insensitively.
- *One complement rule, not one rule per action.* The declarative schema has no
  ``allow`` verdict (:data:`interlock.policy.declarative.VERDICTS`) - the engine
  allows by default - so "allow what we saw" is a single rule that fires when
  the action is *not* in the observed set. A per-action rule would escalate
  every *other* observed action and get the complement exactly backwards.
- *Counted evidence lives in allowed keys.* The rule and document key sets are
  closed (an unknown rule key quarantines the rule, an unknown document key
  aborts the load), so the counts ride in the ``description``/``reason``
  strings and in the returned :class:`Baseline`, never in a new key.
- *Deterministic output.* Rule ids, reasons and evidence strings are fixed; the
  action list is deduped and sorted; the document is serialized with
  ``sort_keys=True``. Two runs over the same log are byte-identical - no
  timestamps, hostnames, absolute paths, floats or random ids go into the file.

Read-only with respect to enforcement: importing this module installs nothing,
and the CLI writes only the file it is told to write.
"""
from __future__ import annotations

import dataclasses
import os
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from .policy.declarative import SCHEMA_VERSION
from .receipt import Receipt
from .report import read_receipts

#: The rule id every generated policy uses. Fixed, so two runs agree byte for
#: byte and a project overlay can name the rule.
RULE_ID = "learn-escalate-unseen"

#: The default ``name`` for a generated draft.
DEFAULT_NAME = "learned-behavioural-baseline"

#: The generated rule's ``reason``. An approver reads this verbatim, so it says
#: what is happening and why a human is in the loop, not what the rule matches.
REASON = "outside the observed envelope: a human decides before this runs"

#: Receipt actions that are audit artifacts, not observed tool calls. They must
#: never widen the envelope: allowing ``receipts.dropped`` would let a sink
#: failure become a permitted action.
_ARTIFACTS = frozenset({"receipts.dropped"})

#: A path to a receipt log, or an already-parsed stream of receipts.
ReceiptSource = Union[str, bytes, os.PathLike, Iterable[Receipt]]


@dataclasses.dataclass
class Baseline:
    """A receipt window reduced to the allow envelope.

    ``counts`` maps an observed action to how many ``ALLOW`` receipts named it;
    ``excluded`` maps everything left out to a count - a non-``ALLOW`` verdict
    (``"BLOCK"``, ``"ESCALATE"``, ``"MODIFY"``) or the ``receipts.dropped``
    audit artifact. Nothing in ``excluded`` can reach the emitted policy.
    """

    counts: Dict[str, int] = dataclasses.field(default_factory=dict)
    excluded: Dict[str, int] = dataclasses.field(default_factory=dict)

    @property
    def actions(self) -> List[str]:
        """The observed actions, deduped and sorted - the allow envelope."""
        return sorted(self.counts)

    @property
    def total(self) -> int:
        """How many ``ALLOW`` receipts formed the envelope."""
        return sum(self.counts.values())

    @property
    def empty(self) -> bool:
        """True when no ``ALLOW`` observation was found."""
        return not self.counts


def count_receipts(receipts: Iterable[Receipt]) -> Baseline:
    """Reduce receipts to the allow envelope.

    A receipt joins the envelope only when its verdict is ``ALLOW`` (matched
    case-insensitively) and its action is a real tool name; everything else is
    counted in :attr:`Baseline.excluded` instead, so the caller can report what
    was left out and why.
    """
    counts: Dict[str, int] = {}
    excluded: Dict[str, int] = {}
    for receipt in receipts:
        action = str(getattr(receipt, "action", "") or "").strip()
        if not action:
            continue
        if action in _ARTIFACTS:
            excluded[action] = excluded.get(action, 0) + 1
            continue
        verdict = str(getattr(receipt, "verdict", "") or "").strip().upper()
        if verdict == "ALLOW":
            counts[action] = counts.get(action, 0) + 1
        else:
            excluded[verdict] = excluded.get(verdict, 0) + 1
    return Baseline(counts=counts, excluded=excluded)


def evidence(baseline: Baseline) -> str:
    """The human-readable count string carried on the generated rule."""
    return ", ".join("{}={}".format(action, baseline.counts[action])
                     for action in baseline.actions)


def build_policy(baseline: Baseline, *, name: str = DEFAULT_NAME) -> Dict[str, Any]:
    """Turn a baseline into a declarative policy document.

    Raises :class:`ValueError` on an empty baseline: there is no observed
    envelope to allow, and a rule whose ``action`` list is empty does not even
    load (the condition language requires a non-empty list), so emitting one
    would only hand the caller a broken - or, if the rule were dropped, an
    everything-allowed - file. Refusing to build is the fail-closed choice.
    """
    if baseline.empty:
        raise ValueError(
            "cannot build a policy from an empty baseline: no ALLOW receipt was observed")
    return {
        "version": SCHEMA_VERSION,
        "name": name,
        "description": "generated by interlock learn from {} allowed receipt(s); "
                       "review before installing".format(baseline.total),
        "rules": [
            {
                "id": RULE_ID,
                "verdict": "escalate",
                "reason": REASON,
                "description": "observed actions (receipt count): {}".format(
                    evidence(baseline)),
                "when": {"not": {"action": baseline.actions}},
            }
        ],
    }


def learn(source: ReceiptSource, *,
          name: str = DEFAULT_NAME) -> Tuple[Optional[Dict[str, Any]], Baseline]:
    """Read receipts and draft a policy.

    ``source`` is a path to a receipt log - read tolerantly, so a line that is
    not a receipt is skipped and a torn tail does not lose the rest - or an
    iterable of already-parsed :class:`~interlock.receipt.Receipt`.

    Returns ``(document, baseline)``. ``document`` is ``None`` when no
    ``ALLOW`` observation was found: there is nothing to allow, and the caller
    must write no policy rather than one that escalates (or allows) everything
    by accident. Reading a log that cannot be opened raises :class:`OSError`.
    """
    receipts = _read(source)
    baseline = count_receipts(receipts)
    if baseline.empty:
        return None, baseline
    return build_policy(baseline, name=name), baseline


def _read(source: ReceiptSource) -> List[Receipt]:
    if isinstance(source, (str, bytes, os.PathLike)):
        receipts, _bad_lines = read_receipts(os.fspath(source))
        return receipts
    return list(source)
