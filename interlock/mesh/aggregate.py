"""Counts without a trusted counter: additive secret sharing (the Prio shape).

A node splits each count into ``n`` shares that sum to the count modulo a
prime, and sends one share to each of ``n`` aggregators run by organisations
that will not collude. Each aggregator adds up the shares it holds; the sums,
combined, are the true totals, and no aggregator ever saw a single node's
number: each share alone is a uniformly random field element. Counts reach a
collector in no other form: the report envelope the consensus service receives
does not carry them (:mod:`.report`).

**The batch floor.** Secret sharing hides one report's counts only inside a
sum over several. Totals over a single report are that report; totals over two
let either reporter subtract its own counts and read the other's. So
:meth:`Aggregator.totals` and :func:`combine_totals` refuse to release a sum
over fewer than ``min_batch`` distinct reconciled reports (default
:data:`MIN_BATCH`, never below :data:`MIN_BATCH_FLOOR`). A repeated or unknown
report id does not count toward the batch. The floor stops a total from being
one or two reports; it does not stop someone who may query ``/v1/totals``
from differencing two overlapping batches (``{r1..r4}`` minus ``{r1..r3}`` is
``r4``). DAP's fixed, non-overlapping batches close that, and are the stated
upgrade (decision R2 step 3 in ``research/mesh-decisions.md``).

This is the arrangement Apple and Google's Exposure Notification Private
Analytics ran at national scale and the IETF's Privacy Preserving Measurement
work standardises. What this module does **not** do is prove that a share
encodes a small, well-formed count: a malicious node could inject a huge or
negative value. Prio's SNIPs, and the DAP protocol's Prio3, add that proof.
Here the defence is the reconciliation step (:func:`reconcile`): aggregators
only sum reports both of them received, and the consensus engine's reputation
and rate limits bound how much any one reporter can skew a total. Range proofs
are the stated upgrade path and the API leaves room for them.
"""
from __future__ import annotations

import hashlib
import secrets
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

__all__ = ["PRIME", "MIN_BATCH", "MIN_BATCH_FLOOR", "share", "combine", "encode_counts", "count_key",
           "Aggregator", "reconcile", "combine_totals", "fire_totals"]

#: A Mersenne prime that keeps every intermediate sum a small Python int.
PRIME = 2 ** 61 - 1

#: The default batch floor: no total is released over fewer reconciled reports.
MIN_BATCH = 3

#: The floor can be raised, never set below this: a batch of one is the report.
MIN_BATCH_FLOOR = 2


def _check_min_batch(min_batch: Any) -> int:
    if not isinstance(min_batch, int) or isinstance(min_batch, bool) or min_batch < MIN_BATCH_FLOOR:
        raise ValueError("min_batch must be an integer of at least {}".format(MIN_BATCH_FLOOR))
    return min_batch


def share(value: int, n: int = 2) -> List[int]:
    """Split ``value`` into ``n`` shares that sum to it modulo :data:`PRIME`."""
    if n < 2:
        raise ValueError("at least two aggregators are needed for privacy")
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value >= PRIME:
        raise ValueError("a count must be an integer in [0, PRIME)")
    shares = [secrets.randbelow(PRIME) for _ in range(n - 1)]
    shares.append((value - sum(shares)) % PRIME)
    return shares


def combine(shares: Iterable[int]) -> int:
    return sum(shares) % PRIME


def count_key(policy_id: str, verdict: str, tool_class: str, phase: str, bucket: int) -> str:
    """One count's identity across nodes: ``rule|verdict|class|phase|bucket``."""
    return "|".join([policy_id, verdict, tool_class, phase, str(int(bucket))])


def encode_counts(counts: Mapping[str, int], n: int = 2) -> List[Dict[str, int]]:
    """Share a whole vector of counts: one dict of shares per aggregator."""
    out: List[Dict[str, int]] = [{} for _ in range(n)]
    for key, value in counts.items():
        for index, piece in enumerate(share(int(value), n)):
            out[index][key] = piece
    return out


class Aggregator:
    """One aggregator's side: shares keyed by report id, summed on demand over
    batches of at least ``min_batch`` reports."""

    def __init__(self, min_batch: int = MIN_BATCH) -> None:
        self.min_batch = _check_min_batch(min_batch)
        self._reports: Dict[str, Dict[str, int]] = {}

    def add(self, report_id: str, shares: Mapping[str, int]) -> None:
        if not isinstance(report_id, str) or not report_id:
            raise ValueError("a report id is required")
        if report_id in self._reports:
            raise ValueError("report {} was already recorded".format(report_id))
        clean: Dict[str, int] = {}
        for key, value in shares.items():
            if not isinstance(key, str) or not isinstance(value, int) or isinstance(value, bool) \
                    or value < 0 or value >= PRIME:
                raise ValueError("malformed share for {!r}".format(key))
            clean[key] = value
        self._reports[report_id] = clean

    def report_ids(self) -> List[str]:
        return sorted(self._reports)

    def manifest(self) -> str:
        """A digest of the report ids held, for cross-checking with the peer."""
        return hashlib.sha256("\n".join(self.report_ids()).encode("utf-8")).hexdigest()

    def totals(self, ids: Iterable[str], min_batch: Optional[int] = None) -> Dict[str, int]:
        """Sum the shares of exactly the reports in ``ids`` that this side holds.

        Raises ``ValueError`` when fewer than ``min_batch`` (default: this
        aggregator's floor) distinct held reports are in ``ids``; a repeated or
        unknown id does not count toward the batch."""
        floor = self.min_batch if min_batch is None else _check_min_batch(min_batch)
        held = sorted({report_id for report_id in ids if report_id in self._reports})
        if len(held) < floor:
            raise ValueError("totals need at least {} reconciled reports, this batch has {}".format(floor, len(held)))
        out: Dict[str, int] = {}
        for report_id in held:
            for key, value in self._reports[report_id].items():
                out[key] = (out.get(key, 0) + value) % PRIME
        return out

    def to_dict(self) -> Dict[str, Dict[str, int]]:
        return {k: dict(v) for k, v in self._reports.items()}

    @classmethod
    def from_dict(cls, data: Mapping[str, Mapping[str, int]], min_batch: int = MIN_BATCH) -> "Aggregator":
        agg = cls(min_batch)
        for report_id, shares in data.items():
            agg.add(report_id, shares)
        return agg


def reconcile(*id_lists: Sequence[str]) -> List[str]:
    """The report ids every aggregator holds. A report that reached only one
    aggregator is excluded, so a node cannot skew a total by sending one share."""
    if not id_lists:
        return []
    common = set(id_lists[0])
    for ids in id_lists[1:]:
        common &= set(ids)
    return sorted(common)


def combine_totals(*totals: Mapping[str, int], ids: Optional[Sequence[str]] = None,
                   min_batch: int = MIN_BATCH) -> Dict[str, int]:
    """Add the aggregators' partial sums into the true totals.

    Each partial sum was floor-checked by the aggregator that produced it.
    Pass the reconciled ``ids`` the sums cover to check the floor here too:
    fewer than ``min_batch`` distinct ids raises ``ValueError``."""
    floor = _check_min_batch(min_batch)
    if ids is not None and len(set(ids)) < floor:
        raise ValueError("totals need at least {} reconciled reports, this batch has {}".format(floor, len(set(ids))))
    out: Dict[str, int] = {}
    for part in totals:
        for key, value in part.items():
            out[key] = (out.get(key, 0) + value) % PRIME
    return out


def fire_totals(manifests: Sequence[Mapping[str, Any]], replies: Sequence[Mapping[str, Any]], *,
                min_batch: int = MIN_BATCH) -> Dict[str, Any]:
    """Per-rule fire totals from the aggregators' ``GET /v1/manifest`` and
    ``POST /v1/totals`` replies (the totals requested for the reconciled ids).

    Returns ``{"reports": n, "min_batch": floor, "rules": {policy_id:
    {verdict: n}}}``. The floor is the highest of ``min_batch`` and every
    aggregator's own, and is enforced over the reconciled ids. A key that is
    not a :func:`count_key` is skipped."""
    if len(manifests) < 2 or len(replies) != len(manifests):
        raise ValueError("fire totals need a manifest and a totals reply from each of at least two aggregators")
    floor = _check_min_batch(min_batch)
    for manifest in manifests:
        theirs = manifest.get("min_batch", MIN_BATCH)
        floor = max(floor, _check_min_batch(theirs))
    ids = reconcile(*[[i for i in (m.get("ids") or []) if isinstance(i, str)] for m in manifests])
    parts = []
    for reply in replies:
        part = reply.get("totals")
        if not isinstance(part, dict):
            raise ValueError("a totals reply carries no totals")
        parts.append(part)
    combined = combine_totals(*parts, ids=ids, min_batch=floor)
    rules: Dict[str, Dict[str, int]] = {}
    for key, value in sorted(combined.items()):
        fields = key.rsplit("|", 4)
        if len(fields) != 5 or not fields[0]:
            continue
        verdicts = rules.setdefault(fields[0], {})
        verdicts[fields[1]] = (verdicts.get(fields[1], 0) + value) % PRIME
    return {"reports": len(ids), "min_batch": floor, "rules": rules}
