"""Counts without a trusted counter: additive secret sharing (the Prio shape).

A node splits each count into ``n`` shares that sum to the count modulo a
prime, and sends one share to each of ``n`` aggregators run by organisations
that will not collude. Each aggregator adds up the shares it holds; the sums,
combined, are the true totals, and no aggregator ever saw a single node's
number: each share alone is a uniformly random field element.

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
from typing import Dict, Iterable, List, Mapping, Sequence

__all__ = ["PRIME", "share", "combine", "encode_counts", "count_key", "Aggregator", "reconcile",
           "combine_totals"]

#: A Mersenne prime that keeps every intermediate sum a small Python int.
PRIME = 2 ** 61 - 1


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
    """One aggregator's side: shares keyed by report id, summed on demand."""

    def __init__(self) -> None:
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

    def totals(self, ids: Iterable[str]) -> Dict[str, int]:
        """Sum the shares of exactly the reports in ``ids`` that this side holds."""
        out: Dict[str, int] = {}
        for report_id in ids:
            shares = self._reports.get(report_id)
            if shares is None:
                continue
            for key, value in shares.items():
                out[key] = (out.get(key, 0) + value) % PRIME
        return out

    def to_dict(self) -> Dict[str, Dict[str, int]]:
        return {k: dict(v) for k, v in self._reports.items()}

    @classmethod
    def from_dict(cls, data: Mapping[str, Mapping[str, int]]) -> "Aggregator":
        agg = cls()
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


def combine_totals(*totals: Mapping[str, int]) -> Dict[str, int]:
    """Add the aggregators' partial sums into the true totals."""
    out: Dict[str, int] = {}
    for part in totals:
        for key, value in part.items():
            out[key] = (out.get(key, 0) + value) % PRIME
    return out
