"""The false-positive and cost harness: what a rule does to traffic that is fine.

For a fail-closed guard, a rule that is wrong at one deployment and shipped to
a thousand is the worst outcome, worse than a missed attack. So nothing enters
the commons without a measured answer to two questions: how often does it fire
on **benign** traffic, and how long does it take to decide?

The harness runs a policy document over a corpus of recorded benign events
(one JSON object per line: ``{"action": ..., "args": {...}, "phase": "call"}``)
and reports the false-positive rate overall and per rule, plus evaluation
latency percentiles. :func:`recall` runs the same policy over attack samples
and reports how many it catches. :func:`gate` turns both into a pass/fail with
reasons, which the forge uses before it proposes anything and which `interlock
mesh harness` prints for a human.

A benign corpus is the node's own business: build one with
``interlock learn``-style observation (receipts with ``ALLOW`` verdicts name
the actions), or record real tool calls from a trusted session. The harness
never fetches one from the network.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from ..enforce import Verdict
from ..event import SensorEvent

__all__ = ["load_corpus", "measure", "recall", "gate", "DEFAULT_MAX_FP_RATE", "DEFAULT_MAX_P95_US"]

DEFAULT_MAX_FP_RATE = 0.001
DEFAULT_MAX_P95_US = 5000
MAX_CORPUS_BYTES = 256 * 1024 * 1024


def load_corpus(path: str, *, limit: Optional[int] = None) -> List[SensorEvent]:
    """Events from a JSONL corpus; malformed lines are skipped."""
    events: List[SensorEvent] = []
    total = 0
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            total += len(line)
            if total > MAX_CORPUS_BYTES:
                break
            event = event_from(line)
            if event is not None:
                events.append(event)
                if limit is not None and len(events) >= limit:
                    break
    return events


def event_from(record: Any) -> Optional[SensorEvent]:
    if isinstance(record, str):
        try:
            record = json.loads(record)
        except ValueError:
            return None
    if not isinstance(record, dict) or not isinstance(record.get("action"), str):
        return None
    args = record.get("args", {})
    if not isinstance(args, dict):
        return None
    phase = record.get("phase", "call")
    if phase not in ("call", "result"):
        return None
    return SensorEvent(action=record["action"], args=args, phase=phase,
                       principal=record.get("principal"), span_id=record.get("span_id"))


def _percentile(values: Sequence[int], q: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(q * (len(ordered) - 1)))))
    return ordered[index]


def measure(policy: Mapping[str, Any], corpus: Iterable[SensorEvent], *, source: str = "<candidate>",
            repeats: int = 1) -> Dict[str, Any]:
    """Run ``policy`` over benign ``corpus``; every non-ALLOW decision is a false positive."""
    from ..policy.declarative import load_policy

    engine = load_policy(policy, source=source)
    events = list(corpus)
    per_rule: Dict[str, Dict[str, int]] = {}
    latencies: List[int] = []
    false_positives = 0
    for _ in range(max(1, repeats)):
        for event in events:
            started = time.perf_counter()
            decision = engine.evaluate(event)
            latencies.append(int((time.perf_counter() - started) * 1_000_000))
            if decision.verdict is not Verdict.ALLOW:
                false_positives += 1
                rule = per_rule.setdefault(decision.policy_id or "(unnamed)", {})
                rule[decision.verdict.name] = rule.get(decision.verdict.name, 0) + 1
    evaluated = len(events) * max(1, repeats)
    return {
        "events": len(events),
        "evaluated": evaluated,
        "false_positives": false_positives,
        "fp_rate": (false_positives / evaluated) if evaluated else 0.0,
        "per_rule": {rule: {"hits": sum(v.values()), "rate": sum(v.values()) / evaluated, "verdicts": v}
                     for rule, v in sorted(per_rule.items())},
        "quarantined": list(engine.quarantined),
        "latency_us": {"p50": _percentile(latencies, 0.5), "p95": _percentile(latencies, 0.95),
                       "max": max(latencies) if latencies else 0},
    }


def recall(policy: Mapping[str, Any], samples: Iterable[SensorEvent], *, source: str = "<candidate>",
           want: Tuple[str, ...] = ("BLOCK", "ESCALATE", "MODIFY")) -> Dict[str, Any]:
    """Run ``policy`` over attack ``samples``; a sample is caught when the verdict is in ``want``."""
    from ..policy.declarative import load_policy

    engine = load_policy(policy, source=source)
    events = list(samples)
    caught = 0
    missed: List[str] = []
    for index, event in enumerate(events):
        if engine.evaluate(event).verdict.name in want:
            caught += 1
        else:
            missed.append("{}:{}".format(index, event.action))
    return {"samples": len(events), "caught": caught,
            "recall": (caught / len(events)) if events else 0.0, "missed": missed[:50]}


def gate(measured: Mapping[str, Any], *, max_fp_rate: float = DEFAULT_MAX_FP_RATE,
         max_p95_us: int = DEFAULT_MAX_P95_US, recalled: Optional[Mapping[str, Any]] = None,
         min_recall: float = 0.0) -> Tuple[bool, List[str]]:
    """Pass or fail a candidate, with every reason it failed."""
    reasons: List[str] = []
    if measured.get("quarantined"):
        reasons.append("quarantined rule(s): {}".format("; ".join(measured["quarantined"])))
    if measured.get("evaluated", 0) == 0:
        reasons.append("no benign events were evaluated; a false-positive rate needs a corpus")
    elif measured["fp_rate"] > max_fp_rate:
        reasons.append("false-positive rate {:.4%} exceeds {:.4%} ({} of {} benign events)".format(
            measured["fp_rate"], max_fp_rate, measured["false_positives"], measured["evaluated"]))
    if measured.get("latency_us", {}).get("p95", 0) > max_p95_us:
        reasons.append("p95 latency {} us exceeds {} us".format(measured["latency_us"]["p95"], max_p95_us))
    if recalled is not None and recalled.get("samples", 0) and recalled["recall"] < min_recall:
        reasons.append("recall {:.1%} below {:.1%} ({} of {} samples caught)".format(
            recalled["recall"], min_recall, recalled["caught"], recalled["samples"]))
    return (not reasons), reasons
