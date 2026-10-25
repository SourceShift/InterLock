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
from dataclasses import replace
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from ..enforce import Verdict
from ..event import SensorEvent

__all__ = ["load_corpus", "load_poisons", "measure", "measure_each_rule",
           "measure_each_detector", "recall",
           "induced_blocking", "gate_induced", "stress_events", "stress", "gate_stress",
           "gate", "DEFAULT_MAX_FP_RATE", "DEFAULT_MAX_P95_US", "DEFAULT_MAX_INDUCED_RATE",
           "DEFAULT_MAX_STRESS_P95_US", "DEFAULT_INJECTION_ARGS"]

DEFAULT_MAX_FP_RATE = 0.001
DEFAULT_MAX_P95_US = 5000
#: A bait string in a non-execution field must never change a verdict.
DEFAULT_MAX_INDUCED_RATE = 0.0
#: Pathological inputs may be slower than ordinary ones; not 100x slower.
DEFAULT_MAX_STRESS_P95_US = 50_000
MAX_CORPUS_BYTES = 256 * 1024 * 1024

#: Argument names that carry content, not executable intent. The policy's job
#: is to decide on what a call *does*; text in these fields is data, so a
#: refusal caused by it is induced blocking, not a true positive.
DEFAULT_INJECTION_ARGS = ("description", "content", "new_string", "prompt", "query",
                          "new_source")


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


def load_poisons(path: str) -> List[Dict[str, str]]:
    """Bait strings from JSONL: ``{"id": ..., "text": ...}``; malformed rows skipped.

    A poison is *benign content that looks like an attack*: documentation that
    quotes ``rm -rf /``, a prose example of a prompt injection, a fake token,
    an ANSI escape. It must be safe in a field that does not execute.
    """
    poisons: List[Dict[str, str]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if not isinstance(record, dict) or not isinstance(record.get("text"), str):
                continue
            poison_id = record.get("id")
            poisons.append({"id": poison_id if isinstance(poison_id, str) else "#{}".format(len(poisons)),
                            "text": record["text"]})
    return poisons


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
                       "p99": _percentile(latencies, 0.99),
                       "max": max(latencies) if latencies else 0},
    }


def measure_each_rule(policy: Mapping[str, Any], corpus: Iterable[SensorEvent], *,
                      source: str = "<candidate>", repeats: int = 1) -> List[Dict[str, Any]]:
    """Measure every rule in ``policy`` on its own, so a dormant rule gets a number.

    :func:`measure` reports a false positive against whichever rule won the
    event; a rule that never fires has no entry at all. This builds a
    one-rule document per rule - keeping the parent's ``tools`` schemas, but
    dropping a document-level ``extends`` (an inherited rule is not in this
    list) - and runs the same corpus through it. The result is the per-rule
    false-positive and latency table a policy review can publish: ``rate`` is
    that rule's false positives over the events it was offered.

    A rule that fails to compile alone is reported with an ``error`` instead of
    aborting the sweep; the full policy's quarantine list is still the
    authority on whether that rule is live.
    """
    doc = dict(policy)
    rules = doc.get("rules")
    if not isinstance(rules, list):
        raise ValueError("a policy document needs a 'rules' list")
    events = list(corpus)
    results: List[Dict[str, Any]] = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, Mapping):
            results.append({"rule": "#{}".format(index), "error": "rule is not an object"})
            continue
        label = rule.get("id") or "#{}".format(index)
        try:
            summary = _measure_rules(doc, [rule], events, "{}#{}".format(source, label), repeats)
        except Exception as exc:  # a broken rule must not hide the others
            results.append({"rule": label, "error": "{}: {}".format(type(exc).__name__, exc)})
            continue
        results.append(dict({"rule": label}, **summary))
    return results


def measure_each_detector(policy: Mapping[str, Any], corpus: Iterable[SensorEvent], *,
                          source: str = "<candidate>", repeats: int = 1) -> List[Dict[str, Any]]:
    """Measure every detector in ``policy`` with all of its rules together.

    A policy can mount one detector under several rules (different actions or
    ``with`` arguments). Measuring rules one at a time prices the parse each
    time and can split one detector's false positives across rows; this groups
    by the detector name and runs only that detector's rules, so the number is
    the detector's. Declarative rules are excluded by construction - they have
    no ``detector`` key and belong to :func:`measure_each_rule`.

    A detector that fails to compile alone is reported with an ``error``; the
    full policy's quarantine list remains the authority on whether it is live.
    """
    doc = dict(policy)
    rules = doc.get("rules")
    if not isinstance(rules, list):
        raise ValueError("a policy document needs a 'rules' list")
    grouped: Dict[str, List[Tuple[int, Mapping[str, Any]]]] = {}
    for index, rule in enumerate(rules):
        if isinstance(rule, Mapping) and isinstance(rule.get("detector"), str):
            grouped.setdefault(rule["detector"], []).append((index, rule))
    events = list(corpus)
    results: List[Dict[str, Any]] = []
    for name, group in sorted(grouped.items()):
        labels = [rule.get("id") or "#{}".format(index) for index, rule in group]
        try:
            summary = _measure_rules(doc, [rule for _, rule in group], events,
                                     "{}@{}".format(source, name), repeats)
        except Exception as exc:  # a broken detector must not hide the others
            results.append({"detector": name, "rules": labels,
                            "error": "{}: {}".format(type(exc).__name__, exc)})
            continue
        results.append(dict({"detector": name, "rules": labels}, **summary))
    return results


def _measure_rules(doc: Mapping[str, Any], rules: Sequence[Mapping[str, Any]],
                   events: Sequence[SensorEvent], source: str, repeats: int) -> Dict[str, Any]:
    """Load one policy from ``doc`` with only ``rules`` and measure it."""
    from ..policy.declarative import load_policy

    single = {k: v for k, v in doc.items() if k not in ("extends", "rules")}
    single["rules"] = list(rules)
    engine = load_policy(single, source=source)
    false_positives = 0
    verdicts: Dict[str, int] = {}
    latencies: List[int] = []
    for _ in range(max(1, repeats)):
        for event in events:
            started = time.perf_counter()
            decision = engine.evaluate(event)
            latencies.append(int((time.perf_counter() - started) * 1_000_000))
            if decision.verdict is not Verdict.ALLOW:
                false_positives += 1
                verdicts[decision.verdict.name] = verdicts.get(decision.verdict.name, 0) + 1
    evaluated = len(events) * max(1, repeats)
    return {
        "events": len(events),
        "evaluated": evaluated,
        "false_positives": false_positives,
        "fp_rate": (false_positives / evaluated) if evaluated else 0.0,
        "verdicts": verdicts,
        "quarantined": list(engine.quarantined),
        "latency_us": {"p50": _percentile(latencies, 0.5),
                       "p95": _percentile(latencies, 0.95),
                       "p99": _percentile(latencies, 0.99),
                       "max": max(latencies) if latencies else 0},
    }


def induced_blocking(policy: Mapping[str, Any], corpus: Iterable[SensorEvent],
                     poisons: Iterable[Mapping[str, str]], *, source: str = "<candidate>",
                     targets: Sequence[str] = DEFAULT_INJECTION_ARGS,
                     max_examples: int = 10) -> Dict[str, Any]:
    """Bait text in non-execution fields must not turn an ALLOW into a refusal.

    For every benign event that the policy allows, each string argument named
    in ``targets`` is appended with each poison text and the variant is judged
    again. A changed verdict is an *induced* block: the attacker did not
    change what the call does, only what it says about itself, and the guard
    refused a call it would otherwise allow. Result-phase events are excluded -
    a result-scoped detector is *supposed* to read result content.

    The return value is ``variants`` (how many poisoned calls were judged),
    ``induced`` and ``induced_rate``, ``by_rule`` (which rule refused), and up
    to ``max_examples`` of the flips.
    """
    from ..policy.declarative import load_policy

    engine = load_policy(policy, source=source)
    events = list(corpus)
    decisions = [engine.evaluate(event) for event in events]
    wanted = set(targets)
    variants = 0
    induced = 0
    by_rule: Dict[str, int] = {}
    examples: List[Dict[str, Any]] = []
    for poison in poisons:
        text = str(poison.get("text", ""))
        if not text:
            continue
        poison_id = str(poison.get("id", "?"))
        for event, decision in zip(events, decisions):
            if event.phase != "call" or decision.verdict is not Verdict.ALLOW:
                continue
            for arg, value in event.args.items():
                if arg not in wanted or not isinstance(value, str):
                    continue
                variant = replace(event, args={**event.args, arg: value + "\n" + text})
                variants += 1
                verdict = engine.evaluate(variant)
                if verdict.verdict is Verdict.ALLOW:
                    continue
                induced += 1
                rule = verdict.policy_id or "(unnamed)"
                by_rule[rule] = by_rule.get(rule, 0) + 1
                if len(examples) < max_examples:
                    examples.append({"poison": poison_id, "action": event.action, "arg": arg,
                                     "verdict": verdict.verdict.name, "rule": rule})
    return {"events": len(events), "variants": variants, "induced": induced,
            "induced_rate": (induced / variants) if variants else 0.0,
            "by_rule": dict(sorted(by_rule.items())), "examples": examples}


def gate_induced(report: Mapping[str, Any], *,
                 max_rate: float = DEFAULT_MAX_INDUCED_RATE) -> List[str]:
    """Pass/fail for :func:`induced_blocking`; every reason it failed."""
    if report.get("variants", 0) == 0:
        return ["no injectable event was evaluated; induced blocking needs a corpus and poisons"]
    if report["induced_rate"] > max_rate:
        return ["induced-block rate {:.4%} exceeds {:.4%} ({} of {} poisoned calls refused: {})".format(
            report["induced_rate"], max_rate, report["induced"], report["variants"],
            ", ".join("{} x{}".format(rule, hits) for rule, hits in report.get("by_rule", {}).items()))]
    return []


def stress_events() -> List[SensorEvent]:
    """Pathological calls a hostile model or tool result can produce.

    Every case is a *call* whose shape is legal, not an attack the policy
    should catch: one enormous argument, deeply nested substitutions, a long
    pipe chain, thousands of words. They measure whether the guard itself is
    the denial of service.
    """
    return [
        SensorEvent("Bash", {"command": "echo '" + "x" * 100_000 + "'"}),
        SensorEvent("Bash", {"command": "$(" * 300 + "true" + ")" * 300}),
        SensorEvent("Bash", {"command": " | ".join(["true"] * 1000)}),
        SensorEvent("Bash", {"command": "echo " + " ".join("arg{}".format(i) for i in range(2000))}),
        SensorEvent("Write", {"file_path": "/tmp/out.txt", "content": "lorem ipsum " * 20_000}),
        SensorEvent("WebSearch", {"query": "term " * 20_000}),
    ]


def stress(policy: Mapping[str, Any], cases: Optional[Iterable[SensorEvent]] = None, *,
           source: str = "<candidate>", repeats: int = 1) -> List[Dict[str, Any]]:
    """Time each pathological case; a crash is a failure, not a slow result."""
    from ..policy.declarative import load_policy

    engine = load_policy(policy, source=source)
    events = list(cases if cases is not None else stress_events())
    rows: List[Dict[str, Any]] = []
    for index, event in enumerate(events):
        latencies: List[int] = []
        verdict = None
        for _ in range(max(1, repeats)):
            started = time.perf_counter()
            decision = engine.evaluate(event)
            latencies.append(int((time.perf_counter() - started) * 1_000_000))
            verdict = decision.verdict.name
        rows.append({
            "case": index,
            "action": event.action,
            "bytes": len(str(event.args)),
            "verdict": verdict,
            "latency_us": {"p50": _percentile(latencies, 0.5),
                           "p95": _percentile(latencies, 0.95),
                           "max": max(latencies) if latencies else 0},
        })
    return rows


def gate_stress(rows: Iterable[Mapping[str, Any]], *,
                max_p95_us: int = DEFAULT_MAX_STRESS_P95_US) -> List[str]:
    """Pass/fail for :func:`stress`; every case above the bound is named."""
    reasons: List[str] = []
    seen = 0
    for row in rows:
        seen += 1
        p95 = row.get("latency_us", {}).get("p95", 0)
        if p95 > max_p95_us:
            reasons.append("case {} ({} , {} bytes) p95 {} us exceeds {} us".format(
                row.get("case"), row.get("action"), row.get("bytes", 0), p95, max_p95_us))
    if not seen:
        reasons.append("no stress case ran")
    return reasons


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
