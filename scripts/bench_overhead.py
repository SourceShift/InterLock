#!/usr/bin/env python3
"""Measure what the guard costs per event, against an engine with no rules.

    python3 scripts/bench_overhead.py                    # human-readable
    python3 scripts/bench_overhead.py --json             # for tooling
    python3 scripts/bench_overhead.py --repeats 50       # steadier tail

The number that matters is not "how fast is evaluate()" but "how much did
installing a policy add to a call that would have happened anyway". So the
same corpus is run twice, back to back, through:

* the floor - a :class:`PolicyEngine` with no rules, which measures the event
  loop and nothing else, and
* the default ``coding-agent`` pack - the policy a hook installs.

Both runs are preceded by an untimed warm-up pass. Every event is timed
individually and sorted per action; overhead is the difference between the
two medians for that action (a difference of percentiles, not a paired
difference - the two engines are measured in separate passes).

A gate failure is a regression signal, not a hardware benchmark: absolute
bounds catch a policy that became expensive, and the ratio catches a floor
that collapsed because the harness stopped measuring what it thought it did.
The methodology and a recorded run are in ``benchmarks/overhead/README.md``.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from interlock.event import SensorEvent  # noqa: E402
from interlock.mesh.harness import (  # noqa: E402
    DEFAULT_MAX_P95_US,
    _percentile,
    load_corpus,
)
from interlock.policy.declarative import load_policy  # noqa: E402
from interlock.policy.engine import PolicyEngine  # noqa: E402
from interlock.policy.packs import builtin_pack  # noqa: E402

DEFAULT_MAX_OVERHEAD_US = 5000
#: The guard was ~30x the empty engine in the recorded run. A 500x ceiling is
#: a smoke alarm for a broken floor, not a budget anyone should tune against.
#: A floor below ``MIN_RATIO_FLOOR_US`` is timer resolution, not work, so no
#: ratio is computed from it.
DEFAULT_MAX_RATIO = 500.0
MIN_RATIO_FLOOR_US = 5


def _run(engine: Any, events: Sequence[SensorEvent], repeats: int) -> Dict[str, List[int]]:
    """Untimed warm-up, then ``repeats`` timed passes; microseconds per action."""
    for event in events:
        engine.evaluate(event)
    per_action: Dict[str, List[int]] = defaultdict(list)
    for _ in range(max(1, repeats)):
        for event in events:
            started = time.perf_counter()
            engine.evaluate(event)
            per_action[event.action].append(int((time.perf_counter() - started) * 1_000_000))
    return per_action


def _summary(values: Iterable[int]) -> Dict[str, int]:
    samples = list(values)
    return {
        "count": len(samples),
        "p50": _percentile(samples, 0.5),
        "p95": _percentile(samples, 0.95),
        "p99": _percentile(samples, 0.99),
        "max": max(samples) if samples else 0,
    }


def measure(policy: Mapping[str, Any], corpus: Iterable[SensorEvent], *,
            source: str = "<candidate>", repeats: int = 20) -> Dict[str, Any]:
    """The guarded engine against the empty floor, per action and overall."""
    events = list(corpus)
    floor = _run(PolicyEngine(), events, repeats)
    guarded = _run(load_policy(policy, source=source), events, repeats)

    actions: Dict[str, Dict[str, Any]] = {}
    for action in sorted(set(floor) | set(guarded)):
        floor_summary = _summary(floor.get(action, ()))
        guarded_summary = _summary(guarded.get(action, ()))
        overhead = guarded_summary["p50"] - floor_summary["p50"]
        ratio = (guarded_summary["p50"] / floor_summary["p50"]
                 if floor_summary["p50"] >= MIN_RATIO_FLOOR_US else None)
        actions[action] = {
            "floor": floor_summary,
            "guarded": guarded_summary,
            "overhead_us": {"p50": overhead,
                            "p95": guarded_summary["p95"] - floor_summary["p95"]},
            "ratio_p50": ratio,
        }

    floor_all = [value for values in floor.values() for value in values]
    guarded_all = [value for values in guarded.values() for value in values]
    floor_summary = _summary(floor_all)
    guarded_summary = _summary(guarded_all)
    return {
        "events": len(events),
        "repeats": max(1, repeats),
        "evaluated": len(floor_all),
        "source": source,
        "floor": floor_summary,
        "guarded": guarded_summary,
        "overhead_us": {"p50": guarded_summary["p50"] - floor_summary["p50"],
                        "p95": guarded_summary["p95"] - floor_summary["p95"],
                        "p99": guarded_summary["p99"] - floor_summary["p99"]},
        "ratio_p50": (guarded_summary["p50"] / floor_summary["p50"]
                      if floor_summary["p50"] >= MIN_RATIO_FLOOR_US else None),
        "by_action": actions,
    }


def gate(measured: Mapping[str, Any], *, max_p95_us: int = DEFAULT_MAX_P95_US,
         max_overhead_us: int = DEFAULT_MAX_OVERHEAD_US,
         max_ratio: float = DEFAULT_MAX_RATIO) -> List[str]:
    """Every reason the measurement is outside budget; empty means pass."""
    reasons: List[str] = []
    if measured.get("evaluated", 0) == 0:
        reasons.append("no events were timed; overhead needs a corpus")
        return reasons
    p95 = measured["guarded"]["p95"]
    if p95 > max_p95_us:
        reasons.append("guarded p95 {} us exceeds {} us".format(p95, max_p95_us))
    overhead = measured["overhead_us"]["p95"]
    if overhead > max_overhead_us:
        reasons.append("added p95 {} us exceeds {} us".format(overhead, max_overhead_us))
    ratio = measured.get("ratio_p50")
    if ratio is not None and ratio > max_ratio:
        reasons.append("guarded floor ratio {:.0f}x exceeds {:.0f}x".format(ratio, max_ratio))
    return reasons


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Measure per-event policy overhead against an empty engine.")
    parser.add_argument("--corpus", default=str(ROOT / "benchmarks" / "fp" / "benign.jsonl"))
    parser.add_argument("--pack", default="coding-agent")
    parser.add_argument("--repeats", type=int, default=20,
                        help="timed passes over the corpus (default 20; the first pass is warm-up)")
    parser.add_argument("--max-p95-us", type=int, default=DEFAULT_MAX_P95_US)
    parser.add_argument("--max-overhead-us", type=int, default=DEFAULT_MAX_OVERHEAD_US)
    parser.add_argument("--max-ratio", type=float, default=DEFAULT_MAX_RATIO)
    parser.add_argument("--no-check", action="store_true", help="print numbers, never exit 1")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    events = load_corpus(args.corpus)
    measured = measure(builtin_pack(args.pack), events,
                       source="builtin:" + args.pack, repeats=args.repeats)
    reasons = gate(measured, max_p95_us=args.max_p95_us,
                   max_overhead_us=args.max_overhead_us, max_ratio=args.max_ratio)
    ok = not reasons

    if args.json:
        print(json.dumps({"passed": ok, "reasons": reasons, "measured": measured},
                         indent=2, sort_keys=True))
        return 0 if ok or args.no_check else 1

    floor, guarded = measured["floor"], measured["guarded"]
    print("corpus: {} ({} events x {} passes)".format(
        args.corpus, measured["events"], measured["repeats"]))
    print("floor   p50 {:>5} us  p95 {:>5} us  p99 {:>5} us".format(
        floor["p50"], floor["p95"], floor["p99"]))
    print("guarded p50 {:>5} us  p95 {:>5} us  p99 {:>5} us".format(
        guarded["p50"], guarded["p95"], guarded["p99"]))
    print("added   p50 {:>5} us  p95 {:>5} us  p99 {:>5} us  ({})".format(
        measured["overhead_us"]["p50"], measured["overhead_us"]["p95"],
        measured["overhead_us"]["p99"],
        "n/a" if measured["ratio_p50"] is None
        else "{:.0f}x floor".format(measured["ratio_p50"])))
    print()
    print("{:<16} {:>8} {:>8} {:>8} {:>9}".format(
        "action", "floor", "p50", "p95", "added"))
    for action, row in sorted(measured["by_action"].items(),
                              key=lambda item: item[1]["guarded"]["p50"], reverse=True):
        print("{:<16} {:>8} {:>8} {:>8} {:>9}".format(
            action, row["floor"]["p50"], row["guarded"]["p50"],
            row["guarded"]["p95"], row["overhead_us"]["p50"]))
    print()
    print("gate: {} (p95 <= {} us, added p95 <= {} us, ratio <= {:.0f}x)".format(
        "PASS" if ok else "FAIL", args.max_p95_us, args.max_overhead_us, args.max_ratio))
    for reason in reasons:
        print("  - " + reason)
    return 0 if ok or args.no_check else 1


if __name__ == "__main__":
    raise SystemExit(main())
