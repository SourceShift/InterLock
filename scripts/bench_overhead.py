#!/usr/bin/env python3
"""Measure what the guard costs per event, against an engine with no rules.

    python3 scripts/bench_overhead.py                    # human-readable
    python3 scripts/bench_overhead.py --json             # for tooling
    python3 scripts/bench_overhead.py --repeats 50       # steadier tail
    python3 scripts/bench_overhead.py --no-native        # Python only

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

The default pack is deliberately not native-eligible (parameterised detectors,
rewrites and overlays keep the policy on Python), so the native comparison
uses ``benchmarks/overhead/native-policy.json``: the same corpus and the same
policy through both engines. It is reported separately and never gates: it
answers "what does the opt-in fast path save", not "did the policy regress".
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, Sequence

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from interlock.event import SensorEvent  # noqa: E402
from interlock.mesh.harness import (  # noqa: E402
    DEFAULT_MAX_P95_US,
    _percentile,
    load_corpus,
)
from interlock.policy import native  # noqa: E402
from interlock.policy.declarative import load_policy  # noqa: E402
from interlock.policy.engine import PolicyEngine  # noqa: E402
from interlock.policy.packs import builtin_pack  # noqa: E402

NATIVE_POLICY = ROOT / "benchmarks" / "overhead" / "native-policy.json"

DEFAULT_MAX_OVERHEAD_US = 5000
#: The guard was ~30x the empty engine in the recorded run. A 500x ceiling is
#: a smoke alarm for a broken floor, not a budget anyone should tune against.
#: A floor below ``MIN_RATIO_FLOOR_US`` is timer resolution, not work, so no
#: ratio is computed from it.
DEFAULT_MAX_RATIO = 500.0
MIN_RATIO_FLOOR_US = 5


def _timed(evaluate: Callable[[SensorEvent], Any], events: Sequence[SensorEvent],
           repeats: int) -> Dict[str, List[int]]:
    """Untimed warm-up, then ``repeats`` timed passes; microseconds per action."""
    for event in events:
        evaluate(event)
    per_action: Dict[str, List[int]] = defaultdict(list)
    for _ in range(max(1, repeats)):
        for event in events:
            started = time.perf_counter()
            evaluate(event)
            per_action[event.action].append(int((time.perf_counter() - started) * 1_000_000))
    return per_action


def _run(engine: Any, events: Sequence[SensorEvent], repeats: int) -> Dict[str, List[int]]:
    """Time ``engine.evaluate``; kept as the seam the Python comparison uses."""
    return _timed(engine.evaluate, events, repeats)


@contextmanager
def _python_engine(policy: Mapping[str, Any], *, source: str) -> Iterator[Any]:
    """Load a policy with the native path forced off.

    A benchmark that inherits ``INTERLOCK_NATIVE=1`` would time the native
    evaluator twice and call the result a comparison. The flag is restored
    afterwards, so measuring does not change the caller's environment.
    """
    saved = os.environ.pop(native.ENV_FLAG, None)
    try:
        yield load_policy(policy, source=source)
    finally:
        if saved is not None:
            os.environ[native.ENV_FLAG] = saved


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
    with _python_engine(policy, source=source) as engine:
        guarded = _run(engine, events, repeats)

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


def measure_native(policy: Mapping[str, Any], corpus: Iterable[SensorEvent], *,
                   source: str = "<native>", repeats: int = 20) -> Dict[str, Any]:
    """The same policy through the Python engine and the native plan evaluator.

    The plan is compiled once, outside the timed passes, because a host does
    that at startup; the samples measure decision cost (including the JSON
    boundary the PyO3 front end needs), not plan parsing. A policy the planner
    declines, or a missing ``interlock_scopes`` wheel, yields ``{"skipped": ...}``
    rather than a comparison of incomparable numbers.
    """
    events = list(corpus)
    if native._plan_class() is None:
        return {"skipped": "interlock_scopes is not installed"}
    with _python_engine(policy, source=source) as engine:
        plan = native.build(engine)
        if plan is None:
            return {"skipped": "policy is not native-eligible"}
        python_samples = _timed(engine.evaluate, events, repeats)
    native_samples = _timed(lambda event: native.decide(plan, event), events, repeats)

    def speedup(python_summary: Mapping[str, int],
                native_summary: Mapping[str, int]) -> Any:
        if not native_summary["p50"]:
            return None
        return round(python_summary["p50"] / native_summary["p50"], 2)

    actions: Dict[str, Dict[str, Any]] = {}
    for action in sorted(set(python_samples) | set(native_samples)):
        python_summary = _summary(python_samples.get(action, ()))
        native_summary = _summary(native_samples.get(action, ()))
        actions[action] = {
            "python": python_summary,
            "native": native_summary,
            "speedup_p50": speedup(python_summary, native_summary),
        }

    python_all = [value for values in python_samples.values() for value in values]
    native_all = [value for values in native_samples.values() for value in values]
    python_summary = _summary(python_all)
    native_summary = _summary(native_all)
    return {
        "events": len(events),
        "repeats": max(1, repeats),
        "evaluated": len(native_all),
        "source": source,
        "python": python_summary,
        "native": native_summary,
        "speedup_p50": speedup(python_summary, native_summary),
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
    parser.add_argument("--native-policy", default=str(NATIVE_POLICY),
                        help="native-eligible policy for the Python-vs-native comparison")
    parser.add_argument("--no-native", action="store_true",
                        help="skip the native comparison")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    events = load_corpus(args.corpus)
    measured = measure(builtin_pack(args.pack), events,
                       source="builtin:" + args.pack, repeats=args.repeats)
    reasons = gate(measured, max_p95_us=args.max_p95_us,
                   max_overhead_us=args.max_overhead_us, max_ratio=args.max_ratio)
    ok = not reasons

    native_measured: Any = None
    if not args.no_native:
        try:
            with open(args.native_policy, encoding="utf-8") as handle:
                native_policy = json.load(handle)
        except OSError as exc:
            native_measured = {"skipped": "cannot read {}: {}".format(
                args.native_policy, exc.strerror)}
        else:
            native_measured = measure_native(
                native_policy, events, source="file:" + args.native_policy,
                repeats=args.repeats)

    if args.json:
        print(json.dumps({"passed": ok, "reasons": reasons, "measured": measured,
                          "native": native_measured},
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
    if native_measured is not None:
        print()
        if "skipped" in native_measured:
            print("native: skipped ({})".format(native_measured["skipped"]))
        else:
            python_side, native_side = native_measured["python"], native_measured["native"]
            print("native ({}): python p50 {} us, native p50 {} us  ({})".format(
                native_measured["source"], python_side["p50"], native_side["p50"],
                "n/a" if native_measured["speedup_p50"] is None
                else "{:.1f}x faster".format(native_measured["speedup_p50"])))
            print("{:<16} {:>10} {:>10} {:>9}".format("action", "python", "native", "speedup"))
            for action, row in sorted(native_measured["by_action"].items(),
                                      key=lambda item: item[1]["python"]["p50"],
                                      reverse=True):
                print("{:<16} {:>10} {:>10} {:>8}".format(
                    action, row["python"]["p50"], row["native"]["p50"],
                    "n/a" if row["speedup_p50"] is None
                    else "{:.1f}x".format(row["speedup_p50"])))
    print()
    print("gate: {} (p95 <= {} us, added p95 <= {} us, ratio <= {:.0f}x)".format(
        "PASS" if ok else "FAIL", args.max_p95_us, args.max_overhead_us, args.max_ratio))
    for reason in reasons:
        print("  - " + reason)
    return 0 if ok or args.no_check else 1


if __name__ == "__main__":
    raise SystemExit(main())
