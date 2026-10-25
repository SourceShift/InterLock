#!/usr/bin/env python3
"""Measure the built-in ``coding-agent`` pack against a committed benign corpus.

    python3 scripts/fp_baseline.py            # human-readable
    python3 scripts/fp_baseline.py --json     # machine-readable
    python3 scripts/fp_baseline.py --corpus other.jsonl --max-fp-rate 0.0

Exits 1 when the harness gate fails: a false positive on benign traffic, a
quarantined rule, or a p95 evaluation cost above the bound. ``tests/
test_fp_baseline.py`` runs the same measurement inside the normal suite, so a
rule that starts firing on ordinary developer traffic breaks CI, not a user.

The pack is built at run time rather than read from a committed JSON because
``coding_agent()`` embeds the current user's home directory in its protected
paths; a static policy file would either be wrong on another machine or carry
one developer's home path into the repository.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from interlock.mesh.harness import (  # noqa: E402
    DEFAULT_MAX_FP_RATE,
    DEFAULT_MAX_INDUCED_RATE,
    DEFAULT_MAX_P95_US,
    DEFAULT_MAX_STRESS_P95_US,
    gate,
    gate_induced,
    gate_stress,
    induced_blocking,
    load_corpus,
    load_poisons,
    measure,
    measure_each_detector,
    measure_each_rule,
    stress,
)
from interlock.policy.packs import builtin_pack  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Measure the built-in coding-agent pack against a benign corpus.")
    parser.add_argument("--corpus", default=str(ROOT / "benchmarks" / "fp" / "benign.jsonl"))
    parser.add_argument("--pack", default="coding-agent")
    parser.add_argument("--repeats", type=int, default=3,
                        help="passes over the corpus; latency percentiles need more than one (default 3)")
    parser.add_argument("--max-fp-rate", type=float, default=DEFAULT_MAX_FP_RATE)
    parser.add_argument("--max-p95-us", type=int, default=DEFAULT_MAX_P95_US)
    parser.add_argument("--per-rule", action="store_true",
                        help="also measure each rule alone, so dormant rules get a number")
    parser.add_argument("--per-detector", action="store_true",
                        help="also measure each detector with all of its rules, "
                             "so a detector is priced as itself")
    parser.add_argument("--poisons", default=None, metavar="FILE",
                        help="JSONL bait strings; measure induced blocking when a call's "
                             "non-execution fields carry them")
    parser.add_argument("--stress", action="store_true",
                        help="time pathological but legal calls (huge args, deep nesting)")
    parser.add_argument("--max-induced-rate", type=float, default=DEFAULT_MAX_INDUCED_RATE)
    parser.add_argument("--max-stress-p95-us", type=int, default=DEFAULT_MAX_STRESS_P95_US)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    policy = builtin_pack(args.pack)
    events = load_corpus(args.corpus)
    source = "builtin:" + args.pack
    measured = measure(policy, events, source=source, repeats=args.repeats)
    ok, reasons = gate(measured, max_fp_rate=args.max_fp_rate, max_p95_us=args.max_p95_us)
    isolated = (measure_each_rule(policy, events, source=source, repeats=args.repeats)
                if args.per_rule else None)
    detectors = (measure_each_detector(policy, events, source=source, repeats=args.repeats)
                 if args.per_detector else None)
    induced = None
    if args.poisons:
        induced = induced_blocking(policy, events, load_poisons(args.poisons), source=source)
        reasons.extend(gate_induced(induced, max_rate=args.max_induced_rate))
    stressed = stress(policy, source=source, repeats=max(1, args.repeats)) if args.stress else None
    if stressed is not None:
        reasons.extend(gate_stress(stressed, max_p95_us=args.max_stress_p95_us))
    ok = not reasons

    if args.json:
        payload = {"passed": ok, "reasons": reasons, "measured": measured}
        if isolated is not None:
            payload["per_rule_isolated"] = isolated
        if detectors is not None:
            payload["per_detector"] = detectors
        if induced is not None:
            payload["induced"] = induced
        if stressed is not None:
            payload["stress"] = stressed
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if ok else 1

    latency = measured["latency_us"]
    print("corpus: {} ({} events, {} evaluated)".format(
        args.corpus, measured["events"], measured["evaluated"]))
    print("false positives: {} ({:.4%})".format(
        measured["false_positives"], measured["fp_rate"]))
    for rule, stats in measured["per_rule"].items():
        print("  {} -> {}".format(rule, stats["verdicts"]))
    print("latency: p50 {} us, p95 {} us, p99 {} us, max {} us".format(
        latency["p50"], latency["p95"], latency["p99"], latency["max"]))
    if isolated is not None:
        print()
        print("per rule, measured alone ({} events x {} passes):".format(
            len(events), args.repeats))
        print("  {:<28} {:>5} {:>9} {:>8} {:>8}  {}".format(
            "rule", "fp", "rate", "p50 us", "p95 us", "verdicts"))
        for row in isolated:
            if "error" in row:
                print("  {:<28} ERROR {}".format(row["rule"], row["error"]))
                continue
            print("  {:<28} {:>5} {:>8.4%} {:>8} {:>8}  {}".format(
                row["rule"], row["false_positives"], row["fp_rate"],
                row["latency_us"]["p50"], row["latency_us"]["p95"],
                row["verdicts"] or "-"))
    if detectors is not None:
        print()
        print("per detector, all of its rules together ({} events x {} passes):".format(
            len(events), args.repeats))
        print("  {:<36} {:>5} {:>9} {:>8} {:>8}  {}".format(
            "detector", "fp", "rate", "p50 us", "p95 us", "rules"))
        for row in detectors:
            if "error" in row:
                print("  {:<36} ERROR {}".format(row["detector"], row["error"]))
                continue
            print("  {:<36} {:>5} {:>8.4%} {:>8} {:>8}  {}".format(
                row["detector"], row["false_positives"], row["fp_rate"],
                row["latency_us"]["p50"], row["latency_us"]["p95"],
                ", ".join(row["rules"])))
    if induced is not None:
        print()
        print("induced blocking: {} of {} poisoned call(s) refused ({:.4%})".format(
            induced["induced"], induced["variants"], induced["induced_rate"]))
        for rule, hits in induced["by_rule"].items():
            print("  {}: {}".format(rule, hits))
    if stressed is not None:
        print()
        print("stress (pathological but legal calls):")
        print("  {:<4} {:<12} {:>9} {:>8} {:>8}  {}".format(
            "case", "action", "bytes", "p50 us", "p95 us", "verdict"))
        for row in stressed:
            print("  {:<4} {:<12} {:>9} {:>8} {:>8}  {}".format(
                row["case"], row["action"], row["bytes"], row["latency_us"]["p50"],
                row["latency_us"]["p95"], row["verdict"]))
    print("gate: {} (max fp rate {:.4%}, max p95 {} us{}{})".format(
        "PASS" if ok else "FAIL", args.max_fp_rate, args.max_p95_us,
        ", max induced rate {:.4%}".format(args.max_induced_rate) if induced is not None else "",
        ", max stress p95 {} us".format(args.max_stress_p95_us) if stressed is not None else ""))
    for reason in reasons:
        print("  - " + reason)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
