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
    DEFAULT_MAX_P95_US,
    gate,
    load_corpus,
    measure,
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
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    policy = builtin_pack(args.pack)
    measured = measure(policy, load_corpus(args.corpus),
                       source="builtin:" + args.pack, repeats=args.repeats)
    ok, reasons = gate(measured, max_fp_rate=args.max_fp_rate, max_p95_us=args.max_p95_us)

    if args.json:
        print(json.dumps({"passed": ok, "reasons": reasons, "measured": measured},
                         indent=2, sort_keys=True))
        return 0 if ok else 1

    latency = measured["latency_us"]
    print("corpus: {} ({} events, {} evaluated)".format(
        args.corpus, measured["events"], measured["evaluated"]))
    print("false positives: {} ({:.4%})".format(
        measured["false_positives"], measured["fp_rate"]))
    for rule, stats in measured["per_rule"].items():
        print("  {} -> {}".format(rule, stats["verdicts"]))
    print("latency: p50 {} us, p95 {} us, max {} us".format(
        latency["p50"], latency["p95"], latency["max"]))
    print("gate: {} (max fp rate {:.4%}, max p95 {} us)".format(
        "PASS" if ok else "FAIL", args.max_fp_rate, args.max_p95_us))
    for reason in reasons:
        print("  - " + reason)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
