"""The committed benign corpus is the regression gate for the default pack.

``benchmarks/fp/benign.jsonl`` records ordinary coding-agent traffic. Every
event in it must be allowed by ``builtin:coding-agent``; a rule that starts
firing on a routine ``git status`` or ``npm test`` is a regression, not a
tuning question. The gate is also part of the suite, so it runs in CI with the
rest of the tests instead of in a separate job.
"""
from __future__ import annotations

import json
from pathlib import Path

from interlock.mesh.harness import (gate, gate_induced, gate_stress, induced_blocking,
                                    load_corpus, load_poisons, measure, stress)
from interlock.policy.packs import builtin_pack

FP_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "fp"
CORPUS = FP_DIR / "benign.jsonl"
HELDOUT = FP_DIR / "benign-heldout.jsonl"
POISONS = FP_DIR / "poisons.jsonl"


def _measure():
    return measure(builtin_pack("coding-agent"), load_corpus(str(CORPUS)),
                   source="builtin:coding-agent")


def test_corpus_has_enough_traffic_to_mean_something():
    assert len(load_corpus(str(CORPUS))) >= 60


def test_default_pack_allows_every_benign_event():
    measured = _measure()
    assert measured["false_positives"] == 0, json.dumps(measured["per_rule"], indent=2)


def test_the_pack_generalises_to_held_out_benign_traffic():
    # The main corpus is what policy tuning looked at, so a clean result there
    # can be overfitting. This split was written after the rules and is not used
    # while tuning: it holds ordinary traffic the pack has not been fitted to.
    heldout = load_corpus(str(HELDOUT))
    assert len(heldout) >= 15
    measured = measure(builtin_pack("coding-agent"), heldout,
                       source="builtin:coding-agent")
    assert measured["false_positives"] == 0, json.dumps(
        {"per_rule": measured["per_rule"], "fp": measured["false_positives"]}, indent=2)


def test_default_pack_passes_the_harness_gate():
    # The FP ceiling is the meaningful half (one event out of 70 already
    # exceeds it). The latency bound is widened 5x: the published p95 is ~2 ms
    # on the author's machine, and a shared CI runner can be several times
    # slower; the gate should catch a pathological regression, not a slow CPU.
    ok, reasons = gate(_measure(), max_p95_us=25_000)
    assert ok, reasons


def test_default_pack_is_not_induced_to_block_by_bait_in_non_execution_fields():
    report = induced_blocking(builtin_pack("coding-agent"), load_corpus(str(CORPUS)),
                              load_poisons(str(POISONS)), source="builtin:coding-agent")
    assert report["variants"] > 0
    assert report["induced"] == 0, json.dumps(report, indent=2)
    assert gate_induced(report) == []


def test_default_pack_stays_bounded_on_pathological_calls():
    # The bound is 3x the published p95 and still far below the pre-fix 0.6 s:
    # this catches a rule that starts scanning an unbounded argument list.
    rows = stress(builtin_pack("coding-agent"), repeats=1)
    assert gate_stress(rows, max_p95_us=150_000) == []
