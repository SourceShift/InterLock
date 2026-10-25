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

from interlock.mesh.harness import gate, load_corpus, measure
from interlock.policy.packs import builtin_pack

CORPUS = Path(__file__).resolve().parent.parent / "benchmarks" / "fp" / "benign.jsonl"


def _measure():
    return measure(builtin_pack("coding-agent"), load_corpus(str(CORPUS)),
                   source="builtin:coding-agent")


def test_corpus_has_enough_traffic_to_mean_something():
    assert len(load_corpus(str(CORPUS))) >= 60


def test_default_pack_allows_every_benign_event():
    measured = _measure()
    assert measured["false_positives"] == 0, json.dumps(measured["per_rule"], indent=2)


def test_default_pack_passes_the_harness_gate():
    # The FP ceiling is the meaningful half (one event out of 70 already
    # exceeds it). The latency bound is widened 5x: the published p95 is ~2 ms
    # on the author's machine, and a shared CI runner can be several times
    # slower; the gate should catch a pathological regression, not a slow CPU.
    ok, reasons = gate(_measure(), max_p95_us=25_000)
    assert ok, reasons
