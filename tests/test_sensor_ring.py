"""The bounded sensor ring: byte cap, drop order, sequence continuity, drain.

The ring is the in-memory half of FR-074. It bounds payload bytes (not entry
count), evicts oldest observability before security with the spool's single
``KIND_PRIORITY`` vocabulary, and keys every entry by ``(host, sensor,
sequence)`` from a counter that survives a restart. ``put`` never raises, so a
full or broken ring cannot reach the guarded call.

The last test is the M6 latency proof: a spool at its cap, no acknowledgements,
and the hook still inside its verdict budget. It is opt-in with
``IL_EVAL_BENCH=1`` because a shared runner's p99 is not a stable measurement.
"""
from __future__ import annotations

import gzip
import json
import math
import os
import time

import pytest

from interlock.adapters import get_adapter, run_hook
from interlock.cloud.connector.spool import Spool, SpoolError
from interlock.policy.artifact import (
    ARTIFACT_FORMAT,
    FAILURE_POLICY_DEFAULTS,
    canonical_bytes,
    load_artifact,
    seal_artifact,
)
from interlock.sensor import DEFAULT_RING_BYTES, Ring


class _Clock:
    def __init__(self, value=0.0):
        self.value = float(value)

    def __call__(self):
        self.value += 1.0
        return self.value


def _ring(tmp_path, cap=DEFAULT_RING_BYTES):
    return Ring(tmp_path / "ring", capacity_bytes=cap, clock=_Clock())


# -- byte bound and drop order ------------------------------------------

def test_the_bound_is_payload_bytes_not_entry_count(tmp_path):
    ring = _ring(tmp_path, cap=100)

    first = ring.put("observability", b"a" * 60, host="h", sensor="s")
    second = ring.put("observability", b"b" * 60, host="h", sensor="s")

    assert first is not None and second is not None
    assert ring.count == 1
    assert ring.bytes == 60 <= ring.capacity_bytes
    assert [entry.payload for entry in ring.entries()] == [b"b" * 60]
    assert ring.dropped_entries == 1
    assert ring.dropped_by_kind == {"security": 0, "observability": 1}


def test_eviction_is_oldest_first_and_observability_before_security(tmp_path):
    ring = _ring(tmp_path, cap=100)
    security = ring.put("security", b"s" * 40, host="h", sensor="sec")
    old = ring.put("observability", b"o" * 40, host="h", sensor="obs")
    new = ring.put("observability", b"n" * 40, host="h", sensor="obs")
    dropped = ring.put("observability", b"x" * 120, host="h", sensor="obs")

    assert security is not None and new is not None
    assert old is not None
    assert dropped is None
    assert [entry is security for entry in ring.entries()] == [True]
    assert ring.dropped_entries == 3
    assert ring.dropped_by_kind["security"] == 0
    assert ring.dropped_by_kind["observability"] == 3


def test_a_security_entry_survives_any_number_of_observability_puts(tmp_path):
    ring = _ring(tmp_path, cap=100)
    security = ring.put("security", b"s" * 90, host="h", sensor="sec")

    for _ in range(100):
        ring.put("observability", b"o" * 20, host="h", sensor="obs")

    assert security is not None
    assert [entry for entry in ring.entries() if entry.kind == "security"] \
        == [security]
    assert ring.dropped_by_kind["security"] == 0
    assert ring.dropped_by_kind["observability"] == 100


def test_put_on_a_full_ring_returns_promptly_and_counts_the_drop(tmp_path):
    ring = Ring(capacity_bytes=10, clock=_Clock())
    started = time.perf_counter()
    for _ in range(1000):
        ring.put("observability", b"x" * 100, host="h", sensor="s")
    elapsed = time.perf_counter() - started

    assert elapsed < 1.0
    assert ring.count == 0
    assert ring.dropped_entries == 1000
    assert ring.status()["gaps"] == [
        {"host": "h", "sensor": "s", "first_missing": 1}]


def test_put_never_raises_for_a_bad_kind_or_payload(tmp_path):
    ring = _ring(tmp_path)

    assert ring.put("not-a-kind", b"x", host="h", sensor="s") is None
    assert ring.put("security", "text", host="h", sensor="s") is None
    assert ring.count == 0


# -- draining -------------------------------------------------------------

def test_drain_into_frames_spool_batches_and_round_trips_names(tmp_path):
    ring = _ring(tmp_path)
    spool = Spool(tmp_path / "spool", clock=_Clock())
    ring.put("security", b'{"review_id":"r1"}', host="host-1",
             sensor="reviews")
    ring.put("observability", b'{"receipts":1}', host="host-1",
             sensor="receipts")

    batches = ring.drain_into(spool)

    assert [batch.kind for batch in batches] == ["security", "observability"]
    # Sequences are per (host, sensor), exactly as the spool keys them.
    assert [batch.seq for batch in batches] == [1, 1]
    assert [batch.name for batch in spool.peek()] == [
        "security-00000000000000000001-host-1~reviews.json.gz",
        "observability-00000000000000000001-host-1~receipts.json.gz",
    ]
    assert gzip.decompress(batches[0].path.read_bytes()) == b'{"review_id":"r1"}'
    assert ring.count == 0 and ring.bytes == 0
    assert spool.batches()[0].host == "host-1"
    assert spool.batches()[0].sensor == "reviews"


def test_drain_returns_oldest_first_and_honours_the_limit(tmp_path):
    ring = _ring(tmp_path)
    first = ring.put("observability", b"1", host="h", sensor="s")
    second = ring.put("observability", b"2", host="h", sensor="s")
    third = ring.put("observability", b"3", host="h", sensor="s")

    assert ring.drain(limit=2) == [first, second]
    assert ring.entries() == [third]
    assert ring.bytes == 1


def test_a_failed_drain_leaves_the_entry_in_place(tmp_path):
    class _BrokenSpool:
        def add(self, *args, **kwargs):
            raise OSError("disk full")

    ring = _ring(tmp_path)
    entry = ring.put("security", b"x", host="h", sensor="s")

    assert ring.drain_into(_BrokenSpool()) == []
    assert ring.entries() == [entry]
    assert ring.bytes == 1


# -- sequence continuity --------------------------------------------------

def test_restart_continues_the_sequence_and_keeps_the_gap(tmp_path):
    directory = tmp_path / "ring"
    ring = Ring(directory, capacity_bytes=10, clock=_Clock())
    dropped = ring.put("observability", b"x" * 20, host="h", sensor="s")
    assert dropped is None

    state = json.loads((directory / "state.json").read_text())
    assert state["seqs"]["h"]["s"] == 1
    assert state["gaps"] == [{"host": "h", "sensor": "s", "first_missing": 1}]

    restarted = Ring(directory, capacity_bytes=10, clock=_Clock())
    entry = restarted.put("observability", b"ok", host="h", sensor="s")

    assert entry is not None
    assert entry.sequence == 2
    assert restarted.status()["gaps"] == [
        {"host": "h", "sensor": "s", "first_missing": 1}]


def test_the_spool_shares_one_sequence_authority_with_the_ring(tmp_path):
    spool = Spool(tmp_path / "spool", clock=_Clock())
    ring = Ring(tmp_path / "ring", clock=_Clock(),
                sequence_source=spool.next_sequence,
                sequence_release=spool.release_sequence)
    entry = ring.put("security", b"x", host="h", sensor="s")

    assert entry is not None
    batches = ring.drain_into(spool)
    assert [batch.seq for batch in batches] == [entry.sequence]
    assert json.loads((tmp_path / "spool" / "state.json").read_text())[
        "seqs"]["h"]["s"] == entry.sequence


def test_a_reserved_sequence_is_accepted_once_and_never_reused(tmp_path):
    spool = Spool(tmp_path / "spool", clock=_Clock())
    seq = spool.next_sequence("h", "s")

    first = spool.add("security", b"x", host="h", sensor="s", seq=seq)
    assert first.seq == seq
    with pytest.raises(SpoolError):
        spool.add("security", b"y", host="h", sensor="s", seq=seq)
    spool.remove(first)
    with pytest.raises(SpoolError):
        spool.add("security", b"z", host="h", sensor="s", seq=seq)


def test_a_restarted_spool_does_not_regress_a_reserved_sequence(tmp_path):
    directory = tmp_path / "spool"
    spool = Spool(directory, clock=_Clock())
    assert spool.next_sequence("h", "s") == 1

    restarted = Spool(directory, clock=_Clock())

    assert restarted.next_sequence("h", "s") == 2


# -- the M6 latency proof -------------------------------------------------

ARTIFACT_BYTES = 1024 * 1024
EVENT_BYTES = 32 * 1024
RULES = 32
REASON_PAD = 32 * 1024
WARMUP = 100
SAMPLES = 2000
NATIVE_P99_MS = 5.0
PYTHON_P99_MS = 10.0


def _rules() -> list:
    note = "operator note: reviewed, no production impact expected. " * (
        REASON_PAD // 55)
    return [
        {
            "id": "no-needle-{:02d}".format(index),
            "verdict": "block",
            "reason": "needle {}; {}".format(index, note),
            "when": {"all": [
                {"arg": "command",
                 "contains": "needle-{:02d}-absent".format(index)},
            ]},
        }
        for index in range(RULES)
    ]


def _artifact() -> bytes:
    body = seal_artifact({
        "format": ARTIFACT_FORMAT,
        "documents": [{"version": 1, "rules": _rules()}],
        "scope": {"version": 1, "bindings": {}, "default_scope": [],
                  "allow_unscoped": True},
        "rules_module": None,
        "template_ids": [],
        "catalog": "",
        "failure_policy": dict(FAILURE_POLICY_DEFAULTS),
    })
    return canonical_bytes(body)


def _payload() -> dict:
    command = "echo " + "a" * (EVENT_BYTES + 16)
    return {
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": {"command": command}, "session_id": "s",
        "cwd": "/tmp",
    }


def _p99_ms(call, samples: int = SAMPLES,
            warmup: int = WARMUP) -> float:
    import gc

    for _ in range(warmup):
        call()
    durations = []
    gc.collect()
    gc.disable()
    try:
        for _ in range(samples):
            started = time.process_time()
            call()
            durations.append((time.process_time() - started) * 1000.0)
    finally:
        gc.enable()
    durations.sort()
    index = max(0, math.ceil(0.99 * samples) - 1)
    return durations[index]


@pytest.mark.skipif(
    not os.environ.get("IL_EVAL_BENCH"),
    reason="set IL_EVAL_BENCH=1 to run the full-spool latency proof")
def test_a_full_spool_leaves_hook_verdict_latency_unchanged(tmp_path, capsys):
    pytest.importorskip("interlock_scopes")
    raw = _artifact()
    payload = _payload()
    assert len(raw) >= ARTIFACT_BYTES
    assert len(json.dumps(payload["tool_input"]["command"])) >= EVENT_BYTES
    adapter = get_adapter("claude-code")

    full = Spool(tmp_path / "spool", cap_bytes=4096, clock=_Clock())
    for _ in range(10):
        full.add("observability", b"o" * 1000, host="host-1", sensor="receipts")
    assert full.dropped_batches > 0
    assert full.bytes <= full.cap_bytes
    dropped = full.dropped_batches

    fast = load_artifact(raw)
    slow = load_artifact(raw, native_enabled=False)
    assert fast.status()["native_base"] is True
    native_ms = _p99_ms(lambda: run_hook(adapter, payload, fast,
                                         review_mode="off"))
    python_ms = _p99_ms(lambda: run_hook(adapter, payload, slow,
                                         review_mode="off"))

    with capsys.disabled():
        print(
            "\nfull-spool budget: spool {}/{} bytes, dropped {}, "
            "{} warm-up + {} samples\n"
            "  hook+native p99 {:.3f} ms CPU (budget {:.1f} ms)\n"
            "  hook+python p99 {:.3f} ms CPU (budget {:.1f} ms)".format(
                full.bytes, full.cap_bytes, dropped, WARMUP, SAMPLES,
                native_ms, NATIVE_P99_MS, python_ms, PYTHON_P99_MS))

    assert full.dropped_batches >= dropped
    assert native_ms < NATIVE_P99_MS, "native p99 {:.3f} ms".format(native_ms)
    assert python_ms < PYTHON_P99_MS, "python p99 {:.3f} ms".format(python_ms)
