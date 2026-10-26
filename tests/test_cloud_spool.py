"""The bounded spool: logical-size accounting, drop order, durability.

The cap is over the *uncompressed* payload: a highly compressible batch must
not sneak past it. Eviction is observability first and security last, oldest
first inside a kind, and every drop is counted for the status surface. The
manifest and seqs survive a restart, and an orphan batch file is adopted so a
crash between write and manifest does not lose data.
"""
from __future__ import annotations

import gzip
import json
import os
import stat

import pytest

from interlock.cloud.connector.spool import (
    DEFAULT_CAP_BYTES,
    Spool,
    SpoolError,
)


class _Clock:
    def __init__(self, value=0.0):
        self.value = float(value)

    def __call__(self):
        self.value += 1.0
        return self.value


def _spool(tmp_path, cap=DEFAULT_CAP_BYTES):
    return Spool(tmp_path / "spool", cap_bytes=cap, clock=_Clock())


def test_add_writes_a_gzip_file_and_a_manifest_entry(tmp_path):
    spool = _spool(tmp_path)
    payload = b'{"review_id":"r1"}'

    batch = spool.add("security", payload, host="host-1", sensor="reviews")

    assert batch.kind == "security"
    assert batch.seq == 1
    assert batch.host == "host-1"
    assert batch.sensor == "reviews"
    assert batch.size == len(payload)
    assert batch.path.is_file()
    assert batch.name.startswith("security-00000000000000000001-")
    assert gzip.decompress(batch.path.read_bytes()) == payload
    assert spool.count == 1
    assert spool.peek() == [batch]
    assert stat.S_IMODE(batch.path.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "spool" / "state.json").stat().st_mode) == 0o600


def test_bytes_counts_uncompressed_payload_not_gzip_output(tmp_path):
    spool = _spool(tmp_path)
    payload = b"a" * 100_000

    batch = spool.add("observability", payload, host="h", sensor="s")

    assert spool.bytes == len(payload) == 100_000
    assert batch.path.stat().st_size < len(payload)
    assert spool.bytes != batch.path.stat().st_size


def test_cap_drops_observability_before_security(tmp_path):
    spool = _spool(tmp_path, cap=1024)
    spool.add("observability", b"o" * 700, host="h", sensor="obs")
    spool.add("security", b"s" * 700, host="h", sensor="sec")

    kinds = [batch.kind for batch in spool.batches()]
    assert kinds == ["security"]
    assert spool.bytes == 700 <= spool.cap_bytes
    assert spool.dropped_batches == 1
    assert spool.dropped_by_kind == {"security": 0, "observability": 1}


def test_security_survives_even_when_it_is_the_older_batch(tmp_path):
    spool = _spool(tmp_path, cap=1024)
    spool.add("security", b"s" * 700, host="h", sensor="sec")
    spool.add("observability", b"o" * 700, host="h", sensor="obs")

    assert [batch.kind for batch in spool.batches()] == ["security"]
    assert spool.dropped_by_kind["observability"] == 1
    assert spool.dropped_by_kind["security"] == 0


def test_a_single_oversized_observability_batch_is_dropped(tmp_path):
    spool = _spool(tmp_path, cap=1024)
    spool.add("security", b"s" * 700, host="h", sensor="sec")
    dropped = spool.add("observability", b"o" * 2000, host="h", sensor="obs")

    assert dropped.path.exists() is False
    assert [batch.kind for batch in spool.batches()] == ["security"]
    assert spool.dropped_batches == 1


def test_security_is_dropped_only_after_observability_is_gone(tmp_path):
    spool = _spool(tmp_path, cap=1024)
    spool.add("security", b"s" * 2000, host="h", sensor="sec")

    assert spool.count == 0
    assert spool.bytes == 0
    assert spool.dropped_by_kind == {"security": 1, "observability": 0}


def test_oldest_observability_batches_go_first(tmp_path):
    clock = _Clock(100.0)
    spool = Spool(tmp_path / "spool", cap_bytes=1500, clock=clock)
    first = spool.add("observability", b"1" * 700, host="h", sensor="a")
    second = spool.add("observability", b"2" * 700, host="h", sensor="b")
    third = spool.add("observability", b"3" * 700, host="h", sensor="c")

    remaining = [batch.name for batch in spool.batches()]
    assert first.name not in remaining
    assert second.name in remaining and third.name in remaining


def test_seqs_are_monotonic_per_host_and_sensor(tmp_path):
    spool = _spool(tmp_path)
    a1 = spool.add("security", b"a", host="h1", sensor="reviews")
    a2 = spool.add("security", b"a", host="h1", sensor="reviews")
    b1 = spool.add("security", b"b", host="h1", sensor="receipts")
    c1 = spool.add("security", b"c", host="h2", sensor="reviews")
    assert (a1.seq, a2.seq, b1.seq, c1.seq) == (1, 2, 1, 1)


def test_acknowledge_removes_the_file_and_manifest_row(tmp_path):
    spool = _spool(tmp_path)
    batch = spool.add("security", b"x", host="h", sensor="s")

    assert spool.acknowledge(batch) is True
    assert not batch.path.exists()
    assert spool.count == 0
    assert spool.remove(batch) is False


def test_state_survives_a_restart_and_seq_does_not_reuse(tmp_path):
    directory = tmp_path / "spool"
    first = Spool(directory, clock=_Clock(1.0))
    batch = first.add("security", b"x", host="h", sensor="s")

    second = Spool(directory, clock=_Clock(2.0))
    assert [b.name for b in second.batches()] == [batch.name]
    assert second.bytes == len(b"x")
    assert second.add("security", b"y", host="h", sensor="s").seq == 2


def test_an_orphan_batch_is_adopted_and_its_seq_is_not_reused(tmp_path):
    directory = tmp_path / "spool"
    directory.mkdir()
    name = "security-00000000000000000007-host~reviews.json.gz"
    (directory / name).write_bytes(gzip.compress(b"orphan"))

    spool = Spool(directory)

    assert [batch.name for batch in spool.batches()] == [name]
    assert spool.bytes == len(b"orphan")
    assert spool.add("security", b"new", host="host",
                     sensor="reviews").seq == 8


def test_an_orphan_with_a_hyphenated_host_keeps_host_and_sensor_apart(
        tmp_path):
    directory = tmp_path / "spool"
    directory.mkdir()
    name = "security-00000000000000000003-build-host~reviews.json.gz"
    (directory / name).write_bytes(gzip.compress(b"orphan"))

    spool = Spool(directory)

    [adopted] = spool.batches()
    assert (adopted.host, adopted.sensor) == ("build-host", "reviews")
    # The recovered (host, sensor) reserves seq 3, so a crash cannot reuse it.
    assert spool.add("security", b"new", host="build-host",
                     sensor="reviews").seq == 4


def test_a_vanished_file_drops_its_manifest_row(tmp_path):
    directory = tmp_path / "spool"
    first = Spool(directory)
    batch = first.add("security", b"x", host="h", sensor="s")
    os.unlink(batch.path)

    second = Spool(directory)
    assert second.count == 0
    assert second.bytes == 0
    assert second.add("security", b"x", host="h", sensor="s").seq == 2


def test_partial_temporary_files_are_cleaned_up(tmp_path):
    directory = tmp_path / "spool"
    directory.mkdir()
    stray = directory / ".batch.json.gz.abc.tmp"
    stray.write_bytes(b"partial")

    Spool(directory)

    assert not stray.exists()


@pytest.mark.parametrize("kind", ["", "audit", "SECURITY", "security "])
def test_unknown_kinds_are_refused(tmp_path, kind):
    with pytest.raises(SpoolError):
        _spool(tmp_path).add(kind, b"x", host="h", sensor="s")


def test_cap_must_be_positive(tmp_path):
    with pytest.raises(SpoolError):
        Spool(tmp_path / "spool", cap_bytes=0)


@pytest.mark.parametrize("data", ["a string", 5, None])
def test_batch_data_must_be_bytes(tmp_path, data):
    with pytest.raises(SpoolError):
        _spool(tmp_path).add("security", data, host="h", sensor="s")


def test_state_file_is_json_and_records_drops(tmp_path):
    spool = _spool(tmp_path, cap=10)
    spool.add("security", b"x" * 20, host="h", sensor="s")
    state = json.loads((tmp_path / "spool" / "state.json").read_text())
    assert state["dropped_batches"] == 1
    assert state["dropped_by_kind"]["security"] == 1
