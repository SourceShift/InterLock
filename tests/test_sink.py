"""Chained sinks: in-memory and newline-delimited JSON.

Every sink assigns ``prev`` and ``mac`` under a lock, so concurrent writers in
one process extend one chain. A ``FileSink`` reopened on an existing log
continues it across restarts; a final line that is not a receipt is refused
rather than silently restarted at GENESIS.
"""
from __future__ import annotations

import json
import threading

import pytest

from interlock.receipt import GENESIS, Receipt, hmac_sha256, verify_chain
from interlock.sink import FileSink, InMemorySink

KEY = b"k" * 32


def _receipt(index=0, **overrides):
    body = {"ts": float(index), "action": "shell", "verdict": "ALLOW",
            "reason": "policy", "policy_id": "p-1", "principal": "alice"}
    body.update(overrides)
    return Receipt(**body)


def test_an_in_memory_sink_chains_and_verifies():
    sink = InMemorySink(key=KEY)
    sink.write(_receipt(0))
    sink.write(_receipt(1))

    assert [receipt.prev for receipt in sink.receipts] == [
        GENESIS, sink.receipts[0].mac]
    assert sink.head == sink.receipts[-1].mac
    assert sink.verify() is None
    assert sink.verify(key=b"x" * 32) is not None


def test_a_file_sink_reopens_and_continues_the_chain(tmp_path):
    path = str(tmp_path / "receipts.jsonl")
    first = FileSink(path, key=KEY)
    first.write(_receipt(0))
    first.write(_receipt(1))
    head = first.head

    second = FileSink(path, key=KEY)
    second.write(_receipt(2))

    assert second.head != head
    lines = [Receipt.from_json(line) for line in
             open(path, encoding="utf-8").read().splitlines()]
    assert len(lines) == 3
    assert lines[2].prev == lines[1].mac
    assert verify_chain(lines, hmac_sha256, KEY) is None


def test_a_file_sink_refuses_to_continue_after_a_damaged_last_line(tmp_path):
    path = tmp_path / "receipts.jsonl"
    path.write_text('{"ts": 1.0, "action": "shel')

    with pytest.raises(ValueError):
        FileSink(str(path), key=KEY)


def test_editing_a_line_breaks_verification(tmp_path):
    path = tmp_path / "receipts.jsonl"
    sink = FileSink(str(path), key=KEY)
    sink.write(_receipt(0))
    sink.write(_receipt(1))
    lines = path.read_text().splitlines()
    record = json.loads(lines[0])
    record["verdict"] = "BLOCK"
    lines[0] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")

    assert FileSink(str(path), key=KEY).verify().startswith("receipt 0:")


def test_a_truncated_tail_is_detected_with_the_recorded_head(tmp_path):
    path = str(tmp_path / "receipts.jsonl")
    sink = FileSink(path, key=KEY)
    sink.write(_receipt(0))
    sink.write(_receipt(1))
    head = sink.head
    lines = open(path, encoding="utf-8").read().splitlines()
    open(path, "w", encoding="utf-8").write(lines[0] + "\n")

    reopened = FileSink(path, key=KEY)
    assert reopened.verify(head=head) is not None


def test_concurrent_writers_share_one_chain(tmp_path):
    path = str(tmp_path / "receipts.jsonl")
    sink = FileSink(path, key=KEY)

    def writer(offset):
        for index in range(10):
            sink.write(_receipt(offset + index))

    threads = [threading.Thread(target=writer, args=(base,))
               for base in (0, 10, 20, 30)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    receipts = [Receipt.from_json(line) for line in
                open(path, encoding="utf-8").read().splitlines()]
    assert len(receipts) == 40
    assert sink.verify() is None
