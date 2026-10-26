"""The connector's receipt tailer (FR-032).

Only complete lines are framed; a trailing partial write is unread. A
malformed line stops the batch before it and is reported with its line
number. The durable offset moves only when the caller commits, which the
connector does only after a 2xx.
"""
from __future__ import annotations

import json

import pytest

from interlock.cloud.connector.receipts import (
    ReceiptBatch,
    ReceiptTailer,
    TailerError,
)
from interlock.receipt import GENESIS, Receipt, compute_mac, hmac_sha256

KEY = b"k" * 32


def _line(index, *, prev=None, action="shell"):
    receipt = Receipt(
        ts=float(index), action=action, verdict="ALLOW", reason="r",
        policy_id="p-1", principal="alice", prev=prev or GENESIS)
    receipt.mac = compute_mac(receipt, hmac_sha256, KEY)
    return receipt


def _write(path, receipts, trailing=b""):
    payload = b"".join(
        (receipt.to_json() + "\n").encode("utf-8") for receipt in receipts)
    path.write_bytes(payload + trailing)
    return payload


def test_only_complete_newline_terminated_lines_are_batched(tmp_path):
    log = tmp_path / "receipts.jsonl"
    first = _line(1)
    second = _line(2, prev=first.mac)
    payload = _write(log, [first, second], trailing=b'{"ts": 3, "action"')
    tailer = ReceiptTailer(log, tmp_path / "offset.json", host_id="h1")

    batch = tailer.next_batch()

    assert batch.count == 2
    assert [receipt.action for receipt in batch.receipts] == ["shell", "shell"]
    assert batch.start_offset == 0
    assert batch.end_offset == len(payload)
    assert batch.end_line == 3
    # The partial third line is still pending, not parsed as a batch; until
    # the batch is committed every unread byte is still pending.
    assert tailer.pending_bytes() == len(payload) + len(b'{"ts": 3, "action"')
    assert tailer.offset == 0
    tailer.commit(batch)
    assert tailer.pending_bytes() == len(b'{"ts": 3, "action"')


def test_the_offset_advances_only_on_commit(tmp_path):
    log = tmp_path / "receipts.jsonl"
    _write(log, [_line(1), _line(2, prev=_line(1).mac)])
    offset_path = tmp_path / "state" / "offset.json"
    tailer = ReceiptTailer(log, offset_path)

    first = tailer.next_batch()
    again = tailer.next_batch()
    assert again.start_offset == first.start_offset == 0
    assert tailer.offset == 0
    assert not offset_path.exists()

    tailer.commit(first)

    assert tailer.offset == first.end_offset
    stored = json.loads(offset_path.read_text())
    assert stored == {"offset": first.end_offset, "line": first.end_line}
    # A fresh tailer resumes at the committed line, not from zero.
    resumed = ReceiptTailer(log, offset_path)
    assert resumed.offset == first.end_offset
    assert resumed.next_batch().count == 0


def test_a_malformed_line_stops_the_batch_and_names_its_line(tmp_path):
    log = tmp_path / "receipts.jsonl"
    good = _line(1)
    second = _line(2, prev=good.mac)
    log.write_text(
        good.to_json() + "\n" + "{not json}\n" + second.to_json() + "\n")
    tailer = ReceiptTailer(log, tmp_path / "offset.json")

    batch = tailer.next_batch()

    assert batch.count == 1
    assert batch.end_line == 2
    assert tailer.last_error_line == 2
    assert tailer.last_error.startswith("line 2:")
    # The offset did not move past the bad line.
    assert batch.end_offset == len((good.to_json() + "\n").encode())


def test_max_batch_frames_a_prefix_and_leaves_the_rest(tmp_path):
    log = tmp_path / "receipts.jsonl"
    receipts = [_line(1), _line(2), _line(3)]
    _write(log, receipts)
    tailer = ReceiptTailer(log, tmp_path / "offset.json", max_batch=2)

    batch = tailer.next_batch()

    assert batch.count == 2
    assert batch.end_line == 3
    tailer.commit(batch)
    assert tailer.next_batch().count == 1


def test_max_bytes_reads_a_complete_line_prefix(tmp_path):
    log = tmp_path / "receipts.jsonl"
    receipts = [_line(1), _line(2)]
    payload = _write(log, receipts)
    tailer = ReceiptTailer(log, tmp_path / "offset.json",
                           max_bytes=len(payload) // 2 + 5)

    batch = tailer.next_batch()

    assert batch.count == 1
    assert batch.end_offset <= len(payload)


def test_rewind_to_a_line_reads_from_that_lines_start(tmp_path):
    log = tmp_path / "receipts.jsonl"
    receipts = [_line(index) for index in range(1, 5)]
    _write(log, receipts)
    tailer = ReceiptTailer(log, tmp_path / "offset.json")
    tailer.commit(tailer.next_batch())
    assert tailer.offset > 0

    offset = tailer.rewind_to(3)

    assert offset == len(
        ("".join(receipt.to_json() + "\n" for receipt in receipts[:2])
         ).encode())
    assert tailer.line == 3
    assert tailer.next_batch().count == 2


def test_rewind_rejects_line_zero(tmp_path):
    log = tmp_path / "receipts.jsonl"
    _write(log, [_line(1)])
    tailer = ReceiptTailer(log, tmp_path / "offset.json")
    with pytest.raises(TailerError):
        tailer.rewind_to(0)


def test_status_names_the_receipt_offset_and_pending_bytes(tmp_path):
    log = tmp_path / "receipts.jsonl"
    _write(log, [_line(1)], trailing=b"partial")
    tailer = ReceiptTailer(log, tmp_path / "offset.json")
    batch = tailer.next_batch()
    tailer.commit(batch)

    status = tailer.status()

    assert status == {
        "receipts_offset": batch.end_offset,
        "receipts_line": 2,
        "receipts_pending_bytes": len(b"partial"),
        "last_receipt_error": None,
    }


def test_a_batch_serializes_the_exact_wire_payload(tmp_path):
    batch = ReceiptBatch([_line(1)], 0, 10, 1, 2)
    payload = json.loads(batch.body("host-1"))
    assert payload["host_id"] == "host-1"
    assert payload["receipts"][0]["action"] == "shell"
    assert payload["receipts"][0]["prev"] == GENESIS
