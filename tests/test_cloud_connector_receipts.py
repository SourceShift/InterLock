"""The connector tails receipt lines and acknowledges only after a 2xx.

A batch is framed from complete lines into the spool as an ``observability``
batch with ``sensor="receipts"``. The durable byte offset moves when that
exact spool file is acknowledged; a 5xx leaves both the spool batch and the
offset untouched, and the next cycle retries the same bytes.
"""
from __future__ import annotations

import json

import pytest

from interlock.cloud.connector.config import CloudHome, HomeError
from interlock.cloud.connector.runner import Connector
from interlock.cloud.connector.transport import FakeTransport
from interlock.cloud.enrollment import generate_agent_key
from interlock.cloud.identity import (
    generate_host_seed,
    key_id,
    public_key_hex,
)
from interlock.receipt import GENESIS, Receipt, compute_mac, hmac_sha256

KEY = b"k" * 32


class _Clock:
    def __init__(self, value=5000.0):
        self.value = float(value)

    def __call__(self):
        return self.value


def _receipts(count=2):
    out = []
    prev = GENESIS
    for index in range(count):
        receipt = Receipt(ts=float(index), action="shell", verdict="ALLOW",
                          reason="r", policy_id="p-1", principal="alice",
                          prev=prev)
        receipt.mac = compute_mac(receipt, hmac_sha256, KEY)
        out.append(receipt)
        prev = receipt.mac
    return out


def _home(tmp_path, *, extra=None, log_text=None):
    home = CloudHome(tmp_path / "home")
    raw, _prefix, _digest = generate_agent_key()
    seed = generate_host_seed()
    public_hex = public_key_hex(seed)
    log = tmp_path / "receipts.jsonl"
    offset = tmp_path / "receipt-offset.json"
    log.write_text(log_text if log_text is not None else "")
    document = {
        "url": "https://cloud.example",
        "org_id": "org-1",
        "host_id": "host-1",
        "agent_key_id": "key-1",
        "agent_key": raw,
        "host_key_id": key_id(public_hex),
        "host_public_key": public_hex,
        "plane_public_keys": {"approval": "", "policy": "", "receipt": ""},
        "spool_dir": "spool",
        "state_dir": "state",
        "receipt_log": str(log),
        "receipt_offset": str(offset),
    }
    document.update(extra or {})
    home.save(document)
    home.save_seed(seed)
    return home, log, offset


def _state(connector):
    return json.loads(connector.state_path.read_text())


def _responses(*, receipts_status=200, receipts_body=None):
    ack = receipts_body or {"status": "linkage_only", "accepted": 2,
                            "verification": "linkage_only", "head": "a" * 64}
    return [
        (receipts_status, {}, json.dumps(ack).encode()),
        (200, {}, b'{"cursor": 0, "grants": []}'),
        (200, {}, b'{"poll_after": 300}'),
    ]


def _line(receipt):
    return receipt.to_json() + "\n"


def test_complete_lines_are_spooled_uploaded_and_the_offset_advances(tmp_path):
    receipts = _receipts(2)
    log_text = _line(receipts[0]) + _line(receipts[1]) + '{"partial":'
    home, log, offset_path = _home(tmp_path, log_text=log_text)
    transport = FakeTransport(_responses())
    connector = Connector(home, transport, clock=_Clock())

    result = connector.run_once()

    assert result["ok"] is True
    assert result["receipts_spooled"] == 2
    assert result["uploaded"] == 1
    sent = [call for call in transport.calls if call[1] == "/v1/receipts"]
    assert len(sent) == 1
    # The spool holds gzip, but the connector sends the decoded JSON body;
    # the plane's gzip support is for clients that choose to compress.
    payload = json.loads(sent[0][2])
    assert payload["host_id"] == "host-1"
    assert [item["mac"] for item in payload["receipts"]] == [
        receipt.mac for receipt in receipts]
    # Only the two complete lines were acknowledged; the partial line stays.
    stored = json.loads(offset_path.read_text())
    assert stored["line"] == 3
    assert stored["offset"] == len(
        (_line(receipts[0]) + _line(receipts[1])).encode())
    state = _state(connector)
    assert state["last_receipt_ack"] == 2
    assert state["verification_level"] == "linkage_only"
    assert state["pending_receipt_batches"] == {}
    assert connector.spool.count == 0
    status = connector.status()
    assert status["receipts_line"] == 3
    assert status["receipts_pending_bytes"] == len('{"partial":')


def test_a_500_keeps_the_batch_and_the_offset_until_a_later_2xx(tmp_path):
    receipts = _receipts(1)
    home, _log, offset_path = _home(tmp_path, log_text=_line(receipts[0]))
    transport = FakeTransport(_responses(receipts_status=500))
    connector = Connector(home, transport, clock=_Clock(), max_attempts=1)

    first = connector.run_once()

    assert first["ok"] is False
    assert not offset_path.exists() or json.loads(
        offset_path.read_text())["offset"] == 0
    assert connector.spool.count == 1
    pending = _state(connector)["pending_receipt_batches"]
    assert len(pending) == 1
    assert len(_state(connector)["pending_receipt_batches"]) == 1

    # The next cycle retries the same spooled bytes; it does not frame more.
    transport.responses = _responses()
    second = connector.run_once()

    assert second["ok"] is True
    assert second["receipts_spooled"] == 0
    assert second["uploaded"] == 1
    assert connector.spool.count == 0
    assert json.loads(offset_path.read_text())["line"] == 2
    assert _state(connector)["pending_receipt_batches"] == {}


def test_review_batches_are_drained_before_one_receipt_batch(tmp_path):
    receipts = _receipts(1)
    home, _log, _offset = _home(tmp_path, log_text=_line(receipts[0]))
    transport = FakeTransport([
        (200, {}, b'{"review": {}}'),
        (200, {}, b'{"status": "linkage_only", "accepted": 1, '
                  b'"verification": "linkage_only"}'),
        (200, {}, b'{"cursor": 0, "grants": []}'),
        (200, {}, b'{"poll_after": 300}'),
    ])
    connector = Connector(home, transport, clock=_Clock())
    connector.spool.add("security", b'{"review_id":"r-1"}',
                        host="host-1", sensor="reviews")

    connector.run_once()

    paths = [call[1].split("?")[0] for call in transport.calls]
    assert paths[:2] == ["/v1/reviews", "/v1/receipts"]


def test_a_malformed_line_is_reported_and_never_spooled(tmp_path):
    good = _receipts(1)[0]
    home, _log, _offset = _home(
        tmp_path, log_text=_line(good) + "{bad json}\n")
    connector = Connector(home, FakeTransport(_responses()), clock=_Clock())

    result = connector.run_once()

    # The complete line before the bad one is uploaded; the bad line stops
    # the next batch and is reported without advancing past it.
    assert result["receipts_spooled"] == 1
    status = connector.status()
    assert status["last_receipt_error"].startswith("line 2:")
    assert status["receipts_line"] == 2


def test_receipt_config_fields_are_optional_and_validated(tmp_path):
    home, _log, _offset = _home(tmp_path)
    assert home.load()["receipt_log"]
    with pytest.raises(HomeError):
        home.save(dict(home.load(), receipt_log=5))
    with pytest.raises(HomeError):
        home.save(dict(home.load(), receipt_offset=[]))
    # A config without the C4 fields still loads; the connector tails nothing.
    document = dict(home.load())
    document.pop("receipt_log")
    document.pop("receipt_offset")
    home.save(document)
    assert Connector(home, FakeTransport()).receipt_tailer() is None


def test_reset_offset_clears_pending_batches_and_persists(tmp_path):
    receipts = _receipts(2)
    home, _log, offset_path = _home(
        tmp_path, log_text=_line(receipts[0]) + _line(receipts[1]))
    connector = Connector(home, FakeTransport(_responses()), clock=_Clock())
    connector.run_once()
    assert json.loads(offset_path.read_text())["line"] == 3

    connector.reset_receipt_offset(1)

    assert json.loads(offset_path.read_text())["line"] == 1
    assert _state(connector)["receipts_line"] == 1
    assert _state(connector)["pending_receipt_batches"] == {}
    assert connector.receipt_tailer().offset == 0
