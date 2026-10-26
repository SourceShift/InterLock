"""Receipt chains: canonical serialization, MACs and verification.

``verify_chain`` checks two independent things per receipt: the ``prev``
linkage and the tag over the receipt's own fields. ``start_prev`` lets an
incremental batch continue a stored head, which is what C4 ingest uses.
"""
from __future__ import annotations

import json

from interlock.receipt import (
    GENESIS,
    Receipt,
    compute_mac,
    hmac_sha256,
    signing_payload,
    verify_chain,
)
from interlock.receipt_ed25519 import (
    ed25519_signer,
    ed25519_verifier,
    generate_seed,
    public_key,
)

KEY = b"k" * 32


def _receipt(**overrides):
    body = {"ts": 1.0, "action": "shell", "verdict": "ALLOW",
            "reason": "policy", "policy_id": "p-1", "principal": "alice"}
    body.update(overrides)
    return Receipt(**body)


def _mac(receipt, signer=hmac_sha256, key=KEY):
    return compute_mac(receipt, signer, key)


def test_a_receipt_serializes_canonically_and_round_trips():
    receipt = _receipt()
    receipt.mac = _mac(receipt)

    line = receipt.to_json()

    assert line == json.dumps(receipt.fields(), sort_keys=True,
                              separators=(",", ":"))
    assert Receipt.from_json(line) == receipt
    assert GENESIS == "0" * 64
    assert len(receipt.mac) == 64


def test_optional_empty_fields_are_omitted_from_the_wire_form():
    fields = _receipt().fields()
    assert "observed" not in fields
    assert "call_id" not in fields
    assert "policy_epoch" not in fields
    assert "masked" not in fields
    kept = _receipt(observed=True, call_id="c-1", masked={"EMAIL": 1}).fields()
    assert kept["observed"] is True
    assert kept["call_id"] == "c-1"
    assert kept["masked"] == {"EMAIL": 1}


def test_the_mac_covers_every_field_but_mac_itself():
    receipt = _receipt()
    first = _mac(receipt)
    assert first == _mac(receipt)  # deterministic
    receipt.action = "filesystem.write"
    assert _mac(receipt) != first
    assert b"mac" not in signing_payload(receipt)


def test_verify_chain_accepts_an_intact_chain():
    receipts = []
    prev = GENESIS
    for index in range(3):
        receipt = _receipt(ts=float(index), prev=prev)
        receipt.mac = _mac(receipt)
        receipts.append(receipt)
        prev = receipt.mac

    assert verify_chain(receipts, hmac_sha256, KEY) is None
    assert verify_chain(receipts, hmac_sha256, KEY,
                        head=receipts[-1].mac) is None


def test_verify_chain_names_the_first_edited_receipt():
    receipts = []
    prev = GENESIS
    for index in range(3):
        receipt = _receipt(ts=float(index), prev=prev)
        receipt.mac = _mac(receipt)
        receipts.append(receipt)
        prev = receipt.mac
    receipts[1].reason = "edited"

    problem = verify_chain(receipts, hmac_sha256, KEY)

    assert problem.startswith("receipt 1:")
    assert "MAC mismatch" in problem


def test_verify_chain_detects_a_deleted_or_reordered_receipt():
    receipts = []
    prev = GENESIS
    for index in range(3):
        receipt = _receipt(ts=float(index), prev=prev)
        receipt.mac = _mac(receipt)
        receipts.append(receipt)
        prev = receipt.mac

    deleted = [receipts[0], receipts[2]]
    assert verify_chain(deleted, hmac_sha256, KEY).startswith("receipt 1:")
    reordered = [receipts[0], receipts[2], receipts[1]]
    assert verify_chain(reordered, hmac_sha256, KEY).startswith("receipt 1:")


def test_verify_chain_detects_a_cut_tail_with_head():
    receipts = []
    prev = GENESIS
    for index in range(2):
        receipt = _receipt(ts=float(index), prev=prev)
        receipt.mac = _mac(receipt)
        receipts.append(receipt)
        prev = receipt.mac
    recorded_head = receipts[-1].mac

    problem = verify_chain(receipts[:1], hmac_sha256, KEY,
                           head=recorded_head)

    assert problem is not None
    assert "expected head" in problem


def test_verify_chain_verifies_with_the_wrong_key_fails():
    receipt = _receipt()
    receipt.mac = _mac(receipt)
    assert verify_chain([receipt], hmac_sha256, b"x" * 32) is not None
    assert verify_chain([receipt], hmac_sha256, KEY) is None


def test_start_prev_continues_a_stored_head():
    first = _receipt(ts=0.0, prev=GENESIS)
    first.mac = _mac(first)
    second = _receipt(ts=1.0, prev=first.mac)
    second.mac = _mac(second)

    assert verify_chain([second], hmac_sha256, KEY,
                        start_prev=first.mac) is None
    assert verify_chain([second], hmac_sha256, KEY,
                        start_prev=GENESIS).startswith("receipt 0:")
    # The default remains the whole-log case.
    assert verify_chain([first, second], hmac_sha256, KEY) is None


def test_an_ed25519_chain_verifies_with_only_the_public_key():
    seed = generate_seed()
    receipts = []
    prev = GENESIS
    for index in range(2):
        receipt = _receipt(ts=float(index), prev=prev)
        receipt.mac = _mac(receipt, ed25519_signer, seed)
        receipts.append(receipt)
        prev = receipt.mac

    verifier = ed25519_verifier(public_key(seed))
    assert len(receipts[0].mac) == 128
    assert verify_chain(receipts, None, b"", verifier=verifier) is None
    receipts[0].principal = "mallory"
    assert verify_chain(receipts, None, b"", verifier=verifier).startswith(
        "receipt 0:")
