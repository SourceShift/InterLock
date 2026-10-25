"""Audit-trail gaps closed: restarts, cut tails, monitor mode, public-key checks.

- A FileSink reopened after a restart started a new chain at GENESIS, so one
  log could not span restarts without verify() reporting a break.
- Receipts deleted from the end left a valid, shorter chain.
- Monitor mode wrote receipts saying BLOCK for calls that went through.
- verify() recomputed every tag with the signing key, so no third party
  holding only a public key could check a chain.
"""
import hashlib
import hmac
import json

import pytest

import interlock
from interlock import PolicyEngine, deny_tool, enforce_tool_call, guard, monitor
from interlock.receipt import GENESIS, Receipt, compute_mac, hmac_sha256, set_sink
from interlock.sink import FileSink, InMemorySink, verify_file

KEY = b"k" * 32


def setup_function(_):
    interlock.install(engine=PolicyEngine())


def teardown_function(_):
    set_sink(None)


def _write(sink, n, action="read_rows"):
    interlock.install(rules=[], sink=sink)
    for _ in range(n):
        enforce_tool_call(action, {"table": "orders"})


def test_a_reopened_file_continues_the_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    first = FileSink(path, key=KEY)
    _write(first, 2)
    second = FileSink(path, key=KEY)              # a restart
    assert second.head == first.head
    _write(second, 1)
    assert verify_file(str(path), key=KEY) is None
    lines = path.read_text().splitlines()
    assert json.loads(lines[2])["prev"] == json.loads(lines[1])["mac"]


def test_a_file_ending_in_garbage_is_refused(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(FileSink(path, key=KEY), 1)
    with open(path, "a") as fh:
        fh.write('{"ts": 1, "action": "half a recei')
    with pytest.raises(ValueError, match="not a readable receipt"):
        FileSink(path, key=KEY)


def test_a_cut_tail_is_caught_with_a_recorded_head(tmp_path):
    path = tmp_path / "audit.jsonl"
    sink = FileSink(path, key=KEY)
    _write(sink, 3)
    head = sink.head
    assert sink.verify(head=head) is None

    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:2]) + "\n")     # delete the last receipt
    assert sink.verify() is None                     # the linkage alone can't tell
    problem = verify_file(str(path), key=KEY, head=head)
    assert problem is not None and "cut from the end" in problem


def test_monitor_mode_receipts_say_observed():
    sink = InMemorySink(key=KEY)
    interlock.install(rules=[deny_tool("run_shell")], sink=sink)

    @monitor()
    def run_shell(cmd):
        return "ran"

    assert run_shell(cmd="ls") == "ran"
    enforce_tool_call("run_shell", {"cmd": "ls"}, enforcement="monitor")
    call_receipts = [r for r in sink.receipts if r.phase == "call"]
    assert [r.verdict for r in call_receipts] == ["BLOCK", "BLOCK"]
    assert all(r.observed for r in call_receipts)
    assert sink.verify() is None


def test_enforced_receipts_keep_the_old_serialized_shape():
    sink = InMemorySink(key=KEY)
    interlock.install(rules=[], sink=sink)

    @guard()
    def read_rows(table):
        return []

    read_rows(table="orders")
    assert "observed" not in json.loads(sink.receipts[0].to_json())


def test_a_receipt_written_before_the_observed_field_still_verifies():
    old = {"ts": 1.0, "action": "a", "verdict": "ALLOW", "reason": "", "policy_id": None,
           "attributed_to": None, "principal": None, "span_id": None, "phase": "call",
           "args_digest": "d", "prev": GENESIS, "mac": ""}
    receipt = Receipt(**old)
    old["mac"] = compute_mac(receipt, hmac_sha256, KEY)
    # the tag an older interlock computed: canonical JSON of every field but mac
    legacy_body = {k: v for k, v in old.items() if k != "mac"}
    legacy = hmac.new(KEY, json.dumps(legacy_body, sort_keys=True, separators=(",", ":")).encode(),
                      hashlib.sha256).hexdigest()
    assert old["mac"] == legacy


def test_a_verifier_checks_the_chain_without_the_signing_key(tmp_path):
    # Stand-in for a public-key scheme: the writer signs with a private key,
    # the auditor only gets a function that says whether a tag is valid.
    private = b"p" * 32

    def sign(key, message):
        return hmac.new(key, message, hashlib.sha256).digest()

    def public_verify(message, tag):
        return hmac.compare_digest(tag, sign(private, message))

    path = tmp_path / "audit.jsonl"
    _write(FileSink(path, signer=sign, key=private), 2)
    assert verify_file(str(path), verifier=public_verify) is None
    assert verify_file(str(path), verifier=lambda m, t: False) == (
        "receipt 0: signature rejected by the verifier (edited, or signed with a different key)"
    )


def test_ed25519_signs_a_chain_a_third_party_verifies_with_the_public_key(tmp_path):
    from interlock.receipt_ed25519 import (
        ed25519_signer,
        ed25519_verifier,
        generate_seed,
        keyid,
        public_key,
    )

    seed = generate_seed()
    other = generate_seed()
    path = tmp_path / "audit.jsonl"
    sink = FileSink(path, signer=ed25519_signer, key=seed)
    _write(sink, 2)

    verifier = ed25519_verifier(public_key(seed))
    assert sink.verify(verifier=verifier) is None
    assert verify_file(str(path), verifier=verifier) is None
    assert len(keyid(public_key(seed))) == 64

    rejected = verify_file(str(path), verifier=ed25519_verifier(public_key(other)))
    assert rejected is not None and "signature rejected" in rejected

    lines = path.read_text().splitlines()
    edited = json.loads(lines[0])
    edited["verdict"] = "BLOCK"
    path.write_text(json.dumps(edited) + "\n" + lines[1] + "\n")
    assert verify_file(str(path), verifier=verifier) is not None


def test_verify_file_needs_a_key_or_a_verifier(tmp_path):
    with pytest.raises(ValueError):
        verify_file(str(tmp_path / "audit.jsonl"))


def test_two_writers_open_at_once_still_show_up_as_a_break(tmp_path):
    # Resuming covers restarts, not concurrent writers: both sinks read the same
    # head when they open, so their receipts fork the chain and verify says so.
    path = tmp_path / "audit.jsonl"
    _write(FileSink(path, key=KEY), 1)
    a = FileSink(path, key=KEY)
    b = FileSink(path, key=KEY)
    _write(a, 1)
    _write(b, 1)
    problem = verify_file(str(path), key=KEY)
    assert problem is not None and "chain break" in problem


def test_a_log_with_longer_signatures_can_be_reopened(tmp_path):
    # Ed25519 signatures are 64 bytes (128 hex chars), not HMAC-SHA256's 32.
    def long_sign(key, message):
        return hashlib.sha512(key + message).digest()

    path = tmp_path / "audit.jsonl"
    first = FileSink(path, signer=long_sign, key=KEY)
    _write(first, 1)
    second = FileSink(path, signer=long_sign, key=KEY)
    assert len(second.head) == 128 and second.head == first.head
    _write(second, 1)
    assert verify_file(str(path), key=KEY, signer=long_sign) is None
