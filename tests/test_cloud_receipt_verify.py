"""Receipt-chain verification semantics (FR-033 .. FR-037, FR-040).

Ed25519 hosts have every signature checked (``verified``); HMAC hosts can only
have ``prev`` linkage checked (``linkage_only``), and a linkage-only chain
whose newest covering checkpoint is older than 24 hours is
``receipts_unverified``. Anything that does not continue the stored head is a
``fork`` - except an exact replay of already stored macs, which is ``ok``.
"""
from __future__ import annotations

from interlock.cloud.receipts import (
    CHECKPOINT_MAX_AGE,
    BatchResult,
    receipt_public_key,
    sign_checkpoint,
    verify_batch,
    verify_checkpoint,
    verify_export,
)
from interlock.receipt import GENESIS, hmac_sha256
from interlock.receipt_ed25519 import generate_seed, public_key

from _c4_helpers import NOW, chain, ed25519_chain


def _host(keys):
    return {"public_keys": keys}


def _hmac_host():
    return _host([])


def _ed25519_host(seed):
    return _host([{"public_key": public_key(seed).hex(),
                   "kind": "receipt", "use": "receipt"}])


def test_an_ed25519_chain_is_verified_with_the_public_key_alone():
    seed = generate_seed()
    receipts = ed25519_chain(seed)

    result = verify_batch(receipts, host=_ed25519_host(seed), now=NOW)

    assert isinstance(result, BatchResult)
    assert result.status == "verified"
    assert result.head == receipts[-1].mac
    assert result.count == len(receipts)
    assert result.accepted


def test_an_edited_ed25519_receipt_is_a_fork_with_its_index():
    seed = generate_seed()
    receipts = ed25519_chain(seed)
    receipts[1].reason = "edited after signing"

    result = verify_batch(receipts, host=_ed25519_host(seed), now=NOW)

    assert result.status == "fork"
    assert result.first_bad == 1
    assert "signature" in result.reason.lower()


def test_a_reordered_chain_is_a_fork():
    key = b"k" * 32
    receipts = chain(key, count=3, signer=hmac_sha256)
    reordered = [receipts[0], receipts[2], receipts[1]]

    result = verify_batch(reordered, host=_hmac_host(),
                          previous_head=GENESIS, now=NOW)

    assert result.status == "fork"
    assert result.first_bad == 1


def test_an_hmac_chain_is_linkage_only():
    key = b"k" * 32
    receipts = chain(key, signer=hmac_sha256)

    result = verify_batch(receipts, host=_hmac_host(), now=NOW)

    assert result.status == "linkage_only"
    assert result.head == receipts[-1].mac


def test_a_stale_checkpoint_downgrades_a_linkage_only_chain():
    key = b"k" * 32
    seed = generate_seed()
    receipts = chain(key, signer=hmac_sha256)
    checkpoint = sign_checkpoint(seed, {
        "v": 1, "org_id": "org", "host_id": "host",
        "head_mac": GENESIS, "count": 0,
        "issued_at": NOW - CHECKPOINT_MAX_AGE - 1,
    })

    result = verify_batch(
        receipts, host=_hmac_host(), checkpoints=[checkpoint],
        previous_head=GENESIS, now=NOW, host_id="host", org_id="org")

    assert result.status == "linkage_only"  # no covering checkpoint
    fresh = sign_checkpoint(seed, {
        "v": 1, "org_id": "org", "host_id": "host",
        "head_mac": GENESIS, "count": 0,
        "issued_at": NOW - CHECKPOINT_MAX_AGE - 1,
    })
    # The host's checkpoint key is its identity pin even for an HMAC chain.
    result = verify_batch(
        receipts,
        host=_host([{"public_key": public_key(seed).hex(), "kind": "identity"}]),
        checkpoints=[fresh], previous_head=GENESIS,
        now=NOW, host_id="host", org_id="org")
    assert result.status == "receipts_unverified"


def test_a_fresh_covering_checkpoint_keeps_linkage_only():
    key = b"k" * 32
    seed = generate_seed()
    receipts = chain(key, signer=hmac_sha256)
    document = sign_checkpoint(seed, {
        "v": 1, "org_id": "org", "host_id": "host",
        "head_mac": GENESIS, "count": 0, "issued_at": NOW - 60,
    })

    result = verify_batch(
        receipts,
        host=_host([{"public_key": public_key(seed).hex(), "kind": "identity"}]),
        checkpoints=[document], previous_head=GENESIS, now=NOW,
        host_id="host", org_id="org")

    assert result.status == "linkage_only"


def test_an_incremental_batch_continues_the_stored_head():
    key = b"k" * 32
    first = chain(key, count=2, signer=hmac_sha256)
    second = chain(key, count=2, signer=hmac_sha256,
                   start=first[-1].mac, base_ts=NOW)

    first_result = verify_batch(first, host=_hmac_host(), now=NOW)
    second_result = verify_batch(
        second, host=_hmac_host(), previous_head=first_result.head,
        previous_count=first_result.count, now=NOW)

    assert second_result.status == "linkage_only"
    assert second_result.count == 4
    assert second_result.head == second[-1].mac


def test_an_exact_replay_is_ok_and_does_not_move_the_head():
    key = b"k" * 32
    receipts = chain(key, signer=hmac_sha256)
    head = receipts[-1].mac

    result = verify_batch(
        receipts, host=_hmac_host(), previous_head=head,
        previous_count=len(receipts), known_macs=[r.mac for r in receipts],
        now=NOW)

    assert result.status == "ok"
    assert result.head == head


def test_a_chain_that_does_not_link_is_a_fork():
    key = b"k" * 32
    receipts = chain(key, signer=hmac_sha256)
    spliced = chain(b"x" * 32, signer=hmac_sha256)

    result = verify_batch(spliced, host=_hmac_host(),
                          previous_head=receipts[-1].mac, now=NOW)

    assert result.status == "fork"
    assert result.first_bad == 0


def test_an_empty_batch_is_ok_and_keeps_the_head():
    result = verify_batch([], host=_hmac_host(), previous_head="a" * 64,
                          previous_count=9, now=NOW)
    assert result.status == "ok"
    assert result.head == "a" * 64
    assert result.count == 9


def test_checkpoint_verification_names_the_failed_check():
    seed = generate_seed()
    document = sign_checkpoint(seed, {
        "v": 1, "org_id": "org", "host_id": "host",
        "head_mac": "a" * 64, "count": 3, "issued_at": NOW,
    })
    key = public_key(seed)

    assert verify_checkpoint(document, key, org_id="org",
                             host_id="host") is None
    assert verify_checkpoint(document, key, org_id="other") == "org"
    assert verify_checkpoint(document, key, host_id="other") == "host"
    assert verify_checkpoint(dict(document, v=2), key) == "version"
    assert verify_checkpoint(dict(document, sig="00"), key) == "signature"
    assert verify_checkpoint(document, None) == "key"
    assert verify_checkpoint(document, key, now=NOW + 2,
                             max_age=1) == "stale"
    assert verify_checkpoint(document, key, now=NOW, max_age=1) is None
    assert verify_checkpoint("not a document", key) == "malformed"


def test_an_export_verifies_with_the_pinned_key():
    seed = generate_seed()
    receipts = ed25519_chain(seed)
    host = _ed25519_host(seed)

    assert verify_export(receipts, host=host) is None

    edited = list(receipts)
    edited[1].action = "rm"
    assert verify_export(edited, host=host) is not None


def test_export_can_start_at_a_retained_prev():
    key = b"k" * 32
    receipts = chain(key, signer=hmac_sha256, count=4)
    retained = receipts[2:]

    assert verify_export(retained, host=_hmac_host(),
                         start_prev=retained[0].prev) is None


def test_receipt_public_key_accepts_a_pin_list_and_a_receipt_dict():
    seed = generate_seed()
    value = public_key(seed).hex()
    assert receipt_public_key({"public_keys": [{"public_key": value}]}) \
        == public_key(seed)
    assert receipt_public_key({"public_keys": {"receipt": value}}) \
        == public_key(seed)
    assert receipt_public_key({"public_keys": []}) is None
    assert receipt_public_key({"public_keys": [{"public_key": "zz"}]}) is None
