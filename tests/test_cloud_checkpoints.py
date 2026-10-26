"""Checkpoint ingest and verification-level display (FR-034, FR-035).

An HMAC host signs a checkpoint with its pinned identity key. The plane checks
the signature over the canonical six fields, requires the checkpoint to cover
the stored head and count, and refuses one that does not move time forward.
"""
from __future__ import annotations

import gzip
import json

from interlock.receipt_ed25519 import generate_seed, public_key

from _c4_helpers import (
    NOW,
    add_agent_key,
    call,
    chain,
    checkpoint_doc,
    ingest,
    make_app,
    post_json,
)


def _setup(*, scopes=("ingest:receipts",)):
    env = make_app(role="owner")
    seed = generate_seed()
    env.host.public_keys[:] = [{
        "public_key": public_key(seed).hex(), "kind": "identity",
    }]
    headers = add_agent_key(env, scopes=scopes)
    return env, seed, headers


def _ingest_chain(env, headers):
    receipts = chain(b"h" * 32, count=3)
    status, _headers, body, _raw = ingest(env, headers, receipts)
    assert status == 200, body
    assert body["verification"] == "linkage_only"
    return receipts


def test_a_signed_checkpoint_at_the_head_is_stored_and_shown():
    env, seed, headers = _setup()
    receipts = _ingest_chain(env, headers)
    document = checkpoint_doc(
        seed, org_id=env.org.id, host_id=env.host.id,
        head_mac=receipts[-1].mac, count=len(receipts))

    status, _headers, body, _raw = post_json(
        env, "/v1/checkpoints", headers, document)

    assert status == 200, body
    assert body["checkpoint"]["head_mac"] == receipts[-1].mac
    assert body["verification"] == "linkage_only"
    assert len(env.store.list_checkpoints(env.org.id, env.host.id)) == 1
    detail = call(env.app, "/v1/hosts/" + env.host.id, headers=env.headers)
    assert detail[0] == 200
    assert detail[2]["host"]["verification"] == "linkage_only"
    assert detail[2]["host"]["last_checkpoint_at"] is not None
    assert detail[2]["host"]["receipts_count"] == 3


def test_a_checkpoint_signed_with_the_wrong_key_is_refused():
    env, _seed, headers = _setup()
    receipts = _ingest_chain(env, headers)
    document = checkpoint_doc(
        generate_seed(), org_id=env.org.id, host_id=env.host.id,
        head_mac=receipts[-1].mac, count=len(receipts))

    status, _headers, body, _raw = post_json(
        env, "/v1/checkpoints", headers, document)

    assert status == 422
    assert body["error"]["code"] == "invalid_checkpoint"
    assert env.store.list_checkpoints(env.org.id, env.host.id) == []


def test_a_checkpoint_that_does_not_cover_the_stored_head_is_refused():
    env, seed, headers = _setup()
    receipts = _ingest_chain(env, headers)
    document = checkpoint_doc(
        seed, org_id=env.org.id, host_id=env.host.id,
        head_mac="a" * 64, count=len(receipts))

    status, _headers, body, _raw = post_json(
        env, "/v1/checkpoints", headers, document)

    assert status == 409
    assert body["error"]["code"] == "checkpoint_not_at_head"


def test_a_checkpoint_with_the_wrong_count_is_refused():
    env, seed, headers = _setup()
    receipts = _ingest_chain(env, headers)
    document = checkpoint_doc(
        seed, org_id=env.org.id, host_id=env.host.id,
        head_mac=receipts[-1].mac, count=2)

    status, _headers, body, _raw = post_json(
        env, "/v1/checkpoints", headers, document)

    assert status == 409
    assert body["error"]["code"] == "checkpoint_count_mismatch"


def test_a_second_checkpoint_must_move_time_forward():
    env, seed, headers = _setup()
    receipts = _ingest_chain(env, headers)
    document = checkpoint_doc(
        seed, org_id=env.org.id, host_id=env.host.id,
        head_mac=receipts[-1].mac, count=len(receipts), issued_at=NOW)
    assert post_json(env, "/v1/checkpoints", headers, document)[0] == 200

    status, _headers, body, _raw = post_json(
        env, "/v1/checkpoints", headers, document)
    assert status == 409
    assert body["error"]["code"] == "checkpoint_not_newer"

    newer = checkpoint_doc(
        seed, org_id=env.org.id, host_id=env.host.id,
        head_mac=receipts[-1].mac, count=len(receipts), issued_at=NOW + 60)
    assert post_json(env, "/v1/checkpoints", headers, newer)[0] == 200


def test_a_checkpoint_is_accepted_gzipped():
    env, seed, headers = _setup()
    receipts = _ingest_chain(env, headers)
    document = checkpoint_doc(
        seed, org_id=env.org.id, host_id=env.host.id,
        head_mac=receipts[-1].mac, count=len(receipts))
    gzipped = gzip.compress(json.dumps(document).encode())
    gzip_headers = dict(headers, **{
        "content-encoding": "gzip",
        "content-length": str(len(gzipped)),
    })

    status, _headers, body, _raw = call(
        env.app, "/v1/checkpoints", method="POST", headers=gzip_headers,
        body=gzipped)

    assert status == 200, body
    assert body["checkpoint"]["count"] == 3


def test_an_agent_without_the_ingest_scope_cannot_post_a_checkpoint():
    env, seed, headers = _setup(scopes=("poll:grants",))
    document = checkpoint_doc(
        seed, org_id=env.org.id, host_id=env.host.id,
        head_mac="a" * 64, count=0)

    status, _headers, body, _raw = post_json(
        env, "/v1/checkpoints", headers, document)

    assert status == 403
    assert body["error"]["code"] == "forbidden"


def test_an_empty_chain_has_no_head_to_attest():
    env, seed, headers = _setup()
    document = checkpoint_doc(
        seed, org_id=env.org.id, host_id=env.host.id,
        head_mac="a" * 64, count=0)

    status, _headers, body, _raw = post_json(
        env, "/v1/checkpoints", headers, document)

    assert status == 409
    assert body["error"]["code"] == "checkpoint_not_at_head"
