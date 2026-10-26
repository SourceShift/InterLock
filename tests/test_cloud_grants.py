"""Plane-side grant signing and the shared verification matrix (C3, FR-025).

A grant is the only thing a decision produces. These tests pin the envelope's
canonical bytes, the ten-minute TTL cap, the per-host ``seq``/``prev`` chain,
and every failure code :func:`verify_grant` can return - including a valid
signature from a key the host did not pin, and a grant addressed to another
host.
"""
from __future__ import annotations

import json

import pytest

from interlock.cloud.grants import (
    CHECKS,
    GENESIS,
    GRANT_MAX_TTL,
    GrantError,
    approval_public_key,
    approval_public_key_hex,
    canonical_grant,
    generate_seed,
    sign_grant,
    verify_grant,
)
from interlock.mesh.ed25519 import sign

NOW = 2_000_000_000.0


def _body(seed, *, seq=1, prev=GENESIS, org="org-1", host="host-1",
          issued=NOW, expires=NOW + 300, **extra):
    body = {
        "v": 1, "grant_id": "g-{}".format(seq), "org_id": org,
        "host_id": host, "review_id": "r-1", "binding": "b" * 64,
        "decision": "approve",
        "approver": {"issuer": "https://idp", "subject": "u1", "email": "a@x"},
        "step_up": {"method": "webauthn", "at": issued},
        "issued_at": issued, "expires_at": expires, "seq": seq, "prev": prev,
    }
    body.update(extra)
    return sign_grant(seed, body)


def _verify(grant, seed, **kwargs):
    kwargs.setdefault("now", NOW)
    return verify_grant(grant, approval_public_key(seed), **kwargs)


def test_a_good_grant_verifies_and_the_checks_are_documented():
    seed = generate_seed()
    assert _verify(_body(seed), seed) is None
    assert CHECKS == ("version", "signature", "org", "host", "expiry",
                      "future", "seq", "prev")


def test_the_canonical_bytes_exclude_the_signature_and_ignore_key_order():
    seed = generate_seed()
    grant = _body(seed)
    reordered = {key: grant[key] for key in reversed(list(grant))}
    assert canonical_grant(grant) == canonical_grant(reordered)
    assert b'"sig"' not in canonical_grant(grant)
    original = json.loads(canonical_grant(grant))
    assert "sig" not in original


def _signed(seed, body):
    return dict(body, sig=sign(seed, canonical_grant(body)).hex())


def test_every_failure_code_in_order():
    seed = generate_seed()
    good = _body(seed)

    # ``version`` is checked before the signature, so it is signed manually.
    version_two = dict(good)
    version_two.pop("sig")
    version_two["v"] = 2
    assert _verify(_signed(seed, version_two), seed) == "version"

    tampered = dict(good)
    tampered["review_id"] = "r-2"
    assert _verify(tampered, seed) == "signature"
    assert _verify(good, generate_seed()) == "signature"
    # Org/host/expiry/future are signed as part of an honest envelope that
    # simply names another tenant or has run out.
    assert _verify(_body(seed, org="org-2"), seed, org_id="org-1") == "org"
    assert _verify(_body(seed, host="host-2"), seed, host_id="host-1") == "host"
    assert _verify(
        _body(seed, issued=NOW - 400, expires=NOW - 120), seed) == "expiry"
    assert _verify(
        _body(seed, issued=NOW + 120, expires=NOW + 300), seed) == "future"
    assert _verify(_body(seed, seq=0), seed) == "seq"
    assert _verify(good, seed, expected_seq=2) == "seq"
    assert _verify(good, seed, expected_prev="not-the-prev") == "prev"


def test_a_malformed_envelope_is_a_failed_check_not_an_exception():
    seed = generate_seed()
    public = approval_public_key(seed)
    assert verify_grant(None, public) == "version"
    assert verify_grant("not-an-object", public) == "version"
    assert verify_grant({"v": 1, "sig": "zz"}, public) == "signature"
    assert verify_grant({"v": 1, "sig": "00" * 64}, public) == "signature"

    # A signer can sign a body with a non-numeric timestamp; verify treats it
    # as a failed version check, not a crash.
    broken = {
        "v": 1, "grant_id": "g-broken", "org_id": "org-1",
        "host_id": "host-1", "review_id": "r-1", "binding": "b" * 64,
        "decision": "approve", "approver": {}, "step_up": {},
        "issued_at": "soon", "expires_at": NOW + 10, "seq": 1,
        "prev": GENESIS,
    }
    assert verify_grant(_signed(seed, broken), public, now=NOW) == "version"


def test_the_ttl_cap_is_six_hundred_seconds():
    seed = generate_seed()
    at_cap = _body(seed, issued=NOW, expires=NOW + GRANT_MAX_TTL)
    assert _verify(at_cap, seed) is None
    with pytest.raises(GrantError):
        _body(seed, issued=NOW, expires=NOW + GRANT_MAX_TTL + 1)
    with pytest.raises(GrantError):
        _body(seed, issued=NOW, expires=NOW)

    # A signature over a too-long envelope is still refused by verify even
    # though no honest signer would have produced it.
    long_body = {
        "v": 1, "grant_id": "g-long", "org_id": "org-1", "host_id": "host-1",
        "review_id": "r-1", "binding": "b" * 64, "decision": "approve",
        "approver": {"issuer": "i", "subject": "s", "email": ""},
        "step_up": {"method": "totp", "at": NOW - 1000},
        "issued_at": NOW - 1000, "expires_at": NOW + 10,
        "seq": 1, "prev": GENESIS,
    }
    unsigned = canonical_grant(long_body)
    envelope = dict(long_body, sig=sign(seed, unsigned).hex())
    assert verify_grant(envelope, approval_public_key(seed), now=NOW) == "expiry"


def test_public_keys_are_the_expected_hex_encoding():
    seed = generate_seed()
    public = approval_public_key(seed)
    assert len(public) == 32
    assert approval_public_key_hex(seed) == public.hex()
    assert len(public.hex()) == 64


def test_the_seq_prev_chain_links_each_grant_to_its_predecessor():
    seed = generate_seed()
    first = _body(seed, seq=1, prev=GENESIS)
    assert _verify(first, seed) is None
    second = _body(seed, seq=2, prev=first["sig"])
    assert _verify(second, seed) is None
    third = _body(seed, seq=3, prev=second["sig"])
    assert _verify(third, seed) is None

    # A missing middle grant breaks the next link: seq is still monotonic but
    # prev names a signature this host never held.
    orphan = _body(seed, seq=4, prev=second["sig"])
    assert _verify(orphan, seed, expected_prev=third["sig"]) == "prev"
    # Another host's grant never verifies for this host even with a good sig.
    other = _body(seed, org="org-3", host="host-9", seq=1)
    assert _verify(other, seed, org_id="org-1", host_id="host-1") == "org"


def test_redelivery_is_byte_identical_and_still_verifies():
    seed = generate_seed()
    grant = _body(seed)
    redelivered = json.loads(json.dumps(grant))
    assert redelivered == grant
    assert _verify(redelivered, seed) is None
