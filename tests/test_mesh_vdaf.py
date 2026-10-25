"""Prio3 and TurboSHAKE against the reference implementation's own vectors.

The JSON in ``tests/vectors/vdaf`` is copied from
``cfrg/draft-irtf-cfrg-vdaf`` at tag ``draft-irtf-cfrg-vdaf-22``. Each report is
replayed through the same operations the generator recorded: shard, both
aggregators' verify_init, the verifier message, verify_next, aggregation and
unsharding. Matching every encoded value is what proves this port is wire
compatible, not merely self-consistent.
"""

import json
from pathlib import Path

import pytest

from interlock.mesh.turboshake import TurboSHAKE128, turboshake128
from interlock.mesh.vdaf import (
    Continued,
    Field128,
    Finished,
    Prio3Sum,
    Prio3SumVec,
    Rejected,
    XofTurboShake128,
)

VECTOR_DIR = Path(__file__).parent / "vectors" / "vdaf"


def _vector(name):
    return json.loads((VECTOR_DIR / name).read_text())


def _prio3(doc):
    if "length" in doc:
        return Prio3SumVec(doc["shares"], doc["length"], doc["max_measurement"], doc["chunk_length"])
    return Prio3Sum(doc["shares"], doc["max_measurement"])


@pytest.mark.parametrize("name", ["Prio3Sum_0.json", "Prio3Sum_1.json", "Prio3Sum_2.json",
                                  "Prio3SumVec_0.json", "Prio3SumVec_1.json"])
def test_reference_vectors_replay_exactly(name):
    doc = _vector(name)
    vdaf = _prio3(doc)
    ctx = bytes.fromhex(doc["ctx"])
    verify_key = bytes.fromhex(doc["verify_key"])
    out_shares = []

    for report in doc["reports"]:
        nonce = bytes.fromhex(report["nonce"])
        public_share, input_shares = vdaf.shard(
            ctx, report["measurement"], nonce, bytes.fromhex(report["rand"]))
        assert vdaf.encode_public_share(public_share).hex() == report["public_share"]
        assert [vdaf.encode_input_share(s).hex() for s in input_shares] == report["input_shares"]

        states, verifier_shares = [], []
        for agg_id in range(vdaf.SHARES):
            state, share = vdaf.verify_init(
                verify_key, ctx, agg_id, None, nonce, public_share, input_shares[agg_id])
            states.append(state)
            verifier_shares.append(share)
        assert [vdaf.encode_verifier_share(s).hex() for s in verifier_shares] == report["verifier_shares"][0]

        message = vdaf.verifier_shares_to_message(ctx, None, verifier_shares)
        assert vdaf.encode_verifier_message(message).hex() == report["verifier_messages"][0]
        shares = [vdaf.verify_next(ctx, state, message) for state in states]
        assert [vdaf.encode_out_share(s).hex() for s in shares] == report["out_shares"]
        out_shares.append(shares)

    aggregate_shares = []
    for agg_id in range(vdaf.SHARES):
        aggregate = vdaf.agg_init(None)
        for shares in out_shares:
            aggregate = vdaf.agg_update(None, aggregate, shares[agg_id])
        aggregate_shares.append(aggregate)
    assert [vdaf.encode_agg_share(s).hex() for s in aggregate_shares] == doc["agg_shares"]
    assert vdaf.unshard(None, aggregate_shares, len(doc["reports"])) == doc["agg_result"]


def test_xof_turboshake_vector():
    doc = _vector("XofTurboShake128.json")
    seed = bytes.fromhex(doc["seed"])
    dst = bytes.fromhex(doc["dst"])
    binder = bytes.fromhex(doc["binder"])
    assert XofTurboShake128.derive_seed(seed, dst, binder).hex() == doc["derived_seed"]
    expanded = XofTurboShake128.expand_into_vec(Field128, seed, dst, binder, doc["length"])
    assert Field128.encode_vec(expanded).hex() == doc["expanded_vec_field128"]


@pytest.mark.parametrize("message,domain,expected", [
    # Cross-checked against pycryptodomex's TurboSHAKE128, itself checked
    # against RFC 9861.
    (b"", 1, "868cbd53b078205abb85815d941f7d0376bff5b8888a6a2d03483afbaf83967f"),
    (b"abc", 1, "59ccfc22a3b84742586b41f51f8a94738dd02bc74551eb0ef50fc4094eb0fc7b"),
    (b"abc", 7, "06e280de6645094e5c71141811a8fc7f55e5f80f5f32a414d621941adf59fe66"),
])
def test_turboshake128_vectors(message, domain, expected):
    assert turboshake128(message, domain, 32).hex() == expected


def test_turboshake128_streaming_matches_one_shot():
    message = bytes(range(168))
    expected = turboshake128(message, 1, 200)
    shake = TurboSHAKE128(1)
    shake.update(message)
    assert shake.read(13) + shake.read(187) == expected


@pytest.mark.parametrize("name", ["Prio3Sum_0.json", "Prio3SumVec_0.json"])
def test_ping_pong_matches_the_two_phase_path(name):
    """DAP drives Prio3 through ping-pong; the output shares must not change."""
    doc = _vector(name)
    vdaf = _prio3(doc)
    # DAP's VDAF context is the protocol version string plus the task ID.
    ctx = b"dap-20" + bytes.fromhex("11" * 32)
    verify_key = bytes.fromhex(doc["verify_key"])

    for report in doc["reports"]:
        nonce = bytes.fromhex(report["nonce"])
        public_share, input_shares = vdaf.shard(
            ctx, report["measurement"], nonce, bytes.fromhex(report["rand"]))
        encoded_public_share = vdaf.encode_public_share(public_share)

        leader_state = vdaf.ping_pong_leader_init(
            verify_key, ctx, b"", nonce, encoded_public_share,
            vdaf.encode_input_share(input_shares[0]))
        assert isinstance(leader_state, Continued)
        helper_state = vdaf.ping_pong_helper_init(
            verify_key, ctx, b"", nonce, encoded_public_share,
            vdaf.encode_input_share(input_shares[1]), leader_state.outbound)
        # Prio3 is single-round, so the helper finishes with a finalize message.
        assert helper_state.__class__.__name__ == "FinishedWithOutbound"
        final = vdaf.ping_pong_leader_continued(ctx, b"", leader_state, helper_state.outbound)
        assert isinstance(final, Finished)

        # The same inputs through the explicit two-phase API agree byte for byte.
        states, verifier_shares = [], []
        for agg_id in range(2):
            state, share = vdaf.verify_init(
                verify_key, ctx, agg_id, None, nonce, public_share, input_shares[agg_id])
            states.append(state)
            verifier_shares.append(share)
        message = vdaf.verifier_shares_to_message(ctx, None, verifier_shares)
        expected = [vdaf.verify_next(ctx, state, message) for state in states]
        assert vdaf.encode_out_share(final.out_share) == vdaf.encode_out_share(expected[0])
        assert vdaf.encode_out_share(helper_state.out_share) == vdaf.encode_out_share(expected[1])


def test_ping_pong_rejects_a_tampered_leader_message():
    doc = _vector("Prio3SumVec_0.json")
    vdaf = _prio3(doc)
    ctx = b"dap-20" + bytes(32)
    verify_key = bytes.fromhex(doc["verify_key"])
    report = doc["reports"][0]
    nonce = bytes.fromhex(report["nonce"])
    public_share, input_shares = vdaf.shard(
        ctx, report["measurement"], nonce, bytes.fromhex(report["rand"]))
    leader_state = vdaf.ping_pong_leader_init(
        verify_key, ctx, b"", nonce, vdaf.encode_public_share(public_share),
        vdaf.encode_input_share(input_shares[0]))
    tampered = leader_state.outbound[:-1] + bytes([leader_state.outbound[-1] ^ 1])
    assert isinstance(vdaf.ping_pong_helper_init(
        verify_key, ctx, b"", nonce, vdaf.encode_public_share(public_share),
        vdaf.encode_input_share(input_shares[1]), tampered), Rejected)


def test_prio3_sumvec_rejects_out_of_range_measurement():
    vdaf = Prio3SumVec(2, 3, 4, 2)
    with pytest.raises(ValueError):
        vdaf.shard(b"ctx", [1, 2, 5], b"\x00" * 16, b"\x00" * vdaf.RAND_SIZE)


def test_prio3_sumvec_rejects_wrong_length_measurement():
    vdaf = Prio3SumVec(2, 3, 4, 2)
    with pytest.raises(ValueError):
        vdaf.shard(b"ctx", [1, 2], b"\x00" * 16, b"\x00" * vdaf.RAND_SIZE)
