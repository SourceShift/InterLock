"""The Merkle log: RFC 9162 hashing and proofs checked against brute-force roots
for every small tree, signed checkpoints, and split-view detection."""
import hashlib

import pytest

from interlock.mesh import ed25519
from interlock.mesh.log import (
    EMPTY_ROOT, Entry, LogError, MerkleLog, consistency_proof, inclusion_proof, leaf_hash, root_hash,
    sign_checkpoint, split_view, verify_checkpoint, verify_consistency, verify_inclusion,
)


def leaves(n):
    return [leaf_hash("entry-{}".format(i).encode()) for i in range(n)]


def test_rfc_6962_hash_shapes():
    assert root_hash([]) == EMPTY_ROOT == hashlib.sha256(b"").digest()
    one = leaf_hash(b"a")
    assert root_hash([one]) == one
    assert root_hash(leaves(2)) == hashlib.sha256(b"\x01" + leaves(2)[0] + leaves(2)[1]).digest()
    # The left subtree is the largest power of two below the size.
    ls = leaves(5)
    assert root_hash(ls) == hashlib.sha256(b"\x01" + root_hash(ls[:4]) + ls[4]).digest()


@pytest.mark.parametrize("n", range(1, 18))
def test_inclusion_proofs_verify_for_every_leaf(n):
    ls = leaves(n)
    root = root_hash(ls)
    for i in range(n):
        proof = inclusion_proof(i, ls)
        assert verify_inclusion(ls[i], i, n, proof, root)
        assert not verify_inclusion(ls[i], i, n, proof, leaf_hash(b"wrong"))
        if n > 1:
            assert not verify_inclusion(ls[(i + 1) % n], i, n, proof, root)
    with pytest.raises(LogError):
        inclusion_proof(n, ls)


@pytest.mark.parametrize("n", range(1, 18))
def test_consistency_proofs_verify_for_every_prefix(n):
    ls = leaves(n)
    second = root_hash(ls)
    for m in range(1, n + 1):
        proof = consistency_proof(m, ls)
        assert verify_consistency(m, n, root_hash(ls[:m]), second, proof), (m, n)
        if m < n:
            assert not verify_consistency(m, n, leaf_hash(b"x"), second, proof)
            assert not verify_consistency(m, n, root_hash(ls[:m]), leaf_hash(b"y"), proof)
    assert not verify_consistency(3, 2, b"", b"", [])
    assert verify_consistency(n, n, second, second, [])


def test_log_append_find_and_persist(tmp_path):
    path = tmp_path / "entries.jsonl"
    log = MerkleLog(str(path))
    added = log.append([Entry("timestamp", "timestamp.json", "a" * 64, 1, 1.0),
                        Entry("target", "packs/x.json", "b" * 64),
                        Entry("timestamp", "timestamp.json", "a" * 64, 1, 1.0)])  # duplicate ignored
    assert added == 2 and log.size == 2
    assert log.find("b" * 64) == 1 and log.find("b" * 64, kind="timestamp") is None
    again = MerkleLog(str(path))
    assert again.root() == log.root() and again.size == 2
    parsed = MerkleLog.from_bytes(log.to_bytes())
    assert parsed.root(1) == root_hash([log.entries[0].leaf()])
    with pytest.raises(LogError):
        MerkleLog.from_bytes(b'{"kind": 1}\n')


def test_checkpoints_and_split_view():
    seed = ed25519.generate_seed()
    keyid = ed25519.keyid(ed25519.public_key(seed))
    log = MerkleLog.from_bytes(b"")
    log.append([Entry("target", "p", "c" * 64), Entry("target", "q", "d" * 64)])
    cp = sign_checkpoint("commons.example", log.size, log.root(), seed, ts=5.0)
    body = verify_checkpoint(cp, [keyid])
    assert body["size"] == 2 and body["root"] == log.root().hex()
    with pytest.raises(LogError):
        verify_checkpoint(cp, ["someone-else"])
    forged = dict(cp, checkpoint=dict(cp["checkpoint"], size=3))
    with pytest.raises(LogError):
        verify_checkpoint(forged, [keyid])
    with pytest.raises(LogError):
        verify_checkpoint({"checkpoint": "x"}, [keyid])
    # Honest growth: no split view. Same size, different root: split view.
    older = sign_checkpoint("commons.example", 1, log.root(1), seed)["checkpoint"]
    assert split_view(older, body, log) is None
    other = dict(body, root=leaf_hash(b"evil").hex())
    assert "different roots" in split_view(body, other)
    assert "does not match the entries" in split_view(dict(older, root="0" * 64), body, log)
    assert split_view(body, dict(body, origin="elsewhere")) is None
