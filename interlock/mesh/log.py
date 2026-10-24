"""An append-only transparency log for everything a commons publishes.

Signed metadata proves a document came from the maintainers. It does not
prove the maintainers published the *same* document to everyone, or that a
compromised signing key did not publish something quietly. A transparency log
does: every metadata document and every pack is a leaf in a Merkle tree, the
maintainers sign the tree's root as a **checkpoint**, and anyone can check
that what they received is in the tree (inclusion) and that the tree only ever
grows (consistency). Certificate Transparency and Sigstore's Rekor are the
same construction for certificates and software signatures.

The tree is RFC 6962 / RFC 9162: ``SHA-256(0x00 || leaf)`` for leaves,
``SHA-256(0x01 || left || right)`` for nodes, the left subtree the largest
power of two smaller than the size. Inclusion and consistency proofs and their
verifiers follow RFC 9162 section 2.1 so that an independent monitor written
against the RFC can read this log.

What is kept simple on purpose: the whole entry list is a JSON-lines file any
mirror can serve (a few megabytes for years of publishing), so a subscriber
recomputes roots directly instead of fetching tiles; proofs are here for
monitors that hold only a prefix. A **split view** (two checkpoints of the
same size with different roots, or a checkpoint the entries cannot reproduce)
is the attack the log exists to catch, and gossip between nodes is how it is
caught: each node remembers the checkpoints it has seen and compares notes.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from . import ed25519
from ._util import atomic_write, canonical, read_bounded

__all__ = ["leaf_hash", "node_hash", "root_hash", "inclusion_proof", "verify_inclusion",
           "consistency_proof", "verify_consistency", "Entry", "MerkleLog", "sign_checkpoint",
           "verify_checkpoint", "LogError", "MAX_ENTRIES_BYTES", "split_view"]

MAX_ENTRIES_BYTES = 16 * 1024 * 1024
MAX_CHECKPOINT_BYTES = 16 * 1024
EMPTY_ROOT = hashlib.sha256(b"").digest()


class LogError(ValueError):
    """The log, a checkpoint or a proof cannot be trusted."""


# --- hashing -----------------------------------------------------------------------


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def root_hash(leaves: Sequence[bytes]) -> bytes:
    """The Merkle tree hash over already-hashed leaves."""
    n = len(leaves)
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return leaves[0]
    k = _split(n)
    return node_hash(root_hash(leaves[:k]), root_hash(leaves[k:]))


# --- proofs (RFC 9162 section 2.1) ------------------------------------------------------


def inclusion_proof(index: int, leaves: Sequence[bytes]) -> List[bytes]:
    n = len(leaves)
    if not 0 <= index < n:
        raise LogError("leaf index out of range")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_proof(index, leaves[:k]) + [root_hash(leaves[k:])]
    return inclusion_proof(index - k, leaves[k:]) + [root_hash(leaves[:k])]


def verify_inclusion(leaf: bytes, index: int, size: int, proof: Sequence[bytes], root: bytes) -> bool:
    if index >= size or size < 1:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while True:
                    fn >>= 1
                    sn >>= 1
                    if fn & 1 or fn == 0:
                        break
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def consistency_proof(first: int, leaves: Sequence[bytes]) -> List[bytes]:
    second = len(leaves)
    if not 0 < first <= second:
        raise LogError("first size must be in 1..second")
    if first == second:
        return []
    return _subproof(first, leaves, True)


def _subproof(m: int, leaves: Sequence[bytes], complete: bool) -> List[bytes]:
    n = len(leaves)
    if m == n:
        return [] if complete else [root_hash(leaves)]
    k = _split(n)
    if m <= k:
        return _subproof(m, leaves[:k], complete) + [root_hash(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [root_hash(leaves[:k])]


def verify_consistency(first: int, second: int, first_root: bytes, second_root: bytes,
                       proof: Sequence[bytes]) -> bool:
    if first > second or first < 1:
        return False
    if first == second:
        return not proof and first_root == second_root
    if not proof:
        return False
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    path = list(proof)
    if fn == 0:
        path = [first_root] + path
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while True:
                    fn >>= 1
                    sn >>= 1
                    if fn & 1 or fn == 0:
                        break
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_root and sr == second_root


# --- the log --------------------------------------------------------------------------


class Entry:
    """One published artefact: what kind, its name, its SHA-256 and version."""

    __slots__ = ("kind", "name", "sha256", "version", "ts")

    def __init__(self, kind: str, name: str, sha256: str, version: Optional[int] = None,
                 ts: Optional[float] = None) -> None:
        self.kind = kind
        self.name = name
        self.sha256 = sha256
        self.version = version
        self.ts = ts

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"kind": self.kind, "name": self.name, "sha256": self.sha256}
        if self.version is not None:
            out["version"] = self.version
        if self.ts is not None:
            out["ts"] = self.ts
        return out

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "Entry":
        if not isinstance(raw, dict) or not all(isinstance(raw.get(k), str) for k in ("kind", "name", "sha256")):
            raise LogError("malformed log entry")
        return cls(raw["kind"], raw["name"], raw["sha256"], raw.get("version"), raw.get("ts"))

    def leaf(self) -> bytes:
        return leaf_hash(canonical(self.to_dict()))


class MerkleLog:
    """Entries in a JSON-lines file, roots recomputed on demand."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.entries: List[Entry] = []
        if os.path.exists(path):
            for line in read_bounded(path, MAX_ENTRIES_BYTES).decode("utf-8").splitlines():
                if line.strip():
                    self.entries.append(Entry.from_dict(json.loads(line)))

    @classmethod
    def from_bytes(cls, raw: bytes) -> "MerkleLog":
        log = cls.__new__(cls)
        log.path = ""
        log.entries = []
        if len(raw) > MAX_ENTRIES_BYTES:
            raise LogError("log exceeds {} bytes".format(MAX_ENTRIES_BYTES))
        for line in raw.decode("utf-8").splitlines():
            if line.strip():
                try:
                    log.entries.append(Entry.from_dict(json.loads(line)))
                except ValueError as exc:
                    raise LogError("log line is not an entry: {}".format(exc))
        return log

    @property
    def size(self) -> int:
        return len(self.entries)

    def leaves(self, size: Optional[int] = None) -> List[bytes]:
        return [e.leaf() for e in self.entries[: self.size if size is None else size]]

    def root(self, size: Optional[int] = None) -> bytes:
        return root_hash(self.leaves(size))

    def append(self, entries: Iterable[Entry]) -> int:
        """Append entries not already present (by kind, name and hash). Returns how many were new."""
        known = {(e.kind, e.name, e.sha256) for e in self.entries}
        added = 0
        for entry in entries:
            key = (entry.kind, entry.name, entry.sha256)
            if key in known:
                continue
            self.entries.append(entry)
            known.add(key)
            added += 1
        if self.path:
            atomic_write(self.path, "".join(json.dumps(e.to_dict(), sort_keys=True, separators=(",", ":")) + "\n"
                                            for e in self.entries).encode("utf-8"))
        return added

    def find(self, sha256: str, kind: Optional[str] = None) -> Optional[int]:
        for index, entry in enumerate(self.entries):
            if entry.sha256 == sha256 and (kind is None or entry.kind == kind):
                return index
        return None

    def to_bytes(self) -> bytes:
        return "".join(json.dumps(e.to_dict(), sort_keys=True, separators=(",", ":")) + "\n"
                       for e in self.entries).encode("utf-8")


# --- checkpoints ------------------------------------------------------------------------


def sign_checkpoint(origin: str, size: int, root: bytes, seed: bytes, *, ts: Optional[float] = None) -> Dict[str, Any]:
    body = {"origin": origin, "size": int(size), "root": root.hex(), "ts": time.time() if ts is None else ts}
    public = ed25519.public_key(seed)
    return {"checkpoint": body, "keyid": ed25519.keyid(public), "public": public.hex(),
            "signature": ed25519.sign(seed, canonical(body)).hex()}


def verify_checkpoint(envelope: Any, allowed_keyids: Iterable[str]) -> Dict[str, Any]:
    """Return the checkpoint body if signed by one of ``allowed_keyids``."""
    if not isinstance(envelope, dict) or not isinstance(envelope.get("checkpoint"), dict):
        raise LogError("not a checkpoint")
    body = envelope["checkpoint"]
    try:
        public = bytes.fromhex(envelope.get("public", ""))
        signature = bytes.fromhex(envelope.get("signature", ""))
        root = bytes.fromhex(body.get("root", ""))
    except (ValueError, TypeError):
        raise LogError("checkpoint fields are not hex")
    if len(public) != ed25519.KEY_SIZE or len(root) != 32:
        raise LogError("checkpoint key or root has the wrong size")
    if ed25519.keyid(public) not in set(allowed_keyids):
        raise LogError("checkpoint signed by an unknown log key")
    if not isinstance(body.get("size"), int) or body["size"] < 0 or not isinstance(body.get("origin"), str):
        raise LogError("checkpoint body is malformed")
    if not ed25519.verify(public, canonical(body), signature):
        raise LogError("checkpoint signature does not verify")
    return body


def split_view(a: Mapping[str, Any], b: Mapping[str, Any], log: Optional[MerkleLog] = None) -> Optional[str]:
    """Why two checkpoints of one origin cannot both be honest, or None.

    Same size with different roots is a split view outright. With the entries in
    hand, a checkpoint whose root is not the root of the first ``size`` entries
    is one too.
    """
    if a.get("origin") != b.get("origin"):
        return None
    if a["size"] == b["size"] and a["root"] != b["root"]:
        return "two checkpoints of size {} with different roots".format(a["size"])
    if log is not None:
        for cp in (a, b):
            if cp["size"] <= log.size and log.root(cp["size"]).hex() != cp["root"]:
                return "checkpoint of size {} does not match the entries".format(cp["size"])
    return None
