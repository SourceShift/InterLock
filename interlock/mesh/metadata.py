"""Signed repository metadata, shaped like The Update Framework.

A commons repository publishes four signed documents, each with its own keys,
version, and expiry, so that no single compromised key and no stale or
replayed view can change what a subscriber installs:

=============  ====================================================================
``root``       the keys and thresholds of every role; offline keys, long expiry.
               A new root is accepted only when signed by a threshold of the
               *old* root's keys and of its own, and its version is exactly one
               more than the trusted one.
``targets``    what is published: each pack's path, byte length and SHA-256,
               plus free-form ``custom`` facts (its status counts, channel).
``snapshot``   the current version, length and hash of ``targets``, so a
               subscriber cannot be shown files that never existed together.
``timestamp``  the current version, length and hash of ``snapshot``, with a
               short expiry. Its expiry is the network's kill switch: when the
               maintainers stop signing it, every subscriber notices within a
               day and ``interlock doctor`` says so.
=============  ====================================================================

:class:`TrustedMetadata` is the client's state machine. Every ``update_*`` call
verifies signatures against the roles the trusted root defines, checks the
type, the expiry, and that versions never go backwards, and only then replaces
the trusted copy. Anything else raises :class:`MetadataError` with a stable
``code`` (``signatures``, ``expired``, ``rollback``, ``hash``, ``length``,
``type``, ``version``, ``format``), and the previous trusted state is kept.

Attacks this is designed to stop, in the framework's own vocabulary: arbitrary
installation (every target's hash and length are signed), rollback and
fast-forward (versions are compared, and a new snapshot may not drop or
regress a targets file), indefinite freeze (expiry), mix-and-match (snapshot
pins targets), endless data (lengths are known before download), and key
compromise (thresholds, and the root rotation rule).

This is TUF-shaped, not a conforming TUF client: delegations, hash-bin
targets and succinct roles are not implemented. The metadata format keeps the
same field names so that it can become one later without changing what
subscribers verify today.
"""
from __future__ import annotations

import dataclasses
import json
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from . import ed25519
from ._util import canonical, from_iso, sha256_hex

__all__ = [
    "SPEC_VERSION", "ROLES", "DEFAULT_EXPIRY", "MAX_LENGTH", "MetadataError", "Key", "Signer",
    "envelope", "dumps", "loads", "signed_bytes", "verify_signatures", "RootInfo",
    "build_root", "build_targets", "build_snapshot", "build_timestamp", "TargetInfo",
    "TrustedMetadata", "consistent_target_name",
]

SPEC_VERSION = "1"
ROLES = ("root", "targets", "snapshot", "timestamp")

#: How long each role's metadata stays valid after signing, in seconds.
DEFAULT_EXPIRY: Dict[str, int] = {
    "root": 365 * 86400,
    "targets": 90 * 86400,
    "snapshot": 7 * 86400,
    "timestamp": 86400,
}

#: The most bytes a subscriber will read for each document. Known before the
#: download starts, so an endless or oversized response is cut off.
MAX_LENGTH: Dict[str, int] = {
    "root": 64 * 1024,
    "timestamp": 16 * 1024,
    "snapshot": 1024 * 1024,
    "targets": 4 * 1024 * 1024,
}

#: The most root rotations a client follows in one update, so a malicious
#: mirror cannot keep a client fetching forever.
MAX_ROOT_ROTATIONS = 32


class MetadataError(ValueError):
    """Metadata that must not be trusted. ``code`` names the failed check."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__("{}: {}".format(code, message))
        self.code = code


@dataclasses.dataclass(frozen=True)
class Key:
    keyid: str
    public: bytes

    @classmethod
    def from_public(cls, public: bytes) -> "Key":
        return cls(ed25519.keyid(public), public)

    def to_meta(self) -> Dict[str, Any]:
        return {"keytype": "ed25519", "scheme": "ed25519", "public": self.public.hex()}


@dataclasses.dataclass(frozen=True)
class Signer:
    """A private key and the public key metadata derives from it."""

    seed: bytes

    @property
    def public(self) -> bytes:
        return ed25519.public_key(self.seed)

    @property
    def key(self) -> Key:
        return Key.from_public(self.public)

    @property
    def keyid(self) -> str:
        return self.key.keyid


# --- envelopes -----------------------------------------------------------------


def signed_bytes(signed: Mapping[str, Any]) -> bytes:
    """The bytes a signature covers: the canonical JSON of ``signed``."""
    return canonical(signed)


def envelope(signed: Mapping[str, Any], signers: Sequence[Signer]) -> Dict[str, Any]:
    """Sign ``signed`` with every signer and wrap it in a metadata envelope."""
    payload = signed_bytes(signed)
    signatures = [{"keyid": s.keyid, "sig": ed25519.sign(s.seed, payload).hex()} for s in signers]
    signatures.sort(key=lambda s: s["keyid"])
    return {"signed": dict(signed), "signatures": signatures}


def dumps(env: Mapping[str, Any]) -> bytes:
    """Serialize an envelope. Canonical, so the bytes hash the same everywhere."""
    return canonical(env)


def loads(raw: bytes, max_length: int) -> Dict[str, Any]:
    """Parse an envelope, refusing anything oversized or not envelope-shaped."""
    if len(raw) > max_length:
        raise MetadataError("length", "{} bytes exceeds the {} byte limit".format(len(raw), max_length))
    try:
        env = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise MetadataError("format", "not JSON: {}".format(exc))
    if (not isinstance(env, dict) or not isinstance(env.get("signed"), dict)
            or not isinstance(env.get("signatures"), list)):
        raise MetadataError("format", "not a metadata envelope")
    for sig in env["signatures"]:
        if (not isinstance(sig, dict) or not isinstance(sig.get("keyid"), str)
                or not isinstance(sig.get("sig"), str)):
            raise MetadataError("format", "malformed signature entry")
    return env


def verify_signatures(env: Mapping[str, Any], keys: Mapping[str, Key],
                      keyids: Sequence[str], threshold: int) -> int:
    """Count distinct valid signatures from ``keyids`` over ``env["signed"]``.

    Raises :class:`MetadataError('signatures')` below ``threshold``. A keyid
    that signs twice counts once; a signature from a key outside the role is
    ignored, not an error, so a rotation period can carry both key sets.
    """
    payload = signed_bytes(env["signed"])
    allowed = set(keyids)
    valid = set()
    for sig in env.get("signatures", []):
        keyid = sig.get("keyid")
        if keyid not in allowed or keyid in valid:
            continue
        key = keys.get(keyid)
        if key is None:
            continue
        try:
            raw = bytes.fromhex(sig.get("sig", ""))
        except ValueError:
            continue
        if ed25519.verify(key.public, payload, raw):
            valid.add(keyid)
    if len(valid) < threshold:
        raise MetadataError("signatures", "{} of {} required signature(s) verified".format(
            len(valid), threshold))
    return len(valid)


# --- root ----------------------------------------------------------------------


@dataclasses.dataclass
class RootInfo:
    version: int
    expires: float
    keys: Dict[str, Key]
    roles: Dict[str, Any]  # role -> {"keyids": [...], "threshold": n}
    consistent_snapshot: bool

    @classmethod
    def parse(cls, signed: Mapping[str, Any]) -> "RootInfo":
        _require_type(signed, "root")
        version = _version(signed)
        expires = _expires(signed)
        raw_keys = signed.get("keys")
        if not isinstance(raw_keys, dict) or not raw_keys:
            raise MetadataError("format", "root has no keys")
        keys: Dict[str, Key] = {}
        for keyid, meta in raw_keys.items():
            if not isinstance(meta, dict) or meta.get("keytype") != "ed25519":
                raise MetadataError("format", "unsupported key type for {}".format(keyid))
            try:
                public = bytes.fromhex(meta.get("public", ""))
            except ValueError:
                raise MetadataError("format", "key {} is not hex".format(keyid))
            if len(public) != ed25519.KEY_SIZE or ed25519.keyid(public) != keyid:
                raise MetadataError("format", "key {} does not match its id".format(keyid))
            keys[keyid] = Key(keyid, public)
        raw_roles = signed.get("roles")
        if not isinstance(raw_roles, dict):
            raise MetadataError("format", "root has no roles")
        roles: Dict[str, Any] = {}
        for role in ROLES:
            spec = raw_roles.get(role)
            if not isinstance(spec, dict):
                raise MetadataError("format", "root lacks the {} role".format(role))
            keyids = spec.get("keyids")
            threshold = spec.get("threshold")
            if (not isinstance(keyids, list) or not keyids
                    or not all(isinstance(k, str) and k in keys for k in keyids)):
                raise MetadataError("format", "role {} names unknown keys".format(role))
            if not isinstance(threshold, int) or isinstance(threshold, bool) \
                    or threshold < 1 or threshold > len(set(keyids)):
                raise MetadataError("format", "role {} has an impossible threshold".format(role))
            roles[role] = {"keyids": sorted(set(keyids)), "threshold": threshold}
        # Optional roles beyond the four: today only ``log``, the key that signs
        # the transparency log's checkpoints. Validated like the others, never
        # required, so a commons without a log still verifies.
        for role in ("log",):
            spec = raw_roles.get(role)
            if spec is None:
                continue
            keyids = spec.get("keyids") if isinstance(spec, dict) else None
            threshold = spec.get("threshold") if isinstance(spec, dict) else None
            if (not isinstance(keyids, list) or not keyids
                    or not all(isinstance(k, str) and k in keys for k in keyids)
                    or not isinstance(threshold, int) or isinstance(threshold, bool)
                    or threshold < 1 or threshold > len(set(keyids))):
                raise MetadataError("format", "role {} is malformed".format(role))
            roles[role] = {"keyids": sorted(set(keyids)), "threshold": threshold}
        return cls(version, expires, keys, roles, bool(signed.get("consistent_snapshot", True)))

    def verify(self, env: Mapping[str, Any], role: str) -> int:
        spec = self.roles[role]
        return verify_signatures(env, self.keys, spec["keyids"], spec["threshold"])


def build_root(role_keys: Mapping[str, Sequence[Key]], thresholds: Mapping[str, int],
               *, version: int, expires: str,
               extra_roles: Optional[Mapping[str, Sequence[Key]]] = None) -> Dict[str, Any]:
    keys: Dict[str, Any] = {}
    roles: Dict[str, Any] = {}
    wanted = [(role, list(role_keys.get(role, ())), True) for role in ROLES]
    wanted += [(role, list(ks), False) for role, ks in (extra_roles or {}).items()]
    for role, role_list, required in wanted:
        if not role_list:
            if required:
                raise ValueError("role {} has no keys".format(role))
            continue
        for key in role_list:
            keys[key.keyid] = key.to_meta()
        threshold = int(thresholds.get(role, 1))
        if threshold < 1 or threshold > len(role_list):
            raise ValueError("role {} threshold {} is impossible with {} key(s)".format(
                role, threshold, len(role_list)))
        roles[role] = {"keyids": sorted(k.keyid for k in role_list), "threshold": threshold}
    return {"_type": "root", "spec_version": SPEC_VERSION, "version": version,
            "expires": expires, "consistent_snapshot": True, "keys": keys, "roles": roles}


def build_targets(targets: Mapping[str, Mapping[str, Any]], *, version: int,
                  expires: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for path, info in sorted(targets.items()):
        entry = {"length": int(info["length"]), "hashes": {"sha256": str(info["sha256"])}}
        if info.get("custom") is not None:
            entry["custom"] = info["custom"]
        out[path] = entry
    return {"_type": "targets", "spec_version": SPEC_VERSION, "version": version,
            "expires": expires, "targets": out}


def _meta_entry(raw: bytes, version: int) -> Dict[str, Any]:
    return {"version": version, "length": len(raw), "hashes": {"sha256": sha256_hex(raw)}}


def build_snapshot(targets_raw: bytes, targets_version: int, *, version: int,
                   expires: str) -> Dict[str, Any]:
    return {"_type": "snapshot", "spec_version": SPEC_VERSION, "version": version,
            "expires": expires, "meta": {"targets.json": _meta_entry(targets_raw, targets_version)}}


def build_timestamp(snapshot_raw: bytes, snapshot_version: int, *, version: int,
                    expires: str) -> Dict[str, Any]:
    return {"_type": "timestamp", "spec_version": SPEC_VERSION, "version": version,
            "expires": expires, "meta": {"snapshot.json": _meta_entry(snapshot_raw, snapshot_version)}}


def consistent_target_name(path: str, sha256: str) -> str:
    """The content-addressed name a target is published under:
    ``packs/<sha256>.coding-agent.json`` for ``packs/coding-agent.json``."""
    directory, _, name = path.rpartition("/")
    return "{}{}{}.{}".format(directory, "/" if directory else "", sha256, name)


# --- the client state machine ------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class TargetInfo:
    path: str
    length: int
    sha256: str
    custom: Dict[str, Any]

    @property
    def consistent_name(self) -> str:
        return consistent_target_name(self.path, self.sha256)


class TrustedMetadata:
    """A subscriber's trusted view of one repository.

    Start from a pinned root (bytes the operator obtained out of band or that
    shipped with interlock), then feed documents in the framework's order:
    ``update_root`` for each ``<N+1>.root.json`` until none is left, then
    ``update_timestamp``, ``update_snapshot``, ``update_targets``. Each step
    returns the parsed, trusted ``signed`` document. ``now`` is injectable so
    expiry can be tested.
    """

    def __init__(self, root_raw: bytes, *, now: Optional[Callable[[], float]] = None) -> None:
        import time as _time
        self._now = now or _time.time
        env = loads(root_raw, MAX_LENGTH["root"])
        root = RootInfo.parse(env["signed"])
        # A pinned root is trusted by fiat, but it must at least be internally
        # consistent: signed by a threshold of the keys it names for itself.
        root.verify(env, "root")
        self.root = root
        self.root_raw = root_raw
        self.timestamp: Optional[Dict[str, Any]] = None
        self.snapshot: Optional[Dict[str, Any]] = None
        self.targets: Optional[Dict[str, Any]] = None

    # root ---------------------------------------------------------------------

    def update_root(self, raw: bytes) -> RootInfo:
        env = loads(raw, MAX_LENGTH["root"])
        new = RootInfo.parse(env["signed"])
        if new.version != self.root.version + 1:
            raise MetadataError("version", "root version {} does not follow trusted {}".format(
                new.version, self.root.version))
        self.root.verify(env, "root")  # the old root approves the new one ...
        new.verify(env, "root")        # ... and the new one is self-consistent
        self.root = new
        self.root_raw = raw
        # Keys may have rotated out from under the other roles: drop them, so the
        # next update re-verifies against the new root.
        self.timestamp = self.snapshot = self.targets = None
        return new

    def root_expired(self) -> bool:
        return self._now() > self.root.expires

    # timestamp ------------------------------------------------------------------

    def update_timestamp(self, raw: bytes) -> Dict[str, Any]:
        env = loads(raw, MAX_LENGTH["timestamp"])
        signed = env["signed"]
        _require_type(signed, "timestamp")
        self.root.verify(env, "timestamp")
        version = _version(signed)
        meta = _meta(signed, "snapshot.json")
        if self.timestamp is not None:
            old_version = _version(self.timestamp)
            if version < old_version:
                raise MetadataError("rollback", "timestamp version {} is older than trusted {}".format(
                    version, old_version))
            old_meta = _meta(self.timestamp, "snapshot.json")
            if version == old_version and meta != old_meta:
                raise MetadataError("rollback", "timestamp version {} re-signed with different content".format(version))
            if meta["version"] < old_meta["version"]:
                raise MetadataError("rollback", "snapshot version {} is older than trusted {}".format(
                    meta["version"], old_meta["version"]))
        _check_not_expired(signed, self._now())
        self.timestamp = signed
        return signed

    # snapshot -------------------------------------------------------------------

    def update_snapshot(self, raw: bytes) -> Dict[str, Any]:
        if self.timestamp is None:
            raise MetadataError("order", "update the timestamp before the snapshot")
        expected = _meta(self.timestamp, "snapshot.json")
        _check_bytes(raw, expected, "snapshot", MAX_LENGTH["snapshot"])
        env = loads(raw, MAX_LENGTH["snapshot"])
        signed = env["signed"]
        _require_type(signed, "snapshot")
        self.root.verify(env, "snapshot")
        version = _version(signed)
        if version != expected["version"]:
            raise MetadataError("version", "snapshot is version {} but the timestamp says {}".format(
                version, expected["version"]))
        new_meta = signed.get("meta")
        if not isinstance(new_meta, dict):
            raise MetadataError("format", "snapshot has no meta")
        if self.snapshot is not None:
            for name, old in self.snapshot["meta"].items():
                fresh = new_meta.get(name)
                if not isinstance(fresh, dict):
                    raise MetadataError("rollback", "snapshot dropped {}".format(name))
                if int(fresh.get("version", 0)) < int(old.get("version", 0)):
                    raise MetadataError("rollback", "{} version {} is older than trusted {}".format(
                        name, fresh.get("version"), old.get("version")))
        _check_not_expired(signed, self._now())
        self.snapshot = signed
        return signed

    # targets --------------------------------------------------------------------

    def update_targets(self, raw: bytes) -> Dict[str, Any]:
        if self.snapshot is None:
            raise MetadataError("order", "update the snapshot before targets")
        expected = _meta(self.snapshot, "targets.json")
        _check_bytes(raw, expected, "targets", MAX_LENGTH["targets"])
        env = loads(raw, MAX_LENGTH["targets"])
        signed = env["signed"]
        _require_type(signed, "targets")
        self.root.verify(env, "targets")
        version = _version(signed)
        if version != expected["version"]:
            raise MetadataError("version", "targets is version {} but the snapshot says {}".format(
                version, expected["version"]))
        if not isinstance(signed.get("targets"), dict):
            raise MetadataError("format", "targets has no targets")
        for path, info in signed["targets"].items():
            if (not isinstance(path, str) or not isinstance(info, dict)
                    or not isinstance(info.get("length"), int)
                    or not isinstance(info.get("hashes"), dict)
                    or not isinstance(info["hashes"].get("sha256"), str)):
                raise MetadataError("format", "malformed target {!r}".format(path))
            if path.startswith("/") or ".." in path.split("/"):
                raise MetadataError("format", "target path {!r} escapes the repository".format(path))
        _check_not_expired(signed, self._now())
        self.targets = signed
        return signed

    def target(self, path: str) -> Optional[TargetInfo]:
        if self.targets is None:
            return None
        info = self.targets["targets"].get(path)
        if info is None:
            return None
        return TargetInfo(path, int(info["length"]), info["hashes"]["sha256"],
                          dict(info.get("custom") or {}))

    def all_targets(self) -> List[TargetInfo]:
        if self.targets is None:
            return []
        return [self.target(p) for p in sorted(self.targets["targets"])]  # type: ignore[misc]

    def verify_target(self, path: str, data: bytes) -> TargetInfo:
        """Check downloaded bytes against the trusted targets entry."""
        info = self.target(path)
        if info is None:
            raise MetadataError("unknown", "{} is not a published target".format(path))
        if len(data) != info.length:
            raise MetadataError("length", "{} is {} bytes, metadata says {}".format(
                path, len(data), info.length))
        if sha256_hex(data) != info.sha256:
            raise MetadataError("hash", "{} does not match its published hash".format(path))
        return info

    def expires(self, role: str) -> Optional[float]:
        doc = {"root": None, "timestamp": self.timestamp, "snapshot": self.snapshot,
               "targets": self.targets}.get(role)
        if role == "root":
            return self.root.expires
        return _expires(doc) if doc else None


# --- field checks -----------------------------------------------------------------


def _require_type(signed: Mapping[str, Any], expected: str) -> None:
    if signed.get("_type") != expected:
        raise MetadataError("type", "expected {} metadata, got {!r}".format(expected, signed.get("_type")))
    if signed.get("spec_version") != SPEC_VERSION:
        raise MetadataError("format", "unsupported spec_version {!r}".format(signed.get("spec_version")))


def _version(signed: Mapping[str, Any]) -> int:
    version = signed.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise MetadataError("format", "version must be a positive integer")
    return version


def _expires(signed: Mapping[str, Any]) -> float:
    try:
        return from_iso(signed.get("expires"))
    except ValueError:
        raise MetadataError("format", "expires is not an ISO-8601 UTC timestamp")


def _check_not_expired(signed: Mapping[str, Any], now: float) -> None:
    if now > _expires(signed):
        raise MetadataError("expired", "{} metadata expired at {}".format(
            signed.get("_type"), signed.get("expires")))


def _meta(signed: Mapping[str, Any], name: str) -> Dict[str, Any]:
    meta = signed.get("meta")
    entry = meta.get(name) if isinstance(meta, dict) else None
    if (not isinstance(entry, dict) or not isinstance(entry.get("version"), int)
            or not isinstance(entry.get("length"), int)
            or not isinstance(entry.get("hashes"), dict)
            or not isinstance(entry["hashes"].get("sha256"), str)):
        raise MetadataError("format", "{} has no usable meta for {}".format(signed.get("_type"), name))
    return entry


def _check_bytes(raw: bytes, expected: Mapping[str, Any], what: str, max_length: int) -> None:
    if len(raw) > max_length:
        raise MetadataError("length", "{} exceeds {} bytes".format(what, max_length))
    if len(raw) != expected["length"]:
        raise MetadataError("length", "{} is {} bytes, expected {}".format(what, len(raw), expected["length"]))
    if sha256_hex(raw) != expected["hashes"]["sha256"]:
        raise MetadataError("hash", "{} does not match the hash its parent signed".format(what))
