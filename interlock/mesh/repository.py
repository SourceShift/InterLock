"""The maintainer side of the commons: keys, and publishing a signed site.

A commons is a directory of packs under version control::

    commons/
      packs/coding-agent.json        a policy document; every rule has a status
      packs/coding-agent.tests.json  optional conformance cases for the pack

``publish`` turns it into a static site any web server, object store or peer
can serve, because every file is either signed metadata or a content-addressed
target::

    site/
      metadata/1.root.json  root.json  timestamp.json
      metadata/7.snapshot.json  snapshot.json  7.targets.json  targets.json
      targets/packs/<sha256>.coding-agent.json

Before anything is signed, each pack is compiled with the same loader a
subscriber uses; a pack with a quarantined rule is refused, so the forge's
"gates pass" promise is enforced at the door and not only in review.

Keys live outside the commons, one JSON file per key, 0600, and a
``roles.json`` with the threshold per role. ``init_keys`` creates a one-key
root for a first deployment; a real commons generates its root keys on offline
machines and raises the threshold, which this module supports but cannot do
for you. A rotated root is signed by both the old and the new root signers, so
keep the previous root key files under ``keys/retired/`` until every
subscriber has rotated.
"""
from __future__ import annotations

import glob
import json
import os
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from . import ed25519, metadata
from ._util import atomic_write, canonical, iso, load_json, sha256_hex
from .bundle import PackError, normalize_pack, pack_summary
from .metadata import Key, MetadataError, Signer, consistent_target_name

__all__ = ["init_keys", "load_signers", "publish", "verify_site", "PublishError", "PACKS_DIR"]

PACKS_DIR = "packs"
METADATA_DIR = "metadata"
TARGETS_DIR = "targets"
LOG_DIR = "log"
LOG_ROLE = "log"
ROLES_FILE = "roles.json"
KEY_FILE_MAX = 4096


class PublishError(ValueError):
    """Publishing cannot proceed; the message says what to fix."""


# --- keys ------------------------------------------------------------------------


def init_keys(keys_dir: str, *, counts: Optional[Mapping[str, int]] = None,
              thresholds: Optional[Mapping[str, int]] = None) -> Dict[str, List[Key]]:
    """Create fresh Ed25519 keys for every role under ``keys_dir``.

    ``counts`` is how many keys each role gets (default one); ``thresholds`` how
    many must sign (default one). Refuses to overwrite an existing key file.
    """
    os.makedirs(keys_dir, exist_ok=True)
    os.chmod(keys_dir, 0o700)
    out: Dict[str, List[Key]] = {}
    role_thresholds: Dict[str, int] = {}
    for role in tuple(metadata.ROLES) + (LOG_ROLE,):
        n = int((counts or {}).get(role, 1))
        t = int((thresholds or {}).get(role, 1))
        if n < 1 or t < 1 or t > n:
            raise PublishError("role {}: {} key(s) with threshold {} is impossible".format(role, n, t))
        role_thresholds[role] = t
        out[role] = []
        for index in range(1, n + 1):
            path = os.path.join(keys_dir, "{}.{}.json".format(role, index))
            if os.path.exists(path):
                raise PublishError("{} exists; refusing to overwrite a key".format(path))
            seed = ed25519.generate_seed()
            signer = Signer(seed)
            record = {"version": 1, "role": role, "keytype": "ed25519", "seed": seed.hex(),
                      "public": signer.public.hex(), "keyid": signer.keyid}
            atomic_write(path, json.dumps(record, indent=1, sort_keys=True).encode("utf-8"), mode=0o600)
            out[role].append(signer.key)
    atomic_write(os.path.join(keys_dir, ROLES_FILE),
                 json.dumps({"version": 1, "thresholds": role_thresholds}, indent=1, sort_keys=True).encode("utf-8"),
                 mode=0o600)
    return out


def load_signers(keys_dir: str) -> Tuple[Dict[str, List[Signer]], Dict[str, int]]:
    """Read every ``<role>.<n>.json`` under ``keys_dir`` and the thresholds.

    The four metadata roles are required; a ``log`` key is optional and, when
    present, turns the transparency log on for every publish.
    """
    signers: Dict[str, List[Signer]] = {role: [] for role in tuple(metadata.ROLES) + (LOG_ROLE,)}
    for path in sorted(glob.glob(os.path.join(keys_dir, "*.json"))):
        if os.path.basename(path) == ROLES_FILE:
            continue
        record = load_json(path, KEY_FILE_MAX)
        role = record.get("role")
        if role not in signers:
            continue
        try:
            seed = bytes.fromhex(record["seed"])
        except (KeyError, ValueError):
            raise PublishError("{}: not a key file".format(path))
        signer = Signer(seed)
        if record.get("public") and record["public"] != signer.public.hex():
            raise PublishError("{}: public key does not match its seed".format(path))
        signers[role].append(signer)
    thresholds: Dict[str, int] = {role: 1 for role in tuple(metadata.ROLES) + (LOG_ROLE,)}
    roles_path = os.path.join(keys_dir, ROLES_FILE)
    if os.path.exists(roles_path):
        raw = load_json(roles_path, KEY_FILE_MAX).get("thresholds", {})
        for role, value in raw.items():
            if role in thresholds:
                thresholds[role] = int(value)
    for role in metadata.ROLES:
        if not signers[role]:
            raise PublishError("no key file for the {} role in {}".format(role, keys_dir))
        if thresholds[role] > len(signers[role]):
            raise PublishError("role {}: threshold {} but only {} key(s)".format(
                role, thresholds[role], len(signers[role])))
    return signers, thresholds


def _retired_root_signers(keys_dir: str) -> List[Signer]:
    out: List[Signer] = []
    for path in sorted(glob.glob(os.path.join(keys_dir, "retired", "*.json"))):
        record = load_json(path, KEY_FILE_MAX)
        if record.get("role") == "root" and record.get("seed"):
            out.append(Signer(bytes.fromhex(record["seed"])))
    return out


# --- packs -------------------------------------------------------------------------


def load_packs(source_dir: str, *, validate: bool = True) -> Dict[str, Dict[str, Any]]:
    """Every pack in ``source_dir/packs``, normalized and (by default) compiled.

    Returns ``{"packs/<name>.json": document}``. A pack whose loader quarantines
    any rule, or that fails to parse, raises :class:`PublishError`.
    """
    packs_dir = os.path.join(source_dir, PACKS_DIR)
    paths = sorted(p for p in glob.glob(os.path.join(packs_dir, "*.json")) if not p.endswith(".tests.json"))
    if not paths:
        raise PublishError("no packs under {}".format(packs_dir))
    out: Dict[str, Dict[str, Any]] = {}
    for path in paths:
        name = os.path.basename(path)
        try:
            doc = load_json(path, metadata.MAX_LENGTH["targets"])
        except (OSError, ValueError) as exc:
            raise PublishError("{}: {}".format(path, exc))
        try:
            doc = normalize_pack(doc, name=name)
        except PackError as exc:
            raise PublishError(str(exc))
        if validate:
            from ..policy.declarative import PolicyError, load_policy
            try:
                engine = load_policy(doc, source=name)
            except PolicyError as exc:
                raise PublishError("{}: {}".format(name, exc))
            if engine.quarantined:
                raise PublishError("{}: quarantined rule(s): {}".format(name, "; ".join(engine.quarantined)))
        out["{}/{}".format(PACKS_DIR, name)] = doc
    return out


# --- publishing ------------------------------------------------------------------------


def _read_version(site_dir: str, name: str) -> int:
    """The version in an existing unsigned-read metadata file, or 0."""
    path = os.path.join(site_dir, METADATA_DIR, name)
    if not os.path.exists(path):
        return 0
    try:
        env = load_json(path, metadata.MAX_LENGTH["targets"])
        version = env["signed"]["version"]
        return int(version) if isinstance(version, int) else 0
    except (ValueError, KeyError, TypeError, OSError):
        return 0


def _root_for(site_dir: str, signers: Mapping[str, Sequence[Signer]], thresholds: Mapping[str, int],
              keys_dir: str, now: float, expiry: Mapping[str, int]) -> Tuple[bytes, int, bool]:
    """The root envelope to publish: the existing one when the keys are unchanged,
    else a new version signed by old and new root signers. Returns (bytes, version, changed)."""
    role_keys = {role: [s.key for s in signers[role]] for role in metadata.ROLES}
    extra = {LOG_ROLE: [s.key for s in signers.get(LOG_ROLE, [])]} if signers.get(LOG_ROLE) else {}
    existing_path = os.path.join(site_dir, METADATA_DIR, "root.json")
    if os.path.exists(existing_path):
        with open(existing_path, "rb") as fh:
            existing_raw = fh.read()
        existing_env = metadata.loads(existing_raw, metadata.MAX_LENGTH["root"])
        existing = metadata.RootInfo.parse(existing_env["signed"])
        wanted = dict(role_keys, **extra)
        same = set(existing.roles) == set(wanted) and all(
            existing.roles[role]["keyids"] == sorted(k.keyid for k in wanted[role])
            and existing.roles[role]["threshold"] == int(thresholds.get(role, 1))
            for role in wanted
        )
        if same and now + 30 * 86400 < existing.expires:
            return existing_raw, existing.version, False
        version = existing.version + 1
        signed = metadata.build_root(role_keys, thresholds, version=version,
                                     expires=iso(now + expiry["root"]), extra_roles=extra)
        old_signers = [s for s in list(signers["root"]) + _retired_root_signers(keys_dir)
                       if s.keyid in existing.roles["root"]["keyids"]]
        if len({s.keyid for s in old_signers}) < existing.roles["root"]["threshold"]:
            raise PublishError("rotating root needs {} signature(s) from the previous root keys; "
                               "put their key files under {}/retired/".format(
                                   existing.roles["root"]["threshold"], keys_dir))
        env = metadata.envelope(signed, list({s.keyid: s for s in old_signers + list(signers["root"])}.values()))
        return metadata.dumps(env), version, True
    signed = metadata.build_root(role_keys, thresholds, version=1, expires=iso(now + expiry["root"]),
                                 extra_roles=extra)
    env = metadata.envelope(signed, signers["root"])
    return metadata.dumps(env), 1, True


def publish(source_dir: str, site_dir: str, keys_dir: str, *, now: Optional[float] = None,
            expiry: Optional[Mapping[str, int]] = None, validate: bool = True) -> Dict[str, Any]:
    """Build and sign ``site_dir`` from the packs in ``source_dir``.

    Versions of targets, snapshot and timestamp are one more than what the site
    already holds, so a subscriber sees every publish as an update and never a
    rollback. Returns a summary the command line prints.
    """
    now = time.time() if now is None else now
    expiry_by_role = dict(metadata.DEFAULT_EXPIRY)
    if expiry:
        expiry_by_role.update({k: int(v) for k, v in expiry.items()})
    signers, thresholds = load_signers(keys_dir)
    packs = load_packs(source_dir, validate=validate)

    targets: Dict[str, Dict[str, Any]] = {}
    blobs: Dict[str, bytes] = {}
    for path, doc in packs.items():
        raw = canonical(doc)
        digest = sha256_hex(raw)
        targets[path] = {"length": len(raw), "sha256": digest, "custom": pack_summary(doc)}
        blobs[consistent_target_name(path, digest)] = raw

    root_raw, root_version, root_changed = _root_for(site_dir, signers, thresholds, keys_dir,
                                                     now, expiry_by_role)
    targets_version = _read_version(site_dir, "targets.json") + 1
    snapshot_version = _read_version(site_dir, "snapshot.json") + 1
    timestamp_version = _read_version(site_dir, "timestamp.json") + 1

    targets_signed = metadata.build_targets(targets, version=targets_version,
                                            expires=iso(now + expiry_by_role["targets"]))
    targets_raw = metadata.dumps(metadata.envelope(targets_signed, signers["targets"]))
    snapshot_signed = metadata.build_snapshot(targets_raw, targets_version, version=snapshot_version,
                                              expires=iso(now + expiry_by_role["snapshot"]))
    snapshot_raw = metadata.dumps(metadata.envelope(snapshot_signed, signers["snapshot"]))
    timestamp_signed = metadata.build_timestamp(snapshot_raw, snapshot_version, version=timestamp_version,
                                                expires=iso(now + expiry_by_role["timestamp"]))
    timestamp_raw = metadata.dumps(metadata.envelope(timestamp_signed, signers["timestamp"]))

    meta_dir = os.path.join(site_dir, METADATA_DIR)
    for name, blob in blobs.items():
        atomic_write(os.path.join(site_dir, TARGETS_DIR, name), blob)
    atomic_write(os.path.join(meta_dir, "{}.root.json".format(root_version)), root_raw)
    atomic_write(os.path.join(meta_dir, "root.json"), root_raw)
    atomic_write(os.path.join(meta_dir, "{}.targets.json".format(targets_version)), targets_raw)
    atomic_write(os.path.join(meta_dir, "targets.json"), targets_raw)
    atomic_write(os.path.join(meta_dir, "{}.snapshot.json".format(snapshot_version)), snapshot_raw)
    atomic_write(os.path.join(meta_dir, "snapshot.json"), snapshot_raw)
    atomic_write(os.path.join(meta_dir, "timestamp.json"), timestamp_raw)

    log_summary = None
    if signers.get(LOG_ROLE):
        from .log import Entry, MerkleLog, sign_checkpoint

        log = MerkleLog(os.path.join(site_dir, LOG_DIR, "entries.jsonl"))
        entries = [Entry("root", "{}.root.json".format(root_version), sha256_hex(root_raw), root_version, now),
                   Entry("targets", "{}.targets.json".format(targets_version), sha256_hex(targets_raw), targets_version, now),
                   Entry("snapshot", "{}.snapshot.json".format(snapshot_version), sha256_hex(snapshot_raw), snapshot_version, now),
                   Entry("timestamp", "timestamp.json", sha256_hex(timestamp_raw), timestamp_version, now)]
        entries += [Entry("target", name, sha256_hex(blob), None, now) for name, blob in sorted(blobs.items())]
        added = log.append(entries)
        # The origin is the identity of the commons, not of its current keys: the
        # first root ever published names it, so a root rotation never looks
        # like a different log.
        first_root_path = os.path.join(meta_dir, "1.root.json")
        with open(first_root_path, "rb") as fh:
            origin = _origin(fh.read())
        checkpoint = sign_checkpoint(origin, log.size, log.root(), signers[LOG_ROLE][0].seed, ts=now)
        atomic_write(os.path.join(site_dir, LOG_DIR, "checkpoint.json"),
                     json.dumps(checkpoint, sort_keys=True).encode("utf-8"))
        log_summary = {"size": log.size, "added": added, "root": log.root().hex(), "origin": origin}
    return {
        "site": os.path.abspath(site_dir),
        "root_version": root_version,
        "root_changed": root_changed,
        "log": log_summary,
        "targets_version": targets_version,
        "snapshot_version": snapshot_version,
        "timestamp_version": timestamp_version,
        "packs": {path: {"sha256": info["sha256"], "length": info["length"], **info["custom"]}
                  for path, info in sorted(targets.items())},
        "expires": {role: iso(now + seconds) for role, seconds in expiry_by_role.items()},
    }


def verify_site(site_dir: str, *, root_path: Optional[str] = None,
                now: Optional[float] = None) -> Dict[str, Any]:
    """Walk a published site the way a subscriber would, offline.

    Starts from ``root_path`` (default: the site's own ``1.root.json``), follows
    root rotations, then timestamp, snapshot, targets and every target blob.
    Raises :class:`MetadataError` at the first thing a subscriber would refuse.
    """
    from .subscriber import Fetcher

    fetch = Fetcher(["file://" + os.path.abspath(site_dir)])
    root_raw = fetch.get("metadata/1.root.json", metadata.MAX_LENGTH["root"]) if root_path is None \
        else open(root_path, "rb").read()
    trusted = metadata.TrustedMetadata(root_raw, now=(lambda: now) if now is not None else None)
    rotations = 0
    while rotations < metadata.MAX_ROOT_ROTATIONS:
        try:
            raw = fetch.get("metadata/{}.root.json".format(trusted.root.version + 1),
                            metadata.MAX_LENGTH["root"])
        except OSError:
            break
        trusted.update_root(raw)
        rotations += 1
    if trusted.root_expired():
        raise MetadataError("expired", "root expired at {}".format(iso(trusted.root.expires)))
    ts_raw = fetch.get("metadata/timestamp.json", metadata.MAX_LENGTH["timestamp"])
    ts = trusted.update_timestamp(ts_raw)
    snap_meta = ts["meta"]["snapshot.json"]
    snap_raw = fetch.get("metadata/{}.snapshot.json".format(snap_meta["version"]), snap_meta["length"])
    snap = trusted.update_snapshot(snap_raw)
    tgt_meta = snap["meta"]["targets.json"]
    tgt_raw = fetch.get("metadata/{}.targets.json".format(tgt_meta["version"]), tgt_meta["length"])
    trusted.update_targets(tgt_raw)
    verified = []
    hashes = [sha256_hex(ts_raw), sha256_hex(snap_raw), sha256_hex(tgt_raw)]
    for info in trusted.all_targets():
        data = fetch.get("{}/{}".format(TARGETS_DIR, info.consistent_name), info.length)
        trusted.verify_target(info.path, data)
        verified.append(info.path)
        hashes.append(info.sha256)
    log_summary = None
    if LOG_ROLE in trusted.root.roles:
        log_summary = verify_log(trusted, fetch, hashes)
    return {"root_version": trusted.root.version, "timestamp_version": ts["version"],
            "snapshot_version": snap["version"], "targets_version": tgt_meta["version"],
            "targets": verified, "timestamp_expires": ts["expires"], "log": log_summary}


def _origin(root_raw: bytes) -> str:
    """A commons' stable identity for its log: the id of its first root key."""
    env = metadata.loads(root_raw, metadata.MAX_LENGTH["root"])
    return "il-commons-" + sorted(env["signed"]["roles"]["root"]["keyids"])[0][:16]


def verify_log(trusted: metadata.TrustedMetadata, fetch: Any, document_hashes: Sequence[str],
               previous: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Fetch and check a commons' log against the documents just verified.

    The checkpoint must be signed by the root's ``log`` role, its root must be
    the root of the entries, it may not be smaller than ``previous`` and the
    previous root must be the root of its prefix (no rewriting), and every
    document hash must appear in the logged prefix (no unlogged publishing).
    Raises :class:`MetadataError('log')` otherwise.
    """
    from .log import LogError, MerkleLog, verify_checkpoint

    role = trusted.root.roles[LOG_ROLE]
    try:
        cp_raw = fetch.get("{}/checkpoint.json".format(LOG_DIR), 16 * 1024)
        entries_raw = fetch.get("{}/entries.jsonl".format(LOG_DIR), 16 * 1024 * 1024)
    except OSError as exc:
        raise MetadataError("log", "the commons advertises a log but it cannot be fetched: {}".format(exc))
    try:
        checkpoint = verify_checkpoint(json.loads(cp_raw.decode("utf-8")), role["keyids"])
        log = MerkleLog.from_bytes(entries_raw)
    except (LogError, ValueError) as exc:
        raise MetadataError("log", str(exc))
    if log.size < checkpoint["size"]:
        raise MetadataError("log", "checkpoint claims {} entries, only {} served".format(checkpoint["size"], log.size))
    if log.root(checkpoint["size"]).hex() != checkpoint["root"]:
        raise MetadataError("log", "checkpoint root does not match the entries (split view or tampering)")
    if previous is not None:
        if previous["size"] > checkpoint["size"]:
            raise MetadataError("log", "the log shrank from {} to {} entries".format(previous["size"], checkpoint["size"]))
        if previous.get("origin") != checkpoint["origin"]:
            raise MetadataError("log", "the log's origin changed")
        if log.root(previous["size"]).hex() != previous["root"]:
            raise MetadataError("log", "the log was rewritten: the previous checkpoint is not a prefix (split view)")
    for digest in document_hashes:
        index = log.find(digest)
        if index is None or index >= checkpoint["size"]:
            raise MetadataError("log", "a published document is not in the log: {}".format(digest[:16]))
    return {"size": checkpoint["size"], "root": checkpoint["root"], "origin": checkpoint["origin"],
            "checkpoint_raw": cp_raw, "entries_raw": entries_raw, "checkpoint": checkpoint}
