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
root for a first deployment. ``publish`` needs only the online keys (targets,
snapshot, timestamp, and log when there is one): while the online keys match
the current root and it has not expired, it re-publishes that root without
any root key present, so the root keys can live on offline machines. A new
root is signed in a ceremony instead, each keyholder on their own machine:

    draft_root      the unsigned next root, from the online keys and the root
                    public keys listed in ``keys/root-keys.json``
    sign_root       one detached signature, ``<draft>.sig.<keyid>``, from a key
                    file or an external signing program (a hardware token)
    assemble_root   check the previous root's threshold and the new root's own,
                    the rule every subscriber applies, then write it into the site

A commons that does keep its root keys beside the online ones still rotates
the old way: the new root is signed by both the old and the new root signers,
the previous root key files kept under ``keys/retired/``.
"""
from __future__ import annotations

import glob
import json
import os
import shlex
import subprocess
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from . import ed25519, metadata
from ._util import atomic_write, canonical, iso, load_json, read_bounded, sha256_hex
from .bundle import PackError, normalize_pack, pack_summary
from .metadata import Key, MetadataError, Signer, consistent_target_name

__all__ = ["init_keys", "load_signers", "load_root_manifest", "publish", "verify_site", "draft_root",
           "sign_root", "assemble_root", "PublishError", "PACKS_DIR", "ROOT_MANIFEST"]

PACKS_DIR = "packs"
METADATA_DIR = "metadata"
TARGETS_DIR = "targets"
LOG_DIR = "log"
LOG_ROLE = "log"
ROLES_FILE = "roles.json"
#: The root's public keys and who holds them; read by ``draft_root`` only.
ROOT_MANIFEST = "root-keys.json"
KEY_FILE_MAX = 4096
#: The roles ``publish`` signs with on every run; the root is not one of them.
ONLINE_ROLES = ("targets", "snapshot", "timestamp")
#: How long ``sign_root`` waits for an external signer (a token may want a touch).
EXTERNAL_SIGNER_TIMEOUT = 120.0


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

    The online roles (targets, snapshot, timestamp) are required. A ``log``
    key is optional and, when present, turns the transparency log on for every
    publish. Root keys are optional too: they belong offline, and ``publish``
    needs them only to sign a new root, so ``signers["root"]`` may be empty.
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
    for role in ONLINE_ROLES + ((LOG_ROLE,) if signers[LOG_ROLE] else ()):
        if not signers[role]:
            raise PublishError("no key file for the {} role in {}".format(role, keys_dir))
        if thresholds[role] > len(signers[role]):
            raise PublishError("role {}: threshold {} but only {} key(s)".format(
                role, thresholds[role], len(signers[role])))
    return signers, thresholds


def load_root_manifest(keys_dir: str) -> Tuple[List[Key], Dict[str, Dict[str, str]]]:
    """The root public keys a ceremony drafts, from ``keys_dir/root-keys.json``::

        {"version": 1, "keys": [{"public": "<hex>", "owner": "...", "term_start": "2026-11-01"}]}

    ``owner`` and ``term_start`` are optional strings (a ``keyid``, when given,
    must match the key). Returns the keys and their owners by key id.
    """
    path = os.path.join(keys_dir, ROOT_MANIFEST)
    if not os.path.exists(path):
        raise PublishError("no {}: list the root public keys there, with their owners (see "
                           "docs/guides/mesh-root-ceremony.md)".format(path))
    try:
        doc = load_json(path, metadata.MAX_LENGTH["root"])
    except ValueError as exc:
        raise PublishError("{}: not JSON: {}".format(path, exc))
    if not isinstance(doc, dict) or doc.get("version") != 1 or not isinstance(doc.get("keys"), list) \
            or not doc["keys"]:
        raise PublishError('{}: expected {{"version": 1, "keys": [...]}} with at least one key'.format(path))
    keys: List[Key] = []
    owners: Dict[str, Dict[str, str]] = {}
    for index, entry in enumerate(doc["keys"]):
        where = "{}: keys[{}]".format(path, index)
        if not isinstance(entry, dict) or not set(entry) <= {"public", "keyid", "owner", "term_start"}:
            raise PublishError("{}: takes only public, keyid, owner, term_start".format(where))
        try:
            public = bytes.fromhex(entry.get("public") if isinstance(entry.get("public"), str) else "")
        except ValueError:
            public = b""
        if len(public) != ed25519.KEY_SIZE:
            raise PublishError("{}: public must be a {}-byte Ed25519 key in hex".format(where, ed25519.KEY_SIZE))
        key = Key.from_public(public)
        if "keyid" in entry and entry["keyid"] != key.keyid:
            raise PublishError("{}: keyid does not match the public key".format(where))
        if key.keyid in owners:
            raise PublishError("{}: key {} is listed twice".format(where, key.keyid[:16]))
        owner = {name: entry[name] for name in ("owner", "term_start") if name in entry}
        if not all(isinstance(v, str) and v for v in owner.values()):
            raise PublishError("{}: owner and term_start must be non-empty strings".format(where))
        keys.append(key)
        owners[key.keyid] = owner
    return keys, {keyid: owner for keyid, owner in owners.items() if owner}


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


def _current_root(site_dir: str) -> Optional[Tuple[bytes, metadata.RootInfo]]:
    """The site's ``metadata/root.json``, raw and parsed, or ``None`` before the first publish."""
    path = os.path.join(site_dir, METADATA_DIR, "root.json")
    if not os.path.exists(path):
        return None
    raw = read_bounded(path, metadata.MAX_LENGTH["root"])
    try:
        return raw, metadata.RootInfo.parse(metadata.loads(raw, metadata.MAX_LENGTH["root"])["signed"])
    except MetadataError as exc:
        raise PublishError("{}: {}".format(path, exc))


_CEREMONY = ("sign one in a root ceremony (interlock mesh root draft|sign|assemble, "
             "docs/guides/mesh-root-ceremony.md)")


def _root_for(site_dir: str, signers: Mapping[str, Sequence[Signer]], thresholds: Mapping[str, int],
              keys_dir: str, now: float, expiry: Mapping[str, int]) -> Tuple[bytes, int, bool, List[str]]:
    """The root envelope to publish: the existing one when the keys are unchanged,
    else a new version signed by old and new root signers.
    Returns (bytes, version, changed, warnings).

    With no complete threshold of root keys in ``keys_dir`` (the root is
    offline), only the online roles are compared, and the existing root is
    re-published as long as they match and it has not expired; inside its
    signing period that comes with a warning. Anything else needs a new root,
    which then has to come from a ceremony.
    """
    role_keys = {role: [s.key for s in signers[role]] for role in metadata.ROLES}
    extra = {LOG_ROLE: [s.key for s in signers.get(LOG_ROLE, [])]} if signers.get(LOG_ROLE) else {}
    root_threshold = int(thresholds.get("root", 1))
    offline = len({s.keyid for s in signers["root"]}) < root_threshold
    current = _current_root(site_dir)
    if current is not None:
        existing_raw, existing = current
        wanted = dict(role_keys, **extra)
        if offline:
            # The root keys are not here to compare, or to sign with: judge the
            # online roles alone, against the root as it is.
            wanted.pop("root")
        changed = sorted(
            role for role in (set(existing.roles) | set(wanted)) - ({"root"} if offline else set())
            if role not in existing.roles or role not in wanted
            or existing.roles[role]["keyids"] != sorted(k.keyid for k in wanted[role])
            or existing.roles[role]["threshold"] != int(thresholds.get(role, 1))
        )
        signing_period = now + metadata.ROOT_SIGNING_PERIOD >= existing.expires
        if offline:
            if changed:
                raise PublishError("the {} key(s) in {} do not match root v{}, so a new root is needed and {} "
                                   "has {} of the {} root key(s) it takes to sign one: {}".format(
                                       ", ".join(changed), keys_dir, existing.version, keys_dir,
                                       len({s.keyid for s in signers["root"]}), root_threshold, _CEREMONY))
            if now > existing.expires:
                raise PublishError("root v{} expired at {}; no subscriber accepts anything under it until a "
                                   "new root is published: {}".format(existing.version, iso(existing.expires),
                                                                      _CEREMONY))
            warnings = []
            if signing_period:
                warnings.append("root v{} expires at {}, in {:.0f} day(s): it is inside its {}-day signing "
                                "period; {}".format(existing.version, iso(existing.expires),
                                                    (existing.expires - now) / 86400,
                                                    metadata.ROOT_SIGNING_PERIOD // 86400, _CEREMONY))
            return existing_raw, existing.version, False, warnings
        if not changed and not signing_period:
            return existing_raw, existing.version, False, []
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
        return metadata.dumps(env), version, True, []
    if offline:
        raise PublishError("{} has no root yet, and {} has {} of the {} root key(s) it takes to sign the first "
                           "one: put the root key files there for the first publish, or {}".format(
                               site_dir, keys_dir, len({s.keyid for s in signers["root"]}), root_threshold,
                               _CEREMONY))
    signed = metadata.build_root(role_keys, thresholds, version=1, expires=iso(now + expiry["root"]),
                                 extra_roles=extra)
    env = metadata.envelope(signed, signers["root"])
    return metadata.dumps(env), 1, True, []


def publish(source_dir: str, site_dir: str, keys_dir: str, *, now: Optional[float] = None,
            expiry: Optional[Mapping[str, int]] = None, validate: bool = True) -> Dict[str, Any]:
    """Build and sign ``site_dir`` from the packs in ``source_dir``.

    Versions of targets, snapshot and timestamp are one more than what the site
    already holds, so a subscriber sees every publish as an update and never a
    rollback. No root key is needed while the current root still fits the
    online keys and has not expired. Returns a summary the command line
    prints; ``warnings`` says when the root is due for a ceremony.
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

    root_raw, root_version, root_changed, warnings = _root_for(site_dir, signers, thresholds, keys_dir,
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
        "warnings": warnings,
    }


# --- the root ceremony ---------------------------------------------------------------
#
# A draft is an envelope with no signatures: ``signed`` is the next root, and
# ``previous_root`` (not signed, informational) names the keys of the root it
# replaces, so a keyholder whose key is only in the old root can still sign and
# a witness can see whose approval it needs. ``assemble_root`` never trusts it:
# it checks against the site's own root.json.


def _write_new(path: str, data: bytes, what: str) -> None:
    if os.path.exists(path):
        raise PublishError("{} exists; a {} is never overwritten: move a failed ceremony's files aside and "
                           "start again".format(path, what))
    atomic_write(path, data)


def _read_draft(path: str) -> Tuple[Dict[str, Any], metadata.RootInfo]:
    try:
        env = metadata.loads(read_bounded(path, metadata.MAX_LENGTH["root"]), metadata.MAX_LENGTH["root"])
        return env, metadata.RootInfo.parse(env["signed"])
    except (MetadataError, ValueError) as exc:
        raise PublishError("{}: not a root draft: {}".format(path, exc))


def _root_role_keys(root: metadata.RootInfo) -> Dict[str, Key]:
    return {keyid: root.keys[keyid] for keyid in root.roles["root"]["keyids"]}


def draft_root(site_dir: str, keys_dir: str, out_path: str, *, expires_days: Optional[float] = None,
               now: Optional[float] = None) -> Dict[str, Any]:
    """Write the unsigned next root to ``out_path`` and return it.

    Its version is one more than the site's ``metadata/root.json`` (1 when the
    site has none), its online roles are the keys in ``keys_dir``, its root
    keys and their owners come from ``keys_dir/root-keys.json``, and its root
    threshold from ``roles.json``. The file is sorted, indented JSON, the one
    file a witness reviews; what each keyholder signs is the canonical form of
    its ``signed`` object, whose SHA-256 ``sign_root`` and ``assemble_root`` report.
    """
    now = time.time() if now is None else now
    seconds = metadata.DEFAULT_EXPIRY["root"] if expires_days is None else int(float(expires_days) * 86400)
    if seconds <= metadata.ROOT_SIGNING_PERIOD:
        raise PublishError("a root must outlive its {}-day signing period; {} day(s) is too short".format(
            metadata.ROOT_SIGNING_PERIOD // 86400, expires_days))
    signers, thresholds = load_signers(keys_dir)
    root_keys, owners = load_root_manifest(keys_dir)
    current = _current_root(site_dir)
    role_keys: Dict[str, List[Key]] = {role: [s.key for s in signers[role]] for role in ONLINE_ROLES}
    role_keys["root"] = root_keys
    extra = {LOG_ROLE: [s.key for s in signers[LOG_ROLE]]} if signers[LOG_ROLE] else {}
    version = 1 if current is None else current[1].version + 1
    try:
        signed = metadata.build_root(role_keys, thresholds, version=version, expires=iso(now + seconds),
                                     extra_roles=extra, key_owners=owners)
    except ValueError as exc:
        raise PublishError("cannot draft root v{}: {}".format(version, exc))
    doc: Dict[str, Any] = {"signed": signed, "signatures": []}
    if current is not None:
        previous = current[1]
        doc["previous_root"] = {
            "version": previous.version, "expires": iso(previous.expires),
            "threshold": previous.roles["root"]["threshold"],
            "keys": {keyid: key.public.hex() for keyid, key in _root_role_keys(previous).items()},
        }
    _write_new(out_path, (json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"),
               "ceremony draft")
    return doc


def _signature_from(external_signer: str, payload: bytes, timeout: float) -> bytes:
    try:
        argv = shlex.split(external_signer)
    except ValueError as exc:
        raise PublishError("--external-signer: {}".format(exc))
    if not argv:
        raise PublishError("--external-signer: empty command")
    try:
        done = subprocess.run(argv, input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PublishError("external signer {!r} did not run: {}".format(argv[0], exc))
    if done.returncode != 0:
        raise PublishError("external signer {!r} exited {}: {}".format(
            argv[0], done.returncode, done.stderr.decode("utf-8", "replace").strip()[-400:]))
    try:
        sig = bytes.fromhex(done.stdout.decode("ascii").strip())
    except (UnicodeDecodeError, ValueError):
        sig = b""
    if len(sig) != 64:
        raise PublishError("external signer {!r} must print one 64-byte Ed25519 signature in hex".format(argv[0]))
    return sig


def sign_root(draft_path: str, *, key_path: Optional[str] = None, external_signer: Optional[str] = None,
              timeout: float = EXTERNAL_SIGNER_TIMEOUT) -> Dict[str, Any]:
    """Add one detached signature to a draft: write ``<draft_path>.sig.<keyid>``.

    Sign with a root key file (``key_path``), or run ``external_signer``, a
    command line that gets the bytes to sign on stdin and prints the hex
    signature (a hardware token's helper). Either way the signature is checked
    before it is written, and must come from a root key of the draft or of the
    root it replaces. Returns the key id, which root(s) it counts toward, and
    the SHA-256 of the signed bytes.
    """
    if (key_path is None) == (external_signer is None):
        raise PublishError("sign with exactly one of a key file or an external signer")
    env, new = _read_draft(draft_path)
    payload = metadata.signed_bytes(env["signed"])
    previous: Dict[str, Key] = {}
    listed = env.get("previous_root")
    listed = listed.get("keys") if isinstance(listed, dict) else ({} if listed is None else None)
    if not isinstance(listed, dict):
        raise PublishError("{}: previous_root is malformed".format(draft_path))
    for keyid, public in listed.items():
        try:
            key = Key.from_public(bytes.fromhex(public))
        except (TypeError, ValueError):
            key = None
        if key is None or key.keyid != keyid:
            raise PublishError("{}: previous_root lists a malformed key".format(draft_path))
        previous[keyid] = key
    candidates = dict(previous, **_root_role_keys(new))
    if key_path is not None:
        record = load_json(key_path, KEY_FILE_MAX)
        if not isinstance(record, dict) or record.get("role") != "root":
            raise PublishError("{}: not a root key file".format(key_path))
        try:
            signer = Signer(bytes.fromhex(record["seed"]))
        except (KeyError, TypeError, ValueError):
            raise PublishError("{}: not a key file".format(key_path))
        if record.get("public") and record["public"] != signer.public.hex():
            raise PublishError("{}: public key does not match its seed".format(key_path))
        if signer.keyid not in candidates:
            raise PublishError("key {} is not a root key of this draft or of the root it replaces".format(
                signer.keyid))
        keyid, sig = signer.keyid, ed25519.sign(signer.seed, payload)
    else:
        sig = _signature_from(str(external_signer), payload, timeout)
        keyid = next((k for k, key in sorted(candidates.items()) if ed25519.verify(key.public, payload, sig)), "")
        if not keyid:
            raise PublishError("the external signer's signature does not verify under any root key of this "
                               "draft or of the root it replaces")
    if not ed25519.verify(candidates[keyid].public, payload, sig):
        raise PublishError("the signature by {} does not verify; nothing was written".format(keyid))
    path = "{}.sig.{}".format(draft_path, keyid)
    atomic_write(path, (json.dumps({"keyid": keyid, "sig": sig.hex()}, sort_keys=True) + "\n").encode("utf-8"))
    counts = [name for name, keys in (("new", _root_role_keys(new)), ("previous", previous)) if keyid in keys]
    return {"path": path, "keyid": keyid, "version": new.version, "counts_toward": counts,
            "sha256": sha256_hex(payload)}


def assemble_root(draft_path: str, sig_paths: Sequence[str], site_dir: str, *,
                  now: Optional[float] = None) -> Dict[str, Any]:
    """Combine a draft and its detached signatures into the site's next root.

    The previous root (the site's ``metadata/root.json``) must approve with
    its threshold and the new root with its own, and the version must be
    exactly one more: :meth:`TrustedMetadata.update_root`, the check every
    subscriber applies, is run on the exact bytes before anything is written.
    Writes ``metadata/<N>.root.json`` and ``root.json`` and, when the site has
    a transparency log, appends the new root to it (the next ``publish``
    signs a checkpoint over it). Run ``publish`` next, so the online roles are
    signed under the new root.
    """
    now = time.time() if now is None else now
    env, new = _read_draft(draft_path)
    signed = env["signed"]
    payload = metadata.signed_bytes(signed)
    current = _current_root(site_dir)
    expected = 1 if current is None else current[1].version + 1
    if new.version != expected:
        raise PublishError("the draft is root v{} but the site's next root is v{}: draft it again; a draft "
                           "for another root is never reused".format(new.version, expected))
    if now > new.expires:
        raise PublishError("the draft expired at {}; draft it again".format(iso(new.expires)))
    new_keys = _root_role_keys(new)
    old_keys = _root_role_keys(current[1]) if current is not None else {}
    collected: Dict[str, Dict[str, str]] = {}
    for path in sig_paths:
        try:
            entry = load_json(path, KEY_FILE_MAX)
        except (OSError, ValueError) as exc:
            raise PublishError("{}: not a signature file: {}".format(path, exc))
        if not isinstance(entry, dict) or not isinstance(entry.get("keyid"), str) \
                or not isinstance(entry.get("sig"), str):
            raise PublishError('{}: expected {{"keyid": ..., "sig": ...}}'.format(path))
        key = new_keys.get(entry["keyid"]) or old_keys.get(entry["keyid"])
        if key is None:
            raise PublishError("{}: key {} is not a root key of the draft or of root v{}".format(
                path, entry["keyid"][:16], expected - 1))
        try:
            sig = bytes.fromhex(entry["sig"])
        except ValueError:
            sig = b""
        if not ed25519.verify(key.public, payload, sig):
            raise PublishError("{}: the signature does not verify over this draft (a different or edited "
                               "draft was signed)".format(path))
        collected[key.keyid] = {"keyid": key.keyid, "sig": sig.hex()}
    short = []
    for name, keys, threshold in (("root v{}".format(expected - 1), old_keys,
                                   current[1].roles["root"]["threshold"] if current is not None else 0),
                                  ("the new root v{}".format(expected), new_keys, new.roles["root"]["threshold"])):
        have = len(set(collected) & set(keys))
        if have < threshold:
            short.append("{} has {} of the {} signature(s) it needs".format(name, have, threshold))
    if short:
        raise PublishError("not assembled: {}".format("; ".join(short)))
    raw = metadata.dumps({"signed": signed, "signatures": sorted(collected.values(), key=lambda s: s["keyid"])})
    try:
        if current is None:
            metadata.TrustedMetadata(raw)
        else:
            metadata.TrustedMetadata(current[0]).update_root(raw)
    except MetadataError as exc:
        raise PublishError("not assembled: {}".format(exc))
    meta_dir = os.path.join(site_dir, METADATA_DIR)
    name = "{}.root.json".format(new.version)
    _write_new(os.path.join(meta_dir, name), raw, "published root")
    atomic_write(os.path.join(meta_dir, "root.json"), raw)
    logged = False
    entries_path = os.path.join(site_dir, LOG_DIR, "entries.jsonl")
    if os.path.exists(entries_path):
        from .log import Entry, MerkleLog

        MerkleLog(entries_path).append([Entry("root", name, sha256_hex(raw), new.version, now)])
        logged = True
    return {"site": os.path.abspath(site_dir), "root_version": new.version, "path": os.path.join(meta_dir, name),
            "signatures": sorted(collected), "logged": logged, "sha256": sha256_hex(payload),
            "expires": iso(new.expires)}


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
