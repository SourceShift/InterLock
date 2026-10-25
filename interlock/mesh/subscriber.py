"""The node side: subscribe to a commons, verify it, and install its packs.

A node keeps everything under one directory (``~/.interlock/mesh`` or
``$INTERLOCK_MESH_DIR``)::

    root.json        the pinned root the operator trusted, obtained out of band
    config.json      mirrors, ring, monitor window, ceilings, grants
    metadata/        every metadata document the node verified and now trusts
    targets/         verified pack bytes, content-addressed
    state.json       when each rule was first seen (the monitor window), last sync
    shadow.jsonl     what shadow-mode rules, and capped rules with no approver, would have decided

``sync`` talks to the network; nothing else does. The policy loader resolves
``"extends": "mesh:<pack>@<ring>"`` from the verified cache alone, so a policy
load never blocks on a mirror and a mirror that goes away leaves the last good
pack in force. A pack that is not in the cache is a load error, which the
loader turns into "keep the previous policy": fail closed, never fail open.

Every sync re-verifies from the pinned root: root rotations, then timestamp,
snapshot, targets, then each pack's bytes against its signed hash and length.
A failure at any step leaves the cache untouched and is recorded in
``state.json`` for ``interlock mesh status`` and ``interlock doctor``.
"""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import default_mesh_dir, metadata
from ._util import atomic_write, iso, load_json, read_bounded
from .bundle import (DEFAULT_CEILINGS, DEFAULT_MONITOR_SECONDS, RINGS, PackError, apply_ring, check_grants,
                     normalize_pack)
from .metadata import MetadataError, TrustedMetadata

__all__ = ["Subscriber", "SubscriberError", "Fetcher", "Config", "parse_spec", "resolve_extends",
           "watch_info", "DEFAULT_RING", "SPEC_PREFIX"]

SPEC_PREFIX = "mesh:"
DEFAULT_RING = "stable"
CONFIG_FILE = "config.json"
ROOT_FILE = "root.json"
STATE_FILE = "state.json"
SHADOW_FILE = "shadow.jsonl"
METADATA_DIR = "metadata"
TARGETS_DIR = "targets"
STATE_MAX = 16 * 1024 * 1024
SHADOW_ROTATE_BYTES = 20 * 1024 * 1024
FETCH_TIMEOUT = 10.0
_state_lock = threading.Lock()

#: The ceilings ``init`` wrote into every config before a stable block needed
#: a grant. No operator chose them, so a config that still holds exactly this
#: map reads as the current defaults; an operator who wants a pack's blocks
#: grants them.
_LEGACY_CEILINGS = {"experimental": "escalate", "test": "modify", "stable": None}


class SubscriberError(Exception):
    """The node cannot do what was asked; the message says why and what to run."""


def parse_spec(spec: str, default_ring: str = DEFAULT_RING) -> Tuple[str, str]:
    """``"mesh:coding-agent@early"`` -> ``("coding-agent", "early")``."""
    if not isinstance(spec, str) or not spec.startswith(SPEC_PREFIX):
        raise SubscriberError("not a mesh spec: {!r}".format(spec))
    body = spec[len(SPEC_PREFIX):]
    pack, _, ring = body.partition("@")
    ring = ring or default_ring
    if not pack or "/" in pack or pack.startswith(".") or not all(
            c.isalnum() or c in "-_." for c in pack):
        raise SubscriberError("bad pack name in {!r}".format(spec))
    if ring not in RINGS:
        raise SubscriberError("unknown ring {!r} in {!r}; use one of {}".format(
            ring, spec, ", ".join(RINGS)))
    return pack, ring


class Config:
    """``config.json``: where to fetch from and how cautiously to install."""

    def __init__(self, mirrors: Sequence[str] = (), ring: str = DEFAULT_RING,
                 monitor_days: float = DEFAULT_MONITOR_SECONDS / 86400,
                 ceilings: Optional[Dict[str, Optional[str]]] = None,
                 max_bundle_bytes: int = 1024 * 1024, refresh_seconds: int = 3600,
                 recorder: Optional[Dict[str, Any]] = None,
                 grants: Optional[Dict[str, Any]] = None) -> None:
        self.mirrors = [m.rstrip("/") for m in mirrors]
        self.ring = ring
        self.monitor_days = float(monitor_days)
        self.ceilings = dict(DEFAULT_CEILINGS) if ceilings is None else dict(ceilings)
        self.max_bundle_bytes = int(max_bundle_bytes)
        self.refresh_seconds = int(refresh_seconds)
        # The fingerprint recorder (phase 2): off until the operator enables it.
        self.recorder: Dict[str, Any] = {"enabled": False, "alpha": 1.5, "sample_rules": []}
        if recorder:
            self.recorder.update({k: recorder[k] for k in ("enabled", "alpha", "sample_rules") if k in recorder})
        # What the operator lets carry the pack's own verdict (decision R5):
        # without a grant, a community block is capped to an escalate.
        self.grants: Dict[str, List[Dict[str, str]]] = check_grants(grants)

    def to_dict(self) -> Dict[str, Any]:
        return {"version": 1, "mirrors": list(self.mirrors), "ring": self.ring,
                "monitor_days": self.monitor_days, "ceilings": self.ceilings,
                "max_bundle_bytes": self.max_bundle_bytes, "refresh_seconds": self.refresh_seconds,
                "recorder": dict(self.recorder), "grants": check_grants(self.grants)}

    def grant(self, entry: Dict[str, str]) -> bool:
        """Add one ``block`` grant; False when an identical one is already there."""
        (entry,) = check_grants({"block": [entry]})["block"]
        if entry in self.grants["block"]:
            return False
        self.grants["block"].append(entry)
        return True

    def revoke(self, entry: Dict[str, str]) -> bool:
        """Remove the ``block`` grant equal to ``entry``; False when none is."""
        (entry,) = check_grants({"block": [entry]})["block"]
        if entry not in self.grants["block"]:
            return False
        self.grants["block"] = [g for g in self.grants["block"] if g != entry]
        return True

    def save(self, path: str) -> None:
        atomic_write(path, json.dumps(self.to_dict(), indent=1, sort_keys=True).encode("utf-8"), mode=0o600)

    @classmethod
    def load(cls, path: str) -> "Config":
        raw = load_json(path, 64 * 1024)
        if not isinstance(raw, dict) or raw.get("version") != 1:
            raise SubscriberError("{}: not a mesh config".format(path))
        ring = raw.get("ring", DEFAULT_RING)
        if ring not in RINGS:
            raise SubscriberError("{}: unknown ring {!r}".format(path, ring))
        ceilings = raw.get("ceilings")
        if ceilings == _LEGACY_CEILINGS:
            ceilings = None
        try:
            grants = check_grants(raw.get("grants"))
        except PackError as exc:
            raise SubscriberError("{}: {}".format(path, exc))
        return cls(mirrors=raw.get("mirrors", []), ring=ring,
                   monitor_days=raw.get("monitor_days", DEFAULT_MONITOR_SECONDS / 86400),
                   ceilings=ceilings, max_bundle_bytes=raw.get("max_bundle_bytes", 1024 * 1024),
                   refresh_seconds=raw.get("refresh_seconds", 3600),
                   recorder=raw.get("recorder") if isinstance(raw.get("recorder"), dict) else None,
                   grants=grants)


class Fetcher:
    """Bounded HTTP(S) and ``file://`` reads from a list of mirrors, first one
    that answers wins. Every read stops at ``max_length + 1`` bytes."""

    def __init__(self, mirrors: Sequence[str], timeout: float = FETCH_TIMEOUT) -> None:
        self.mirrors = [m.rstrip("/") for m in mirrors]
        self.timeout = timeout
        if not self.mirrors:
            raise SubscriberError("no mirrors configured")

    def get(self, relpath: str, max_length: int) -> bytes:
        last: Optional[Exception] = None
        for mirror in self.mirrors:
            url = "{}/{}".format(mirror, urllib.parse.quote(relpath, safe="/.-_"))
            try:
                return self._read(url, max_length)
            except (OSError, ValueError) as exc:
                last = exc
        raise OSError("{}: {}".format(relpath, last))

    def _read(self, url: str, max_length: int) -> bytes:
        scheme = urllib.parse.urlsplit(url).scheme
        if scheme == "file":
            path = urllib.request.url2pathname(urllib.parse.urlsplit(url).path)
            return read_bounded(path, max_length)
        if scheme not in ("http", "https"):
            raise ValueError("unsupported mirror scheme {!r}".format(scheme))
        request = urllib.request.Request(url, headers={"User-Agent": "interlock-mesh"})
        with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310 (scheme checked)
            data = response.read(max_length + 1)
        if len(data) > max_length:
            raise ValueError("{} is larger than {} bytes".format(url, max_length))
        return data


#: The clock every subscriber built without an explicit ``now`` reads. Module
#: level so a test can move the policy loader's own subscriber through time.
_CLOCK: Callable[[], float] = time.time


class Subscriber:
    def __init__(self, mesh_dir: Optional[str] = None, *, now: Optional[Callable[[], float]] = None,
                 fetcher: Optional[Fetcher] = None) -> None:
        self.dir = os.path.abspath(mesh_dir or default_mesh_dir())
        self._now = now if now is not None else (lambda: _CLOCK())
        self._fetcher = fetcher

    # paths ------------------------------------------------------------------------

    @property
    def config_path(self) -> str:
        return os.path.join(self.dir, CONFIG_FILE)

    @property
    def root_path(self) -> str:
        return os.path.join(self.dir, ROOT_FILE)

    @property
    def state_path(self) -> str:
        return os.path.join(self.dir, STATE_FILE)

    @property
    def shadow_path(self) -> str:
        return os.path.join(self.dir, SHADOW_FILE)

    @property
    def targets_metadata_path(self) -> str:
        return os.path.join(self.dir, METADATA_DIR, "targets.json")

    def _meta(self, name: str) -> str:
        return os.path.join(self.dir, METADATA_DIR, name)

    def _target_file(self, consistent_name: str) -> str:
        return os.path.join(self.dir, TARGETS_DIR, *consistent_name.split("/"))

    def is_configured(self) -> bool:
        return os.path.exists(self.config_path) and os.path.exists(self.root_path)

    # setup ------------------------------------------------------------------------

    def init(self, root_raw: bytes, mirrors: Sequence[str], *, ring: str = DEFAULT_RING,
             monitor_days: Optional[float] = None) -> Config:
        """Pin a root and write the config. The root must parse and self-verify."""
        try:
            TrustedMetadata(root_raw, now=self._now)
        except MetadataError as exc:
            raise SubscriberError("the root is not usable: {}".format(exc))
        if ring not in RINGS:
            raise SubscriberError("unknown ring {!r}".format(ring))
        os.makedirs(self.dir, exist_ok=True)
        os.chmod(self.dir, 0o700)
        config = Config(mirrors=mirrors, ring=ring,
                        monitor_days=DEFAULT_MONITOR_SECONDS / 86400 if monitor_days is None else monitor_days)
        atomic_write(self.root_path, root_raw, mode=0o600)
        atomic_write(self.config_path, json.dumps(config.to_dict(), indent=1, sort_keys=True).encode("utf-8"),
                     mode=0o600)
        return config

    def config(self) -> Config:
        if not self.is_configured():
            raise SubscriberError("the mesh is not configured; run: interlock mesh init --root ROOT --mirror URL")
        return Config.load(self.config_path)

    # state --------------------------------------------------------------------------

    def _load_state(self) -> Dict[str, Any]:
        if not os.path.exists(self.state_path):
            return {"version": 1, "first_seen": {}, "subscriptions": {}, "next_transition": {}}
        try:
            state = load_json(self.state_path, STATE_MAX)
        except (OSError, ValueError):
            return {"version": 1, "first_seen": {}, "subscriptions": {}, "next_transition": {}}
        state.setdefault("first_seen", {})
        state.setdefault("subscriptions", {})
        state.setdefault("next_transition", {})
        return state

    def _save_state(self, state: Dict[str, Any]) -> None:
        atomic_write(self.state_path, json.dumps(state, sort_keys=True, indent=1).encode("utf-8"), mode=0o600)

    # trust ----------------------------------------------------------------------------

    def _trusted(self, *, allow_expired: bool) -> TrustedMetadata:
        """Rebuild the trusted view from the pinned root and the verified cache."""
        root_raw = read_bounded(self.root_path, metadata.MAX_LENGTH["root"])
        now: Callable[[], float] = (lambda: 0.0) if allow_expired else self._now
        trusted = TrustedMetadata(root_raw, now=now)
        for _ in range(metadata.MAX_ROOT_ROTATIONS):
            path = self._meta("{}.root.json".format(trusted.root.version + 1))
            if not os.path.exists(path):
                break
            trusted.update_root(read_bounded(path, metadata.MAX_LENGTH["root"]))
        for name, update in (("timestamp.json", trusted.update_timestamp),
                             ("snapshot.json", trusted.update_snapshot),
                             ("targets.json", trusted.update_targets)):
            path = self._meta(name)
            if not os.path.exists(path):
                break
            update(read_bounded(path, metadata.MAX_LENGTH[name.split(".")[0]]))
        return trusted

    # sync -----------------------------------------------------------------------------

    def sync(self) -> Dict[str, Any]:
        """Refresh the verified cache from the mirrors. Fail closed: on any error
        the cache is left as it was and the error is recorded and raised."""
        config = self.config()
        fetch = self._fetcher or Fetcher(config.mirrors)
        state = self._load_state()
        now = self._now()
        try:
            result = self._sync(config, fetch, now)
        except (MetadataError, OSError, ValueError, SubscriberError) as exc:
            state["last_error"] = "{}: {}".format(type(exc).__name__, exc)
            state["last_error_at"] = now
            self._save_state(state)
            raise SubscriberError("sync failed, cache unchanged: {}".format(exc))
        state["last_sync"] = now
        state.pop("last_error", None)
        state.pop("last_error_at", None)
        self._save_state(state)
        return result

    def _sync(self, config: Config, fetch: Fetcher, now: float) -> Dict[str, Any]:
        trusted = self._trusted(allow_expired=False)
        new_roots: List[Tuple[int, bytes]] = []
        for _ in range(metadata.MAX_ROOT_ROTATIONS):
            next_version = trusted.root.version + 1
            try:
                raw = fetch.get("metadata/{}.root.json".format(next_version), metadata.MAX_LENGTH["root"])
            except OSError:
                break
            trusted.update_root(raw)
            new_roots.append((next_version, raw))
        if trusted.root_expired():
            raise MetadataError("expired", "the root expired at {}; obtain a new one out of band".format(
                iso(trusted.root.expires)))
        ts_raw = fetch.get("metadata/timestamp.json", metadata.MAX_LENGTH["timestamp"])
        ts = trusted.update_timestamp(ts_raw)
        snap_meta = ts["meta"]["snapshot.json"]
        snap_raw = fetch.get("metadata/{}.snapshot.json".format(snap_meta["version"]), snap_meta["length"])
        snap = trusted.update_snapshot(snap_raw)
        tgt_meta = snap["meta"]["targets.json"]
        tgt_raw = fetch.get("metadata/{}.targets.json".format(tgt_meta["version"]), tgt_meta["length"])
        trusted.update_targets(tgt_raw)

        fetched: List[str] = []
        kept: List[str] = []
        for info in trusted.all_targets():
            if info.length > config.max_bundle_bytes:
                raise MetadataError("length", "{} is {} bytes, above the configured {}".format(
                    info.path, info.length, config.max_bundle_bytes))
            local = self._target_file(info.consistent_name)
            if os.path.exists(local):
                try:
                    trusted.verify_target(info.path, read_bounded(local, info.length))
                    kept.append(info.path)
                    continue
                except (MetadataError, ValueError, OSError):
                    pass
            data = fetch.get("{}/{}".format(TARGETS_DIR, info.consistent_name), info.length)
            trusted.verify_target(info.path, data)
            atomic_write(local, data)
            fetched.append(info.path)

        # The transparency log, when the commons has one: every document above
        # must be in it, and the log may only have grown since we last looked.
        log_info = None
        if "log" in trusted.root.roles:
            from ._util import sha256_hex
            from .repository import verify_log
            previous = self._saved_checkpoint()
            hashes = [sha256_hex(ts_raw), sha256_hex(snap_raw), sha256_hex(tgt_raw)]
            hashes += [info.sha256 for info in trusted.all_targets()]
            try:
                log_info = verify_log(trusted, fetch, hashes, previous=previous)
            except MetadataError as exc:
                if "split view" in str(exc) or "rewritten" in str(exc):
                    self._record_split_view("sync", str(exc))
                raise

        # Everything verified: now, and only now, replace the trusted cache.
        for version, raw in new_roots:
            atomic_write(self._meta("{}.root.json".format(version)), raw)
        atomic_write(self._meta("timestamp.json"), ts_raw)
        atomic_write(self._meta("snapshot.json"), snap_raw)
        atomic_write(self._meta("{}.snapshot.json".format(snap["version"])), snap_raw)
        atomic_write(self._meta("targets.json"), tgt_raw)
        atomic_write(self._meta("{}.targets.json".format(tgt_meta["version"])), tgt_raw)
        if log_info is not None:
            atomic_write(self._log_path("checkpoint.json"), log_info["checkpoint_raw"])
            atomic_write(self._log_path("entries.jsonl"), log_info["entries_raw"])
            self._remember_checkpoint(log_info["checkpoint"], source="sync")
        self._prune_targets({info.consistent_name for info in trusted.all_targets()})
        return {"root_version": trusted.root.version, "timestamp_version": ts["version"],
                "snapshot_version": snap["version"], "targets_version": tgt_meta["version"],
                "timestamp_expires": ts["expires"], "fetched": fetched, "kept": kept,
                "packs": [info.path for info in trusted.all_targets()],
                "log": None if log_info is None else {"size": log_info["size"], "root": log_info["root"]}}

    # log and gossip -----------------------------------------------------------------

    def _log_path(self, name: str) -> str:
        return os.path.join(self.dir, "log", name)

    def _saved_checkpoint(self) -> Optional[Dict[str, Any]]:
        path = self._log_path("checkpoint.json")
        if not os.path.exists(path):
            return None
        try:
            return json.loads(read_bounded(path, 16 * 1024).decode("utf-8")).get("checkpoint")
        except (OSError, ValueError, AttributeError):
            return None

    def _remember_checkpoint(self, checkpoint: Dict[str, Any], *, source: str) -> None:
        line = json.dumps({"ts": self._now(), "source": source, **checkpoint}, sort_keys=True) + "\n"
        os.makedirs(os.path.dirname(self._log_path("seen.jsonl")), exist_ok=True)
        with open(self._log_path("seen.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(line)

    def _record_split_view(self, source: str, detail: str) -> None:
        with _state_lock:
            state = self._load_state()
            state.setdefault("split_views", []).append({"ts": self._now(), "source": source, "detail": detail})
            state["split_views"] = state["split_views"][-50:]
            self._save_state(state)

    def gossip(self, peer_url: str, *, token: Optional[str] = None) -> Dict[str, Any]:
        """Exchange checkpoints with a peer and compare: the way a split view is caught.

        Sends our newest verified checkpoint to ``peer_url/v1/gossip``, receives
        the peer's, verifies its signature under our root's log keys, and checks
        both against our entries. A conflict is recorded in the state for
        ``status`` and ``doctor``; it is evidence, and it names the peer.
        """
        from .log import LogError, MerkleLog, split_view, verify_checkpoint
        from .report import submit

        path = self._log_path("checkpoint.json")
        if not os.path.exists(path):
            raise SubscriberError("no verified checkpoint yet; run: interlock mesh sync")
        ours_env = json.loads(read_bounded(path, 16 * 1024).decode("utf-8"))
        try:
            reply = submit(peer_url.rstrip("/") + "/v1/gossip", {"checkpoint": ours_env}, token=token)
        except OSError as exc:
            raise SubscriberError("peer {} unreachable: {}".format(peer_url, exc))
        theirs_env = reply.get("checkpoint")
        result: Dict[str, Any] = {"peer": peer_url, "ours": ours_env["checkpoint"], "theirs": None, "conflict": None}
        if not theirs_env:
            return result
        trusted = self._trusted(allow_expired=True)
        keyids = trusted.root.roles.get("log", {}).get("keyids", [])
        try:
            theirs = verify_checkpoint(theirs_env, keyids)
        except LogError as exc:
            result["conflict"] = "peer checkpoint rejected: {}".format(exc)
            self._record_split_view(peer_url, result["conflict"])
            return result
        result["theirs"] = theirs
        log = None
        entries = self._log_path("entries.jsonl")
        if os.path.exists(entries):
            try:
                log = MerkleLog.from_bytes(read_bounded(entries, 16 * 1024 * 1024))
            except (LogError, ValueError):
                log = None
        conflict = split_view(ours_env["checkpoint"], theirs, log)
        if conflict:
            result["conflict"] = conflict
            self._record_split_view(peer_url, conflict)
        else:
            self._remember_checkpoint(theirs, source="gossip:" + peer_url)
        return result

    def _prune_targets(self, keep: set) -> None:
        base = os.path.join(self.dir, TARGETS_DIR)
        for root, _dirs, files in os.walk(base):
            for name in files:
                full = os.path.join(root, name)
                rel = os.path.relpath(full, base).replace(os.sep, "/")
                if rel not in keep:
                    try:
                        os.unlink(full)
                    except OSError:
                        pass

    # resolve ----------------------------------------------------------------------------

    def resolve(self, pack: str, ring: Optional[str] = None) -> Tuple[Dict[str, Any], str, Dict[str, Any]]:
        """The installable document for ``pack`` on ``ring``, from the cache only.

        Returns ``(document, cache_path, info)``; ``info`` has the rules dropped
        by the ring, the shadowed ones, the ceilings applied, the rules a grant
        lifted (``granted``) and the ones capped to an escalate (``capped``),
        and the next shadow-to-enforce transition. Raises
        :class:`SubscriberError` when the pack is not in the verified cache.
        """
        config = self.config()
        ring = ring or config.ring
        try:
            trusted = self._trusted(allow_expired=True)
        except (MetadataError, OSError, ValueError) as exc:
            raise SubscriberError("the mesh cache does not verify ({}); run: interlock mesh sync".format(exc))
        path = "packs/{}.json".format(pack)
        info = trusted.target(path)
        if info is None:
            raise SubscriberError("pack {!r} is not in the mesh cache; run: interlock mesh sync".format(pack))
        local = self._target_file(info.consistent_name)
        try:
            raw = read_bounded(local, info.length)
            trusted.verify_target(path, raw)
        except (OSError, ValueError, MetadataError) as exc:
            raise SubscriberError("cached pack {!r} does not verify ({}); run: interlock mesh sync".format(
                pack, exc))
        try:
            doc = normalize_pack(json.loads(raw.decode("utf-8")), name=path)
        except (ValueError, PackError) as exc:
            raise SubscriberError("pack {!r} is not a valid pack: {}".format(pack, exc))
        spec = "{}{}@{}".format(SPEC_PREFIX, pack, ring)
        with _state_lock:
            state = self._load_state()
            first_seen = state["first_seen"].setdefault(spec, {})
            try:
                result = apply_ring(doc, ring, now=self._now(), first_seen=first_seen,
                                    monitor_seconds=config.monitor_days * 86400,
                                    ceilings=config.ceilings, source=spec, grants=config.grants, pack=pack)
            except PackError as exc:
                raise SubscriberError("{}: {}".format(self.config_path, exc))
            state["subscriptions"][spec] = {"sha256": info.sha256, "resolved_at": self._now(),
                                            "granted": result.granted, "capped": result.capped}
            if result.next_transition is None:
                state["next_transition"].pop(spec, None)
            else:
                state["next_transition"][spec] = result.next_transition
            self._save_state(state)
        details = {"dropped": result.dropped, "shadowed": result.shadowed,
                   "ceilings": result.ceilings, "next_transition": result.next_transition,
                   "granted": result.granted, "capped": result.capped,
                   "sha256": info.sha256, "spec": spec}
        return result.document, local, details

    # shadow -------------------------------------------------------------------------

    def shadow_sink(self, record: Dict[str, Any]) -> None:
        """Append one shadow decision. Never raises: a logging failure must not
        touch a policy decision, and the caller wraps us anyway."""
        try:
            line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
            os.makedirs(self.dir, exist_ok=True)
            try:
                if os.path.getsize(self.shadow_path) > SHADOW_ROTATE_BYTES:
                    os.replace(self.shadow_path, self.shadow_path + ".1")
            except OSError:
                pass
            with open(self.shadow_path, "a", encoding="utf-8") as fh:
                fh.write(line)
        except Exception:
            pass

    def shadow_summary(self, limit_lines: int = 200000) -> Dict[str, Any]:
        counts: Dict[str, Dict[str, int]] = {}
        total = 0
        if os.path.exists(self.shadow_path):
            with open(self.shadow_path, "r", encoding="utf-8") as fh:
                for index, line in enumerate(fh):
                    if index >= limit_lines:
                        break
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    total += 1
                    by_rule = counts.setdefault(str(rec.get("policy_id")), {})
                    verdict = str(rec.get("verdict"))
                    by_rule[verdict] = by_rule.get(verdict, 0) + 1
        return {"total": total, "by_rule": counts}

    # status --------------------------------------------------------------------------

    def status(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"dir": self.dir, "configured": self.is_configured()}
        if not self.is_configured():
            return out
        config = self.config()
        state = self._load_state()
        out.update({"mirrors": config.mirrors, "ring": config.ring, "monitor_days": config.monitor_days,
                    "last_sync": state.get("last_sync"), "last_error": state.get("last_error"),
                    "subscriptions": state.get("subscriptions", {}),
                    "next_transition": state.get("next_transition", {}),
                    "split_views": state.get("split_views", []),
                    "log": self._saved_checkpoint(),
                    "recorder": config.recorder, "grants": config.grants,
                    "capped": _count_capped(state.get("subscriptions", {}))})
        try:
            trusted = self._trusted(allow_expired=True)
            expires = trusted.expires("timestamp")
            out["root_version"] = trusted.root.version
            out["timestamp_expires"] = iso(expires) if expires else None
            out["timestamp_expired"] = bool(expires and self._now() > expires)
            out["packs"] = {i.path: {"sha256": i.sha256, **i.custom} for i in trusted.all_targets()}
        except (MetadataError, OSError, ValueError) as exc:
            out["cache_error"] = str(exc)
        out["shadow"] = self.shadow_summary()
        return out


def _count_capped(subscriptions: Dict[str, Any]) -> int:
    """Distinct pack rules the last resolve capped to an escalate. A pack
    resolved on two rings counts each rule once."""
    capped = set()
    for spec, sub in subscriptions.items():
        if isinstance(sub, dict) and isinstance(sub.get("capped"), list):
            capped.update((spec.partition("@")[0], str(rule_id)) for rule_id in sub["capped"])
    return len(capped)


# --- the policy loader's entry points ------------------------------------------------


def resolve_extends(spec: str, mesh_dir: Optional[str] = None) -> Tuple[Dict[str, Any], str, str]:
    """Resolve a ``mesh:`` extends spec from the verified cache.

    Returns ``(document, spec, cache_path)``. Raises :class:`SubscriberError`
    (the loader turns it into a :class:`PolicyError`).
    """
    subscriber = Subscriber(mesh_dir)
    config = subscriber.config()
    pack, ring = parse_spec(spec, default_ring=config.ring)
    doc, path, _details = subscriber.resolve(pack, ring)
    return doc, "{}{}@{}".format(SPEC_PREFIX, pack, ring), path


_RECORDER: Optional[Any] = None


def install_recorder(mesh_dir: Optional[str] = None) -> Optional[Any]:
    """Install (or remove) the fingerprint recorder according to the node's
    config, and stamp receipts with the catalog id. Idempotent; returns the
    recorder in force, or None."""
    global _RECORDER
    from ..receipt import add_decision_observer, remove_decision_observer, set_catalog_id
    from .catalog import catalog_id

    subscriber = Subscriber(mesh_dir)
    try:
        config = subscriber.config()
    except SubscriberError:
        return None
    set_catalog_id(catalog_id())
    if _RECORDER is not None:
        remove_decision_observer(_RECORDER)
        _RECORDER = None
    settings = config.recorder
    if not settings.get("enabled"):
        return None
    from .fingerprint import Recorder
    _RECORDER = Recorder(subscriber.dir, alpha=float(settings.get("alpha", 1.5)),
                         sample_rules=settings.get("sample_rules", []))
    add_decision_observer(_RECORDER)
    return _RECORDER


def watch_info(specs: Sequence[str], mesh_dir: Optional[str] = None) -> Tuple[List[str], Optional[float], Callable[[Dict[str, Any]], None]]:
    """For a policy that resolved ``specs``: the files whose change should
    trigger a reload (``config.json`` too, so a new grant takes effect), the
    wall-clock time the next shadow rule leaves its window, and the shadow sink
    to record would-be decisions with."""
    subscriber = Subscriber(mesh_dir)
    state = subscriber._load_state()
    reload_at: Optional[float] = None
    for spec in specs:
        value = state.get("next_transition", {}).get(spec)
        if isinstance(value, (int, float)):
            reload_at = float(value) if reload_at is None else min(reload_at, float(value))
    files = [subscriber.targets_metadata_path, subscriber.state_path, subscriber.config_path]
    return files, reload_at, subscriber.shadow_sink
