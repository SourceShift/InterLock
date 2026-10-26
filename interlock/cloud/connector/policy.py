"""Host-side policy distribution: verify, fetch, load and swap (C5).

The plane never pushes.  A host long-polls a *minimal* hint (version and kill
epoch), fetches the signed manifest when the hint changes, verifies it against
the policy public key pinned at enrollment, then fetches the artifact by the
sha256 the manifest named.  Hints are untrusted: they only decide whether to
look, never what to accept.

Ordering is the safety property:

1. verify the manifest (signature, target, expiry, strictly greater version)
2. persist ``highest_version`` and ``last_manifest_id`` **before** fetching
   bytes, outside the artifact directory, so a plane restored from backup
   cannot roll this host back even if the process dies mid-download
3. fetch the bytes, require the exact length and sha256
4. write ``artifacts/<sha>.json.tmp`` with ``fsync`` and rename
5. ``load_artifact`` the candidate (this is where the rules module is
   imported) before touching ``active.json``
6. swap ``active.json`` atomically, retaining the previous artifact and
   writing ``active.json.prev``

Any failure keeps the last-known-good artifact.  Expiry does too: the host
keeps running what it verified, records ``expired_since``, raises an alarm
after fifteen minutes and exposes a six-hour grace window.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from ... import __version__ as AGENT_VERSION
from ...policy.artifact import ACTIVE_POINTER, canonical_bytes, load_artifact
from ..policy.manifest import verify_kill, verify_manifest
from .config import CloudHome, redact
from .transport import TransportError

#: A host keeps serving a verified artifact this long after expiry while it
#: alarms; after the grace window the operator must act.
EXPIRY_GRACE_SECONDS = 6 * 60 * 60

#: How long after expiry the status starts alarming.
EXPIRY_ALARM_SECONDS = 15 * 60

#: The hints poll's bound, matching the plane's.
MAX_WAIT_SECONDS = 25

DEFAULT_RING = "stable"


class PolicyDistributor:
    """Verify, fetch and atomically activate signed policy artifacts."""

    def __init__(self, home: Any, transport: Any, clock: Any = time.time, *,
                 sleep: Any = None, timeout: float = 30,
                 ring: Optional[str] = None) -> None:
        self.home = home if isinstance(home, CloudHome) else CloudHome(home)
        self.transport = transport
        self.clock = clock
        self.sleep = sleep
        self.timeout = timeout
        self._ring = ring
        self._config: Optional[Dict[str, Any]] = None
        self._state: Optional[Dict[str, Any]] = None

    # -- paths and config ----------------------------------------------
    @property
    def config(self) -> Dict[str, Any]:
        if self._config is None:
            self._config = self.home.document
        return self._config

    def _resolve(self, value: str) -> Path:
        path = Path(value).expanduser()
        return path if path.is_absolute() else self.home.root / path

    @property
    def ring(self) -> str:
        if self._ring:
            return str(self._ring)
        return str(self.config.get("ring") or DEFAULT_RING)

    @property
    def artifacts_dir(self) -> Path:
        return self.home.root / "artifacts"

    @property
    def active_path(self) -> Path:
        return self.artifacts_dir / ACTIVE_POINTER

    @property
    def previous_path(self) -> Path:
        return self.artifacts_dir / (ACTIVE_POINTER + ".prev")

    @property
    def state_path(self) -> Path:
        config = self.config
        directory = self._resolve(str(config.get("state_dir") or "state"))
        return directory / "state.json"

    def _public_key(self) -> bytes:
        keys = self.config.get("plane_public_keys") or {}
        raw = keys.get("policy") if isinstance(keys, Mapping) else None
        if not isinstance(raw, str) or not raw:
            return b""
        try:
            return bytes.fromhex(raw)
        except ValueError:
            return b""

    # -- persistence ----------------------------------------------------
    def _load_state(self) -> Dict[str, Any]:
        if self._state is None:
            state: Dict[str, Any] = {
                "highest_version": 0,
                "manifest_version": 0,
                "last_manifest_id": None,
                "artifact_sha256": None,
                "epoch": None,
                "mode": None,
                "expires_at": None,
                "issued_at": None,
                "last_swap": None,
                "expired_since": None,
                "kill_epoch": 0,
                "kill": None,
                "kill_active": False,
                "refusals": {},
                "last_error": None,
                "last_hint": None,
            }
            try:
                document = json.loads(self.state_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                document = None
            if isinstance(document, dict):
                state.update(document)
            if not isinstance(state.get("refusals"), dict):
                state["refusals"] = {}
            self._state = state
        return dict(self._state)

    def _save_state(self, state: Mapping[str, Any]) -> None:
        self._state = dict(state)
        path = self.state_path
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = json.dumps(self._state, sort_keys=True).encode("utf-8")
        fd, tmp_name = tempfile.mkstemp(
            dir=str(path.parent), prefix=".state.", suffix=".tmp")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, str(path))
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def _refuse(self, state: Dict[str, Any], code: str) -> None:
        refusals = dict(state.get("refusals") or {})
        refusals[code] = int(refusals.get(code, 0)) + 1
        state["refusals"] = refusals

    # -- HTTP -----------------------------------------------------------
    def _headers(self) -> Dict[str, str]:
        config = self.config
        return {
            "accept": "application/json",
            "authorization": "Bearer " + str(config.get("agent_key") or ""),
            "x-interlock-host": str(config.get("host_id") or ""),
            "x-interlock-org": str(config.get("org_id") or ""),
            "x-interlock-version": str(AGENT_VERSION),
        }

    def _get(self, path: str, *, wait: int = MAX_WAIT_SECONDS) -> tuple:
        return self.transport.request(
            "GET", path, None, headers=self._headers(), timeout=self.timeout)

    # -- atomic pointer -------------------------------------------------
    @staticmethod
    def _write_atomic(path: Path, payload: bytes) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            dir=str(path.parent), prefix="." + path.name + ".", suffix=".tmp")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, str(path))
            try:
                dir_fd = os.open(str(path.parent), os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def _swap(self, state: Dict[str, Any], sha256: str, epoch: str,
              version: int, mode: str, rules_module: Optional[str]) -> None:
        pointer = {
            "sha256": sha256,
            "version": int(version),
            "epoch": epoch,
            "mode": mode,
            "rules_module": rules_module,
        }
        current = None
        try:
            current = self.active_path.read_text(encoding="utf-8")
        except OSError:
            current = None
        if current is not None:
            # Retain the pointer we are replacing; the artifact file it names
            # stays on disk too, so a swap retains two generations.
            self._write_atomic(self.previous_path, current.encode("utf-8"))
        self._write_atomic(self.active_path, canonical_bytes(pointer))
        state["artifact_sha256"] = sha256
        state["epoch"] = epoch
        state["manifest_version"] = int(version)
        state["mode"] = mode
        state["last_swap"] = float(self.clock())

    # -- expiry ---------------------------------------------------------
    def _check_expiry(self, state: Dict[str, Any], now: float) -> None:
        expires = state.get("expires_at")
        if expires is None:
            return
        if now > float(expires):
            if state.get("expired_since") is None:
                state["expired_since"] = now
        else:
            state["expired_since"] = None

    def _alarm(self, state: Dict[str, Any], now: float) -> bool:
        since = state.get("expired_since")
        return since is not None and now - float(since) >= EXPIRY_ALARM_SECONDS

    def _grace_until(self, state: Dict[str, Any]) -> Optional[float]:
        expires = state.get("expires_at")
        if expires is None:
            return None
        return float(expires) + EXPIRY_GRACE_SECONDS

    # -- one poll -------------------------------------------------------
    def poll_once(self) -> Dict[str, Any]:
        """One hint -> manifest -> artifact -> swap cycle; never raises."""
        state = self._load_state()
        now = float(self.clock())
        self._check_expiry(state, now)
        try:
            status, _headers, data = self._get(
                "/v1/hints?since={}&kill={}&ring={}&wait={}".format(
                    int(state.get("manifest_version") or 0),
                    int(state.get("kill_epoch") or 0),
                    self.ring, MAX_WAIT_SECONDS),
            )
            if status != 200:
                state["last_error"] = "hints_{}".format(status)
                self._save_state(state)
                return self._result(state, False)
            hint = json.loads(data.decode("utf-8")) if data else {}
            if not isinstance(hint, dict):
                hint = {}
        except (TransportError, OSError, ValueError) as exc:
            state["last_error"] = redact(str(exc))
            self._save_state(state)
            return self._result(state, False)

        state["last_hint"] = {
            "version": hint.get("version"),
            "kill_epoch": hint.get("kill_epoch"),
        }
        hint_version = _integer(hint.get("version"))
        hint_kill = _integer(hint.get("kill_epoch"))
        reachable = True
        if hint_version > int(state.get("manifest_version") or 0):
            reachable = self._poll_manifest(state, now) and reachable
        if hint_kill > int(state.get("kill_epoch") or 0):
            reachable = self._poll_kills(state, hint_kill) and reachable
        self._check_expiry(state, now)
        if reachable:
            # A completed hint cycle clears a previous transport error. A
            # refusal is an answer too: the plane was reached, it was wrong.
            state["last_error"] = None
        self._save_state(state)
        return self._result(state, True)

    def _poll_manifest(self, state: Dict[str, Any], now: float) -> bool:
        """Fetch and apply one manifest; False only when the plane was unreachable."""
        try:
            status, _headers, data = self._get(
                "/v1/manifest?ring={}".format(self.ring), wait=0)
        except (TransportError, OSError) as exc:
            state["last_error"] = redact(str(exc))
            return False
        if status != 200:
            state["last_error"] = "manifest_{}".format(status)
            return False
        try:
            manifest = json.loads(data.decode("utf-8")) if data else {}
        except (UnicodeDecodeError, ValueError):
            self._refuse(state, "manifest_invalid")
            return True
        if not isinstance(manifest, dict):
            self._refuse(state, "manifest_invalid")
            return True
        failure = verify_manifest(
            manifest, self._public_key(),
            org_id=str(self.config.get("org_id") or "") or None,
            host_id=str(self.config.get("host_id") or "") or None,
            ring=self.ring,
            now=now,
            min_version=int(state.get("highest_version") or 0),
            agent_version=str(AGENT_VERSION),
        )
        if failure is not None:
            self._refuse(state, failure)
            if failure == "expired":
                state["expires_at"] = float(manifest.get("expires_at") or 0.0)
            return True
        artifact = manifest.get("artifact") or {}
        sha = artifact.get("sha256")
        size = _integer(artifact.get("size"))
        version = _integer(manifest.get("version"))
        # Persist the acceptance before fetching a byte: a crash after this
        # point must not let a restored, older plane re-offer a lower version.
        state["highest_version"] = version
        state["manifest_version"] = version
        state["last_manifest_id"] = manifest.get("manifest_id")
        state["expires_at"] = float(manifest.get("expires_at") or 0.0)
        state["issued_at"] = float(manifest.get("issued_at") or 0.0)
        state["epoch"] = manifest.get("epoch")
        state["mode"] = manifest.get("mode")
        self._save_state(state)

        try:
            fetch_status, _h, body = self._get(
                "/v1/artifacts/{}".format(sha), wait=0)
        except (TransportError, OSError) as exc:
            state["last_error"] = redact(str(exc))
            return False
        if fetch_status != 200:
            self._refuse(state, "artifact_unavailable")
            return True
        raw = bytes(body or b"")
        if len(raw) != size:
            self._refuse(state, "artifact_size")
            return True
        if hashlib.sha256(raw).hexdigest() != sha:
            self._refuse(state, "artifact_sha256")
            return True

        target = self.artifacts_dir / "{}.json".format(sha)
        try:
            self.artifacts_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(
                dir=str(self.artifacts_dir), prefix=".{}.json.".format(sha),
                suffix=".tmp")
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp_name, str(target))
                try:
                    dir_fd = os.open(str(self.artifacts_dir), os.O_RDONLY)
                    try:
                        os.fsync(dir_fd)
                    finally:
                        os.close(dir_fd)
                except OSError:
                    pass
            except BaseException:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
                raise
        except OSError as exc:
            self._refuse(state, "artifact_write")
            state["last_error"] = redact(str(exc))
            return False

        # Load before swapping: a bad module reference must never replace a
        # working active artifact. This is the only rules-module import.
        try:
            loaded = load_artifact(raw)
        except Exception as exc:  # noqa: BLE001 - refusal path
            self._refuse(state, "artifact_invalid")
            state["last_error"] = redact(str(exc))
            return True

        self._swap(
            state, sha, str(manifest.get("epoch") or ""), version,
            str(manifest.get("mode") or ""), loaded.rules_module,
        )
        self._save_state(state)
        return True

    def _poll_kills(self, state: Dict[str, Any], hint_kill: int) -> bool:
        since = int(state.get("kill_epoch") or 0)
        try:
            status, _headers, data = self._get(
                "/v1/kills?since={}&ring={}".format(since, self.ring), wait=0)
        except (TransportError, OSError) as exc:
            state["last_error"] = redact(str(exc))
            return False
        if status != 200:
            state["last_error"] = "kills_{}".format(status)
            return False
        try:
            payload = json.loads(data.decode("utf-8")) if data else {}
        except (UnicodeDecodeError, ValueError):
            self._refuse(state, "kills_invalid")
            return True
        kills = payload.get("kills") if isinstance(payload, dict) else None
        if not isinstance(kills, list):
            kills = []
        newest = since
        for document in kills:
            if not isinstance(document, dict):
                self._refuse(state, "kill_invalid")
                continue
            failure = verify_kill(
                document, self._public_key(),
                org_id=str(self.config.get("org_id") or "") or None,
                host_id=str(self.config.get("host_id") or "") or None,
                ring=self.ring,
            )
            if failure is not None:
                self._refuse(state, "kill_" + failure)
                continue
            # A verified kill is honoured regardless of manifest freshness,
            # which is the point of a kill switch. Nothing here clears it.
            state["kill"] = document
            state["kill_active"] = True
        server_epoch = payload.get("kill_epoch") if isinstance(payload, dict) else None
        if isinstance(server_epoch, int) and not isinstance(server_epoch, bool):
            newest = max(newest, server_epoch)
        state["kill_epoch"] = max(newest, hint_kill)
        return True

    # -- results --------------------------------------------------------
    def _result(self, state: Dict[str, Any], ok: bool) -> Dict[str, Any]:
        return {
            "ok": bool(ok),
            "manifest_version": int(state.get("manifest_version") or 0),
            "artifact_sha256": state.get("artifact_sha256"),
            "epoch": state.get("epoch"),
            "mode": state.get("mode"),
            "last_swap": state.get("last_swap"),
            "expired_since": state.get("expired_since"),
            "kill_active": bool(state.get("kill_active")),
            "refusals": dict(state.get("refusals") or {}),
            "last_error": state.get("last_error"),
        }

    def status(self) -> Dict[str, Any]:
        """Distribution status for the connector CLI; never the agent key."""
        state = self._load_state()
        now = float(self.clock())
        self._check_expiry(state, now)
        status = self._result(state, True)
        status.update({
            "active": str(self.active_path),
            "artifacts": str(self.artifacts_dir),
            "ring": self.ring,
            "highest_version": int(state.get("highest_version") or 0),
            "last_manifest_id": state.get("last_manifest_id"),
            "expired": state.get("expired_since") is not None,
            "alarm": self._alarm(state, now),
            "grace_until": self._grace_until(state),
            "kill": state.get("kill"),
            "kill_epoch": int(state.get("kill_epoch") or 0),
        })
        return redact(status)

    def active_policy(self) -> Any:
        """Load the active artifact once for a process that will enforce it."""
        return load_artifact(self.active_path)


def _integer(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


__all__ = [
    "DEFAULT_RING",
    "EXPIRY_ALARM_SECONDS",
    "EXPIRY_GRACE_SECONDS",
    "MAX_WAIT_SECONDS",
    "PolicyDistributor",
]
