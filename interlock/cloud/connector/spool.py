"""A bounded on-disk outbound spool (FR-011, FR-074).

One gzip file per batch, named ``<kind>-<seq:020d>-<host>~<sensor>.json.gz``.
Host and sensor are sanitised to ``[A-Za-z0-9_.-]``, so ``~`` cannot occur
inside either field and a hyphenated host is recovered unambiguously from an
orphan file. ``seq`` is monotonic per ``(host, sensor)`` and persisted in
``state.json`` with an fsync before the batch is considered queued.

The cap is **256 MiB of payload**, not of gzip output: the plane and the
operator care how much data is waiting, and a highly compressible batch must
not sneak past the bound. ``bytes`` reports that same logical total.

Eviction scans oldest-first and drops **observability before security**: an
audit/security batch is not discarded while any observability batch remains,
even when a single incoming observability batch is itself over the cap. Every
drop increments ``dropped_batches`` and ``dropped_by_kind``, which the status
surface reports.

A batch file is removed only after the plane acknowledges it; a partial
``.tmp`` file is ignored on startup and deleted.
"""
from __future__ import annotations

import gzip
import json
import os
import re
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

#: FR-011: the spool is capped at 256 MiB by default.
DEFAULT_CAP_BYTES = 256 * 1024 * 1024

#: Higher-priority kinds are never dropped while a lower one remains.
KIND_PRIORITY = ("security", "observability")
KINDS = frozenset(KIND_PRIORITY)
_EVICT_ORDER = ("observability", "security")

_STATE_NAME = "state.json"
_TMP_SUFFIX = ".tmp"
_SAFE = re.compile(r"[^A-Za-z0-9_.-]+")
#: Not in the sanitised alphabet, so host and sensor can never be confused.
_FIELD_SEP = "~"
_FILENAME = re.compile(
    r"^(security|observability)-(\d{20})-(.+)$"
)


class SpoolError(ValueError):
    """A batch or spool operation is invalid."""


@dataclass(frozen=True)
class Batch:
    """One queued batch; ``size`` is the uncompressed payload length."""

    path: Path
    kind: str
    seq: int
    host: str
    sensor: str
    size: int
    created: float

    @property
    def name(self) -> str:
        return self.path.name


def _sanitize(value: str, *, default: str = "default") -> str:
    text = _SAFE.sub("_", str(value or "")).strip("._-")
    return (text or default)[:64]


def _atomic_bytes(path: Path, payload: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent),
                                    prefix="." + path.name + ".",
                                    suffix=_TMP_SUFFIX)
    try:
        os.fchmod(fd, mode)
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


class Spool:
    """A directory of gzip batches with a payload cap and a drop order."""

    def __init__(self, directory: Union[str, Path], *,
                 cap_bytes: int = DEFAULT_CAP_BYTES,
                 clock: Any = time.time) -> None:
        if int(cap_bytes) <= 0:
            raise SpoolError("cap_bytes must be positive")
        self.directory = Path(directory)
        self.cap_bytes = int(cap_bytes)
        self.clock = clock
        self.state_path = self.directory / _STATE_NAME
        self._lock = threading.RLock()
        self._seqs: Dict[str, Dict[str, int]] = {}
        #: Sequences handed out by :meth:`next_sequence` but not yet framed as
        #: a batch. The sensor ring reserves a sequence before it holds the
        #: entry, so the drain must accept that exact value once.
        self._reserved: set = set()
        self._batches: Dict[str, Dict[str, Any]] = {}
        self.dropped_batches = 0
        self.dropped_by_kind: Dict[str, int] = {kind: 0 for kind in KIND_PRIORITY}
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._clean_tmp()
        self._load_state()
        self._reconcile()

    # -- state ----------------------------------------------------------
    def _clean_tmp(self) -> None:
        for path in self.directory.glob("*" + _TMP_SUFFIX):
            try:
                path.unlink()
            except OSError:
                pass

    def _load_state(self) -> None:
        if not self.state_path.is_file():
            return
        try:
            doc = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(doc, dict):
            return
        seqs = doc.get("seqs")
        if isinstance(seqs, dict):
            for host, sensors in seqs.items():
                if not isinstance(sensors, dict):
                    continue
                self._seqs[str(host)] = {
                    str(sensor): int(value)
                    for sensor, value in sensors.items()
                    if isinstance(value, int) and value >= 0
                }
        batches = doc.get("batches")
        if isinstance(batches, dict):
            for name, meta in batches.items():
                if isinstance(meta, dict):
                    self._batches[str(name)] = dict(meta)
        self.dropped_batches = int(doc.get("dropped_batches") or 0)
        dropped = doc.get("dropped_by_kind")
        if isinstance(dropped, dict):
            for kind in KIND_PRIORITY:
                self.dropped_by_kind[kind] = int(dropped.get(kind) or 0)

    def _save_state(self) -> None:
        doc = {
            "seqs": self._seqs,
            "batches": self._batches,
            "dropped_batches": self.dropped_batches,
            "dropped_by_kind": self.dropped_by_kind,
        }
        _atomic_bytes(self.state_path,
                      json.dumps(doc, sort_keys=True).encode("utf-8"))

    # -- files ----------------------------------------------------------
    def _next_seq(self, host: str, sensor: str) -> int:
        sensors = self._seqs.setdefault(host, {})
        value = int(sensors.get(sensor, 0)) + 1
        sensors[sensor] = value
        return value

    def next_sequence(self, host: str, sensor: str) -> int:
        """Reserve the next durable sequence for ``(host, sensor)``.

        The counter is persisted (and fsynced) **before** the caller shows the
        entry anywhere, so a restart cannot regress or reuse it. The reserved
        value must be handed to :meth:`add` with ``seq=``; until then the spool
        accepts it even though the counter has already advanced.
        """
        safe_host = _sanitize(host)
        safe_sensor = _sanitize(sensor)
        with self._lock:
            seq = self._next_seq(safe_host, safe_sensor)
            self._reserved.add((safe_host, safe_sensor, seq))
            try:
                self._save_state()
            except Exception:
                self._seqs[safe_host][safe_sensor] = seq - 1
                self._reserved.discard((safe_host, safe_sensor, seq))
                raise
            return seq

    def release_sequence(self, host: str, sensor: str, seq: int) -> None:
        """Forget a reservation whose entry will never become a batch."""
        key = (_sanitize(host), _sanitize(sensor), int(seq))
        with self._lock:
            self._reserved.discard(key)

    def _parse_name(self, name: str) -> Optional[Dict[str, Any]]:
        match = _FILENAME.match(name)
        if match is None:
            return None
        kind, seq, rest = match.groups()
        if not rest.endswith(".json.gz"):
            return None
        rest = rest[:-len(".json.gz")]
        host, sep, sensor = rest.partition(_FIELD_SEP)
        if not sep or not host:
            return None
        return {"kind": kind, "seq": int(seq), "host": host,
                "sensor": sensor or "default"}

    def _logical_size(self, path: Path) -> int:
        try:
            return len(gzip.decompress(path.read_bytes()))
        except (OSError, EOFError, ValueError):
            try:
                return path.stat().st_size
            except OSError:
                return 0

    def _reconcile(self) -> None:
        """Drop manifest rows whose file vanished; adopt orphan batch files."""
        with self._lock:
            changed = False
            present = {path.name for path in self.directory.glob("*.json.gz")}
            for name in list(self._batches):
                if name not in present:
                    self._batches.pop(name, None)
                    changed = True
            for name in present - set(self._batches):
                parsed = self._parse_name(name)
                if parsed is None:
                    continue
                path = self.directory / name
                try:
                    created = path.stat().st_mtime
                except OSError:
                    continue
                size = self._logical_size(path)
                self._batches[name] = dict(parsed, size=size, created=created)
                changed = True
            # Never reuse a seq whose file is still on disk.
            for meta in self._batches.values():
                host = str(meta.get("host", "default"))
                sensor = str(meta.get("sensor", "default"))
                seq = int(meta.get("seq", 0))
                sensors = self._seqs.setdefault(host, {})
                if seq > int(sensors.get(sensor, 0)):
                    sensors[sensor] = seq
                    changed = True
            if changed or not self.state_path.exists():
                self._save_state()

    def _batch(self, name: str, meta: Dict[str, Any]) -> Batch:
        return Batch(
            path=self.directory / name,
            kind=str(meta.get("kind", "observability")),
            seq=int(meta.get("seq", 0)),
            host=str(meta.get("host", "default")),
            sensor=str(meta.get("sensor", "default")),
            size=int(meta.get("size", 0)),
            created=float(meta.get("created", 0.0)),
        )

    def batches(self) -> List[Batch]:
        """All live batches, oldest first."""
        with self._lock:
            live = []
            for name, meta in self._batches.items():
                batch = self._batch(name, meta)
                if batch.path.is_file():
                    live.append(batch)
            return sorted(live, key=lambda batch: (batch.created, batch.seq,
                                                   batch.name))

    def peek(self, limit: int = 10) -> List[Batch]:
        return self.batches()[: max(0, int(limit))]

    # -- accounting -----------------------------------------------------
    @property
    def bytes(self) -> int:
        """Payload bytes queued (uncompressed), the quantity the cap bounds."""
        return sum(batch.size for batch in self.batches())

    @property
    def count(self) -> int:
        return len(self.batches())

    # -- mutation -------------------------------------------------------
    def add(self, kind: str, data: bytes, *, host: str,
            sensor: str, seq: Optional[int] = None) -> Batch:
        """Queue one batch, then enforce the cap (FR-011).

        ``seq`` is normally allocated here. A producer that must know the
        sequence before the payload is complete (the sensor ring) calls
        :meth:`next_sequence` first and passes that exact value; an already
        used sequence is refused rather than reused.
        """
        if kind not in KINDS:
            raise SpoolError("unknown batch kind: {!r}".format(kind))
        if not isinstance(data, (bytes, bytearray)):
            raise SpoolError("batch data must be bytes")
        payload = bytes(data)
        safe_host = _sanitize(host)
        safe_sensor = _sanitize(sensor)
        with self._lock:
            reserved = None
            if seq is None:
                seq = self._next_seq(safe_host, safe_sensor)
            else:
                if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
                    raise SpoolError("seq must be a positive integer")
                reserved = (safe_host, safe_sensor, seq)
                current = int(self._seqs.get(safe_host, {}).get(safe_sensor, 0))
                if seq <= current and reserved not in self._reserved:
                    raise SpoolError(
                        "sequence {} was already used for {}/{}".format(
                            seq, safe_host, safe_sensor))
            name = "{}-{:020d}-{}{}{}.json.gz".format(
                kind, seq, safe_host, _FIELD_SEP, safe_sensor)
            path = self.directory / name
            if path.exists():
                raise SpoolError("batch already exists: {}".format(name))
            if seq > int(self._seqs.setdefault(safe_host, {}).get(safe_sensor, 0)):
                self._seqs[safe_host][safe_sensor] = seq
            body = gzip.compress(payload, compresslevel=6)
            _atomic_bytes(path, body)
            created = float(self.clock())
            self._batches[name] = {
                "kind": kind, "seq": seq, "host": host, "sensor": sensor,
                "size": len(payload), "created": created,
            }
            if reserved is not None:
                self._reserved.discard(reserved)
            self._save_state()
            # Capture the record before eviction: an over-cap batch is still
            # returned to its caller so the loss can be observed and counted.
            batch = self._batch(name, self._batches[name])
            self._enforce_cap()
            return batch

    def remove(self, batch: Union[Batch, str, Path]) -> bool:
        """Delete a batch after a 2xx acknowledgement."""
        path = batch.path if isinstance(batch, Batch) else Path(batch)
        with self._lock:
            removed = False
            try:
                path.unlink()
                removed = True
            except FileNotFoundError:
                pass
            if self._batches.pop(path.name, None) is not None:
                removed = True
                self._save_state()
            return removed

    def acknowledge(self, batch: Union[Batch, str, Path]) -> bool:
        """Alias for :meth:`remove`; the connector acks a batch this way."""
        return self.remove(batch)

    def _enforce_cap(self) -> None:
        """Drop oldest observability first; never security while one remains."""
        total = self.bytes
        if total <= self.cap_bytes:
            self._save_state()
            return
        changed = False
        for kind in _EVICT_ORDER:
            candidates = sorted(
                (batch for batch in self.batches() if batch.kind == kind),
                key=lambda batch: (batch.created, batch.seq, batch.name),
            )
            for batch in candidates:
                if total <= self.cap_bytes:
                    break
                try:
                    batch.path.unlink()
                except FileNotFoundError:
                    pass
                self._batches.pop(batch.name, None)
                total -= batch.size
                self.dropped_batches += 1
                self.dropped_by_kind[kind] = \
                    self.dropped_by_kind.get(kind, 0) + 1
                changed = True
            if total <= self.cap_bytes:
                break
        if changed:
            self._save_state()


__all__ = [
    "Batch",
    "DEFAULT_CAP_BYTES",
    "KINDS",
    "KIND_PRIORITY",
    "Spool",
    "SpoolError",
]
