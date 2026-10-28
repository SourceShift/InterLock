"""A bounded in-memory ring between a sensor and the disk spool (FR-011, FR-074).

The ring holds telemetry that has not yet reached the spool. It is bounded in
**payload bytes**, not entry count, and eviction follows exactly the spool's
order: oldest observability first, security last, via ``KIND_PRIORITY`` from
:mod:`interlock.cloud.connector.spool`. There is one priority vocabulary and
one ``(host, sensor, sequence)`` identity for both halves.

``put`` never blocks and never raises. A full ring evicts, counts the drop and
records a ``(host, sensor, first_missing)`` gap, so a consumer can tell a drop
from a quiet sensor. Sequence allocation is persisted with an fsync before the
entry becomes visible; a connector can instead borrow the spool's counter, so
the ring and the batches it frames share one durable sequence authority.

``drain_into`` never holds the ring lock across spool I/O: it snapshots the
entries under the lock, writes batches, then removes only what landed.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from interlock.cloud.connector.spool import (
    KIND_PRIORITY,
    KINDS,
    _atomic_bytes,
)

#: The ring is a hand-off buffer, not a history: a few MiB bounds a burst
#: without competing with the guarded process's own working set.
DEFAULT_RING_BYTES = 8 * 1024 * 1024

_STATE_NAME = "state.json"
_EVICT_ORDER = tuple(reversed(KIND_PRIORITY))

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Entry:
    """One queued sensor event; ``payload`` is the quantity the cap bounds."""

    host: str
    sensor: str
    sequence: int
    kind: str
    payload: bytes
    created: float

    @property
    def size(self) -> int:
        return len(self.payload)


class Ring:
    """A byte-bounded FIFO with the spool's drop order and sequence keys."""

    def __init__(self, directory: Optional[Union[str, Path]] = None, *,
                 capacity_bytes: int = DEFAULT_RING_BYTES,
                 clock: Any = time.time,
                 sequence_source: Optional[Callable[[str, str], int]] = None,
                 sequence_release: Optional[
                     Callable[[str, str, int], None]] = None) -> None:
        if int(capacity_bytes) <= 0:
            raise ValueError("capacity_bytes must be positive")
        self.directory = Path(directory) if directory is not None else None
        self.capacity_bytes = int(capacity_bytes)
        self.clock = clock
        self.state_path = (self.directory / _STATE_NAME
                           if self.directory is not None else None)
        # The data lock guards entries and counters. It is never held across
        # sequence persistence or spool I/O; ``_put_lock`` serialises sequence
        # allocation so per-(host, sensor) order matches insertion order.
        self._lock = threading.RLock()
        self._put_lock = threading.Lock()
        self._entries: List[Entry] = []
        self._bytes = 0
        self._seqs: Dict[str, Dict[str, int]] = {}
        self._sequence_source = sequence_source
        self._sequence_release = sequence_release
        self.dropped_entries = 0
        self.dropped_by_kind: Dict[str, int] = {
            kind: 0 for kind in KIND_PRIORITY}
        self._gaps: Dict[tuple, int] = {}
        if self.directory is not None:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._load_state()

    # -- state ----------------------------------------------------------
    def _load_state(self) -> None:
        assert self.state_path is not None
        if not self.state_path.is_file():
            return
        try:
            doc = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(doc, dict):
            return
        if self._sequence_source is None:
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
        self.dropped_entries = int(doc.get("dropped_entries") or 0)
        dropped = doc.get("dropped_by_kind")
        if isinstance(dropped, dict):
            for kind in KIND_PRIORITY:
                self.dropped_by_kind[kind] = int(dropped.get(kind) or 0)
        gaps = doc.get("gaps")
        if isinstance(gaps, list):
            for gap in gaps:
                if not isinstance(gap, dict):
                    continue
                host = str(gap.get("host") or "")
                sensor = str(gap.get("sensor") or "")
                first = int(gap.get("first_missing") or 0)
                if host and sensor and first > 0:
                    self._gaps[(host, sensor)] = first

    def _save_state(self) -> None:
        if self.state_path is None:
            return
        with self._lock:
            doc = {
                "seqs": (self._seqs if self._sequence_source is None else {}),
                "dropped_entries": self.dropped_entries,
                "dropped_by_kind": self.dropped_by_kind,
                "gaps": [
                    {"host": host, "sensor": sensor,
                     "first_missing": first}
                    for (host, sensor), first in sorted(self._gaps.items())
                ],
            }
        _atomic_bytes(self.state_path,
                      json.dumps(doc, sort_keys=True).encode("utf-8"))

    def _allocate(self, host: str, sensor: str) -> int:
        if self._sequence_source is not None:
            value = self._sequence_source(host, sensor)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError("sequence_source returned an invalid sequence")
            return value
        sensors = self._seqs.setdefault(host, {})
        previous = int(sensors.get(sensor, 0))
        sensors[sensor] = previous + 1
        try:
            self._save_state()
        except Exception:
            # Not visible means not consumed: leave the counter as it was so a
            # restart cannot reuse a sequence no entry ever carried.
            sensors[sensor] = previous
            raise
        return previous + 1

    def _release(self, host: str, sensor: str, sequence: int) -> None:
        if self._sequence_release is None:
            return
        try:
            self._sequence_release(host, sensor, sequence)
        except Exception:
            _log.exception("sensor ring: sequence release failed")

    # -- accounting -----------------------------------------------------
    @property
    def bytes(self) -> int:
        with self._lock:
            return self._bytes

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._entries)

    def entries(self) -> List[Entry]:
        """A snapshot, oldest first."""
        with self._lock:
            return list(self._entries)

    def status(self) -> Dict[str, Any]:
        """Counters and gap markers only: never tenant or payload content."""
        with self._lock:
            return {
                "capacity_bytes": self.capacity_bytes,
                "bytes": self._bytes,
                "dropped_entries": self.dropped_entries,
                "dropped_by_kind": dict(self.dropped_by_kind),
                "gaps": [
                    {"host": host, "sensor": sensor,
                     "first_missing": first}
                    for (host, sensor), first in sorted(self._gaps.items())
                ],
            }

    # -- mutation -------------------------------------------------------
    def put(self, kind: str, data: Any, *, host: str,
            sensor: str) -> Optional[Entry]:
        """Queue one event; return it, or ``None`` when it was dropped.

        Never raises: a full ring, an unwritable state file or a sequence
        source failure must not reach the guarded call.
        """
        try:
            if kind not in KINDS:
                raise ValueError("unknown sensor kind: {!r}".format(kind))
            if not isinstance(data, (bytes, bytearray)):
                raise ValueError("sensor data must be bytes")
            payload = bytes(data)
            host = str(host)
            sensor = str(sensor)
            with self._put_lock:
                sequence = self._allocate(host, sensor)
                entry = Entry(host=host, sensor=sensor, sequence=sequence,
                              kind=kind, payload=payload,
                              created=float(self.clock()))
                dropped = []
                with self._lock:
                    self._entries.append(entry)
                    self._bytes += len(payload)
                    dropped = self._enforce_cap_locked()
                if dropped:
                    for victim in dropped:
                        self._release(victim.host, victim.sensor,
                                      victim.sequence)
                    try:
                        self._save_state()
                    except Exception:
                        _log.exception("sensor ring: counter state save failed")
                return None if entry in dropped else entry
        except Exception:
            _log.exception("sensor ring: put failed")
            return None

    def _enforce_cap_locked(self) -> List[Entry]:
        dropped: List[Entry] = []
        while self._bytes > self.capacity_bytes and self._entries:
            index = None
            for kind in _EVICT_ORDER:
                for position, entry in enumerate(self._entries):
                    if entry.kind == kind:
                        index = position
                        break
                if index is not None:
                    break
            if index is None:
                break
            victim = self._entries.pop(index)
            self._bytes -= len(victim.payload)
            self.dropped_entries += 1
            self.dropped_by_kind[victim.kind] = \
                self.dropped_by_kind.get(victim.kind, 0) + 1
            key = (victim.host, victim.sensor)
            previous = self._gaps.get(key)
            if previous is None or victim.sequence < previous:
                self._gaps[key] = victim.sequence
            dropped.append(victim)
        return dropped

    def drain(self, limit: Optional[int] = None) -> List[Entry]:
        """Remove and return entries oldest first."""
        with self._lock:
            count = len(self._entries) if limit is None \
                else max(0, int(limit))
            chosen = self._entries[:count]
            del self._entries[:count]
            self._bytes -= sum(len(entry.payload) for entry in chosen)
            return chosen

    def drain_into(self, spool: Any, limit: Optional[int] = None) -> List[Any]:
        """Frame entries as spool batches, removing each only after it lands.

        The ring lock is held only for the snapshot and the removal; the spool
        write happens outside it. A failure stops the drain so per-sensor
        order is preserved, and leaves the unlanded entries in place.
        """
        with self._lock:
            count = len(self._entries) if limit is None \
                else max(0, int(limit))
            snapshot = list(self._entries[:count])
        batches = []
        for entry in snapshot:
            with self._lock:
                present = any(current is entry for current in self._entries)
            if not present:
                continue
            try:
                batch = spool.add(entry.kind, entry.payload,
                                  host=entry.host, sensor=entry.sensor,
                                  seq=entry.sequence)
            except Exception:
                _log.exception("sensor ring: spool drain failed")
                break
            with self._lock:
                for position, current in enumerate(self._entries):
                    if current is entry:
                        del self._entries[position]
                        self._bytes -= len(entry.payload)
                        break
            batches.append(batch)
        return batches


__all__ = ["DEFAULT_RING_BYTES", "Entry", "Ring"]
