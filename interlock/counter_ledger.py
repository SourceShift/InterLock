"""A durable per-key counter for the rate limiters.

The rate limiters - ``call_rate_limiter``, ``egress_rate_limiter`` and
``failed_auth_lockout`` - judge a principal in aggregate, so their whole
opinion lives in a running count. Kept in the rule's closure that count dies
with the process: fine for a daemon, useless for a hook host, which starts a
new process per tool call and so gives every call a fresh budget. Point the
rule's ``state=`` at a file and the counts live here instead.

What it stores is deliberately little: the key (a principal name - the same
value a receipt already carries) and one integer. No argument, no path, no
result text.

One ``BEGIN IMMEDIATE`` transaction per event, so two hooks racing on the same
principal cannot lose a count. A counter never decays: like the in-process
dict it replaces, it is a lifetime tally, not a sliding window - so a durable
limiter reads as "N calls since the state file was created", and resetting the
budget is deleting the file. At most ``max_keys`` keys are tracked, oldest
first; that bound is what keeps an agent that mints a new principal per call
from growing the file without limit, and an evicted key starts again at zero.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
from typing import Dict, Optional

from ._sqlite import LazyFile, check_state_path, connect, immediate, prepare

_log = logging.getLogger(__name__)

#: How many keys one state file tracks before the oldest is evicted. Generous
#: enough for every principal a real host sees, small enough that a runaway
#: identity churn cannot fill a disk.
DEFAULT_MAX_KEYS = 4096

_SCHEMA = """
CREATE TABLE IF NOT EXISTS counters (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    count INTEGER NOT NULL
);
"""


class CounterLedger:
    """Per-key counts in one SQLite file, shared by every process that names it."""

    def __init__(self, path: str) -> None:
        self.path = os.path.abspath(os.path.expanduser(path))
        prepare(self.path, _SCHEMA)

    def bump(self, key: str, *, max_keys: int) -> int:
        """Add one to *key*'s count and return the new total."""
        with immediate(self.path) as db:
            return self._bump_locked(db, key, max_keys=max_keys)

    def _bump_locked(self, db: sqlite3.Connection, key: str, *,
                     max_keys: int) -> int:
        row = db.execute("SELECT count FROM counters WHERE key = ?", (key,)).fetchone()
        if row is None:
            self._claim_key(db, max_keys)
            db.execute("INSERT INTO counters (key, count) VALUES (?, 1)", (key,))
            return 1
        count = int(row[0]) + 1
        db.execute("UPDATE counters SET count = ? WHERE key = ?", (count, key))
        return count

    @staticmethod
    def _claim_key(db: sqlite3.Connection, max_keys: int) -> None:
        """Make room for a new key by evicting the oldest one."""
        total = int(db.execute("SELECT COUNT(*) FROM counters").fetchone()[0])
        if total < max_keys:
            return
        oldest = db.execute(
            "SELECT key FROM counters ORDER BY seq LIMIT 1").fetchone()
        if oldest is not None:
            db.execute("DELETE FROM counters WHERE key = ?", (oldest[0],))

    def count(self, key: str) -> int:
        """*key*'s count, or 0 if it was never bumped (or was evicted)."""
        db = connect(self.path)
        try:
            row = db.execute("SELECT count FROM counters WHERE key = ?",
                             (key,)).fetchone()
        finally:
            db.close()
        return 0 if row is None else int(row[0])


class Counters:
    """Per-key counts, in this process or in a file when *state* names one.

    This is the one place a rule touches its counts, so the three limiters share
    the durability policy instead of each reimplementing it: construction writes
    nothing (``interlock policy check`` must not create files), the file opens on
    the first event, and any storage fault is warned once and then the counts
    stay in memory for the rest of the process. A storage fault is the same
    failure as a restart - a budget that resets - and refusing every call would
    make the guard worse than the incident.
    """

    def __init__(self, what: str, state: Optional[str] = None, *,
                 max_keys: int = DEFAULT_MAX_KEYS) -> None:
        checked = check_state_path(state)
        self._max_keys = max_keys
        self._counts: Dict[str, int] = {}
        self._lock = threading.Lock()
        self._durable = (LazyFile(checked, CounterLedger, what, _log)
                         if checked is not None else None)

    def bump(self, key: str) -> int:
        """Add one to *key*'s count and return the new total."""
        if self._durable is not None:
            ledger = self._durable.get()
            if ledger is not None:
                try:
                    return ledger.bump(key, max_keys=self._max_keys)
                except Exception as exc:  # locked, full disk, a corrupted file
                    self._durable.fail(exc)
        with self._lock:
            self._counts[key] = self._counts.get(key, 0) + 1
            return self._counts[key]


__all__ = ["DEFAULT_MAX_KEYS", "CounterLedger", "Counters"]
