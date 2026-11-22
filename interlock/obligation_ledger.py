"""A durable opening ledger for the live obligation guard.

A hook host runs one process per tool call, so a ledger kept in the rule's
closure opens a deadline in one process and cannot see it in the next: the
obligation is forgotten exactly where it matters. Point the rule's ``state=``
at a file and the openings live in a small SQLite database instead, so the
next hook invocation enforces the deadline the previous one opened.

What it stores is deliberately little: the scope identity (a span id or a
principal - the same value a receipt already carries), the two action names,
and two timestamps. No argument, no path, no result text. The ledger cannot
leak more than the receipt log it duplicates.

One ``BEGIN IMMEDIATE`` transaction per event: two hooks racing on the same
call cannot both discharge an obligation or both open it. Three states are
written, in the same order the in-process ledger applies them - discharge the
oldest matching ``then``, then expire the oldest lapsed opening, then open a
``when`` - so a daemon and a hook host reach the same verdict for the same
call stream.

Rows whose ``(when, then)`` pair the current policy no longer lists are
dropped on sight: an edited policy does not resurrect a deadline it removed.
Two obligations with the same pair and different deadlines are one entry here;
put the deadline on a distinct action pair if the difference matters. The
receipt log remains the authority for every opening, including the late ones
the live guard deliberately lets through.
"""
from __future__ import annotations

import os
import sqlite3
from typing import List, Optional, Sequence, Tuple

from .obligations import Obligation

_SCHEMA = """
CREATE TABLE IF NOT EXISTS openings (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    scope TEXT NOT NULL,
    when_ TEXT NOT NULL,
    then_ TEXT NOT NULL,
    opened_at REAL NOT NULL,
    required_by REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS openings_scope ON openings (scope, seq);
"""

#: Seconds a writer waits for another hook's transaction before giving up.
#: The rule degrades to its in-process ledger on a failure, so this is a
#: patience bound, not a correctness one.
BUSY_TIMEOUT = 10.0


class FileLedger:
    """Open obligations in one SQLite file, shared by every process that names it."""

    def __init__(self, path: str) -> None:
        self.path = os.path.abspath(os.path.expanduser(path))
        directory = os.path.dirname(self.path)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        db = self._db()
        try:
            db.executescript(_SCHEMA)
        finally:
            db.close()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _db(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=BUSY_TIMEOUT, isolation_level=None)

    def apply(self, scope: str, action: str, wanted: Sequence[Obligation], now: float, *,
              max_scopes: int, max_open: int) -> Optional[Tuple[Obligation, float]]:
        """Record one call; return the obligation it breached, if any.

        The returned tuple is ``(obligation, opened_at)`` - the same shape the
        in-process ledger produces, so the rule builds its decision one way.
        """
        db = self._db()
        try:
            db.execute("BEGIN IMMEDIATE")
            try:
                breach = self._apply_locked(db, scope, action, wanted, now,
                                            max_scopes=max_scopes, max_open=max_open)
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        finally:
            db.close()
        return breach

    def _apply_locked(self, db: sqlite3.Connection, scope: str, action: str,
                      wanted: Sequence[Obligation], now: float, *,
                      max_scopes: int, max_open: int) -> Optional[Tuple[Obligation, float]]:
        known = {}
        for obligation in wanted:
            known.setdefault((obligation.when, obligation.then), obligation)
        rows = db.execute(
            "SELECT seq, when_, then_, opened_at, required_by FROM openings "
            "WHERE scope = ? ORDER BY seq", (scope,)).fetchall()
        kept: List[Tuple[int, Obligation, float, float]] = []
        for seq, when, then, opened_at, required_by in rows:
            obligation = known.get((when, then))
            if obligation is None:
                db.execute("DELETE FROM openings WHERE seq = ?", (seq,))
                continue
            kept.append((seq, obligation, opened_at, required_by))

        # 1. Discharge: the compensating action closes the oldest opening.
        for position, (seq, obligation, _opened, _by) in enumerate(kept):
            if obligation.then == action:
                db.execute("DELETE FROM openings WHERE seq = ?", (seq,))
                del kept[position]
                break

        # 2. Expire: the oldest lapsed opening is the breach this call meets.
        for seq, obligation, opened_at, required_by in kept:
            if now > required_by:
                db.execute("DELETE FROM openings WHERE seq = ?", (seq,))
                return obligation, opened_at

        # 3. Open: a trigger action starts its clock, within both bounds.
        for obligation in wanted:
            if obligation.when != action:
                continue
            if len(kept) >= max_open:
                seq = kept.pop(0)[0]
                db.execute("DELETE FROM openings WHERE seq = ?", (seq,))
            self._claim_scope(db, scope, max_scopes)
            cursor = db.execute(
                "INSERT INTO openings (scope, when_, then_, opened_at, required_by) "
                "VALUES (?, ?, ?, ?, ?)",
                (scope, obligation.when, obligation.then, now, now + obligation.within))
            kept.append((int(cursor.lastrowid or 0), obligation, now, now + obligation.within))
        return None

    @staticmethod
    def _claim_scope(db: sqlite3.Connection, scope: str, max_scopes: int) -> None:
        """Make room for ``scope``'s first row by evicting the oldest scope."""
        if db.execute("SELECT 1 FROM openings WHERE scope = ? LIMIT 1", (scope,)).fetchone():
            return
        scopes = [row[0] for row in db.execute(
            "SELECT scope FROM openings GROUP BY scope ORDER BY MIN(seq)").fetchall()]
        if len(scopes) >= max_scopes:
            db.execute("DELETE FROM openings WHERE scope = ?", (scopes[0],))

    def scopes(self) -> List[str]:
        """The scopes holding at least one open obligation, oldest first."""
        db = self._db()
        try:
            return [row[0] for row in db.execute(
                "SELECT scope FROM openings GROUP BY scope ORDER BY MIN(seq)").fetchall()]
        finally:
            db.close()

    def open_count(self) -> int:
        db = self._db()
        try:
            return int(db.execute("SELECT COUNT(*) FROM openings").fetchone()[0])
        finally:
            db.close()


__all__ = ["BUSY_TIMEOUT", "FileLedger"]
