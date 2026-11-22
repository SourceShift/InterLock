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
from typing import Iterable, List, Optional, Sequence, Tuple

from ._sqlite import BUSY_TIMEOUT, connect, immediate, prepare
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

#: Seconds a writer waits for another hook's transaction before giving up;
#: re-exported from :mod:`interlock._sqlite`, where every durable ledger's
#: patience bound lives.
__all__ = ["BUSY_TIMEOUT", "FileLedger"]


class FileLedger:
    """Open obligations in one SQLite file, shared by every process that names it."""

    def __init__(self, path: str) -> None:
        self.path = os.path.abspath(os.path.expanduser(path))
        prepare(self.path, _SCHEMA)

    def _db(self) -> sqlite3.Connection:
        return connect(self.path)

    def apply(self, scope: str, action: str, wanted: Sequence[Obligation], now: float, *,
              max_scopes: int, max_open: int) -> Optional[Tuple[Obligation, float]]:
        """Record one call; return the obligation it breached, if any.

        The returned tuple is ``(obligation, opened_at)`` - the same shape the
        in-process ledger produces, so the rule builds its decision one way.
        """
        with immediate(self.path) as db:
            return self._apply_locked(db, scope, action, wanted, now,
                                      max_scopes=max_scopes, max_open=max_open)

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

    def seed(self, entries: Iterable[Tuple[str, str, str, float, float]], *,
             max_scopes: int, max_open: int) -> int:
        """Replace the openings with *entries*, replayed in the order given.

        An entry is ``(scope, when, then, opened_at, required_by)`` - the shape
        a replayed receipt log yields. The log is the older and more complete
        record than the file, so a seed *replaces* rather than appends: running
        it twice over one log gives the same ledger, and a fresh install after a
        restart enforces the deadlines the receipts still show. Each scope keeps
        its newest *max_open* openings and at most *max_scopes* scopes survive,
        the stalest first - the same bounds :meth:`apply` keeps. Returns the
        number of openings written.
        """
        written = 0
        with immediate(self.path) as db:
            db.execute("DELETE FROM openings")
            for scope, when, then, opened_at, required_by in entries:
                self._claim_scope(db, scope, max_scopes)
                db.execute(
                    "INSERT INTO openings (scope, when_, then_, opened_at, "
                    "required_by) VALUES (?, ?, ?, ?, ?)",
                    (scope, when, then, opened_at, required_by))
                db.execute(
                    "DELETE FROM openings WHERE scope = ? AND seq NOT IN "
                    "(SELECT seq FROM openings WHERE scope = ? "
                    "ORDER BY seq DESC LIMIT ?)",
                    (scope, scope, max_open))
                written += 1
        return written

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

