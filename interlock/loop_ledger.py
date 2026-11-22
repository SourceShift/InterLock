"""A durable repeat-run ledger for the live loop guard.

:mod:`interlock.detectors.duplicate_call_loop_guard` remembers the signature of
the call it saw last and how many times that signature has repeated. Kept in
the rule's closure that run dies with the process - fine for a daemon, useless
for a hook host, which starts a new process per tool call and so sees every
call as the first of its run, never tripping the guard. Point the rule's
``state=`` at a file and the runs live here instead.

What it stores is deliberately little: the scope identity (a span id or a
principal - the same value a receipt already carries), the previous call's
signature as a **SHA-256 digest**, and the run length. The digest is the whole
point: the guard only ever compares two signatures for equality, so storing the
signature itself - which stringifies the arguments - would put file paths and
argument text into a file that need not hold them.

One ``BEGIN IMMEDIATE`` transaction per event, so two hooks racing on the same
call cannot both see a stale run. At most ``max_scopes`` scopes are tracked,
least recently seen first.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3

from ._sqlite import connect, immediate, prepare

_SCHEMA = """
CREATE TABLE IF NOT EXISTS streaks (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    scope TEXT NOT NULL UNIQUE,
    digest TEXT NOT NULL,
    run INTEGER NOT NULL
);
"""


def digest_of(signature: str) -> str:
    """The stored form of a call signature: a SHA-256 hex digest, never the text."""
    return hashlib.sha256(signature.encode("utf-8", "surrogatepass")).hexdigest()


class LoopLedger:
    """Consecutive-repeat runs per scope in one SQLite file, shared by every process."""

    def __init__(self, path: str) -> None:
        self.path = os.path.abspath(os.path.expanduser(path))
        prepare(self.path, _SCHEMA)

    def apply(self, scope: str, digest: str, *, max_scopes: int) -> int:
        """Record one call and return its signature's run length.

        A digest equal to the scope's stored one extends the run; any other
        digest starts a new run at one, which is what "in a row" means.
        """
        with immediate(self.path) as db:
            return self._apply_locked(db, scope, digest, max_scopes=max_scopes)

    def _apply_locked(self, db: sqlite3.Connection, scope: str, digest: str, *,
                      max_scopes: int) -> int:
        row = db.execute("SELECT digest, run FROM streaks WHERE scope = ?",
                         (scope,)).fetchone()
        if row is None:
            self._claim_scope(db, max_scopes)
            run = 1
        else:
            run = int(row[1]) + 1 if row[0] == digest else 1
            # Rewriting the row moves it to the newest seq, so eviction below
            # drops the scope that has gone longest without a call.
            db.execute("DELETE FROM streaks WHERE scope = ?", (scope,))
        db.execute("INSERT INTO streaks (scope, digest, run) VALUES (?, ?, ?)",
                   (scope, digest, run))
        return run

    @staticmethod
    def _claim_scope(db: sqlite3.Connection, max_scopes: int) -> None:
        """Make room for ``scope``'s first row by evicting the stalest scope."""
        total = int(db.execute("SELECT COUNT(*) FROM streaks").fetchone()[0])
        if total < max_scopes:
            return
        oldest = db.execute("SELECT scope FROM streaks ORDER BY seq LIMIT 1").fetchone()
        if oldest is not None:
            db.execute("DELETE FROM streaks WHERE scope = ?", (oldest[0],))

    def run_of(self, scope: str) -> int:
        """*scope*'s current run length, or 0 if it has no row."""
        db = connect(self.path)
        try:
            row = db.execute("SELECT run FROM streaks WHERE scope = ?",
                             (scope,)).fetchone()
        finally:
            db.close()
        return 0 if row is None else int(row[0])


__all__ = ["LoopLedger", "digest_of"]
