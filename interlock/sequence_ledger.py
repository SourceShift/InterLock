"""A durable action journal for the live sequence guard.

:mod:`interlock.detectors.sequence_guard` recalls the last ``window`` actions
of a run to notice a forbidden pair. Kept in the rule's closure that history
dies with the process - fine for a daemon, useless for a hook host, which
starts a new process per tool call and so never sees the ``before`` its own
previous invocation journalled. Point the rule's ``state=`` at a file and the
journal lives here instead.

What it stores is deliberately little: the scope identity (a span id or a
principal - the same value a receipt already carries) and one canonical action
name per row. No argument, no path, no result text.

One ``BEGIN IMMEDIATE`` transaction per event, so two hooks racing on the same
call cannot both match a pair against a journal the other is rewriting. Each
scope keeps at most ``window`` rows - the same bound the in-memory deque has -
and at most ``max_scopes`` scopes are tracked, oldest first.
"""
from __future__ import annotations

import os
from typing import Iterable, Optional, Sequence, Tuple

from ._sqlite import connect, immediate, prepare

_SCHEMA = """
CREATE TABLE IF NOT EXISTS journal (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    scope TEXT NOT NULL,
    action TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS journal_scope ON journal (scope, seq);
"""


class JournalLedger:
    """Recent actions per scope in one SQLite file, shared by every process."""

    def __init__(self, path: str) -> None:
        self.path = os.path.abspath(os.path.expanduser(path))
        prepare(self.path, _SCHEMA)

    def apply(self, scope: str, action: str,
              pairs: Sequence[Tuple[str, str]], *, window: int,
              max_scopes: int) -> Optional[Tuple[str, str]]:
        """Journal one call; return the ``(before, after)`` pair it completes.

        The journal is updated whether or not a pair matched, so a blocked
        ``after`` step stays blocked while its ``before`` remains in the window
        instead of being retried through.
        """
        with immediate(self.path) as db:
            return self._apply_locked(db, scope, action, pairs,
                                      window=window, max_scopes=max_scopes)

    def _apply_locked(self, db, scope: str, action: str,
                      pairs: Sequence[Tuple[str, str]], *, window: int,
                      max_scopes: int) -> Optional[Tuple[str, str]]:
        rows = db.execute(
            "SELECT action FROM journal WHERE scope = ? ORDER BY seq DESC LIMIT ?",
            (scope, window)).fetchall()
        recent = [row[0] for row in reversed(rows)]
        matched = None
        for before, after in pairs:
            if action == after and before in recent:
                matched = (before, after)
                break
        self._claim_scope(db, scope, max_scopes)
        db.execute("INSERT INTO journal (scope, action) VALUES (?, ?)", (scope, action))
        db.execute(
            "DELETE FROM journal WHERE scope = ? AND seq NOT IN "
            "(SELECT seq FROM journal WHERE scope = ? ORDER BY seq DESC LIMIT ?)",
            (scope, scope, window))
        return matched

    @staticmethod
    def _claim_scope(db, scope: str, max_scopes: int) -> None:
        """Make room for ``scope``'s first row by evicting the oldest scope."""
        if db.execute("SELECT 1 FROM journal WHERE scope = ? LIMIT 1",
                      (scope,)).fetchone():
            return
        scopes = [row[0] for row in db.execute(
            "SELECT scope FROM journal GROUP BY scope ORDER BY MIN(seq)").fetchall()]
        if len(scopes) >= max_scopes:
            db.execute("DELETE FROM journal WHERE scope = ?", (scopes[0],))

    def seed(self, entries: Iterable[Tuple[str, str]], *, window: int,
             max_scopes: int) -> int:
        """Replace the journal with *entries*, replayed in the order given.

        The log is the older and more complete record than the file, so a seed
        *replaces* rather than appends: running it twice over one log yields
        the same journal, and a fresh install after a restart sees exactly the
        history the receipts show. Each scope keeps its newest *window*
        actions, and at most *max_scopes* scopes survive, oldest first -
        the same bounds :meth:`apply` keeps. Returns the number of actions
        written.
        """
        written = 0
        with immediate(self.path) as db:
            db.execute("DELETE FROM journal")
            for scope, action in entries:
                self._claim_scope(db, scope, max_scopes)
                db.execute("INSERT INTO journal (scope, action) VALUES (?, ?)",
                           (scope, action))
                written += 1
            for (scope,) in db.execute(
                    "SELECT DISTINCT scope FROM journal").fetchall():
                db.execute(
                    "DELETE FROM journal WHERE scope = ? AND seq NOT IN "
                    "(SELECT seq FROM journal WHERE scope = ? "
                    "ORDER BY seq DESC LIMIT ?)",
                    (scope, scope, window))
        return written

    def journal(self, scope: str, *, window: int) -> list:
        """The recent actions for *scope*, oldest first (the newest *window*)."""
        db = connect(self.path)
        try:
            rows = db.execute(
                "SELECT action FROM journal WHERE scope = ? ORDER BY seq DESC LIMIT ?",
                (scope, window)).fetchall()
        finally:
            db.close()
        return [row[0] for row in reversed(rows)]


__all__ = ["JournalLedger"]
