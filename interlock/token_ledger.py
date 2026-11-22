"""A durable rolling token window for the live token-budget guard.

:mod:`interlock.detectors.token_budget_guard` charges estimated tokens to a
principal and judges the total still inside a window of ``window_s`` seconds.
Kept in the rule's closure that window dies with the process - fine for a
daemon, useless for a hook host, which starts a new process per tool call and
so gives every call an empty window. Point the rule's ``state=`` at a file and
the charges live here instead.

What it stores is deliberately little: the scope identity (a principal - the
same value a receipt already carries), the charge's timestamp, and the token
*count*. Never the text those tokens were estimated from: the guard counts
text, it does not need to keep it.

One ``BEGIN IMMEDIATE`` transaction per event, so two hooks racing on the same
principal cannot both read a window that excludes the other's charge. A charge
whose timestamp is at or before the cutoff has left the window and is dropped;
each scope keeps at most ``max_charges`` charges and at most ``max_scopes``
scopes are tracked, the stalest first.
"""
from __future__ import annotations

import os
import sqlite3

from ._sqlite import connect, immediate, prepare

#: How many charges one scope keeps inside its window before the oldest is
#: dropped. A window holds ``window_s`` seconds of calls; this bound is what
#: keeps a very chatty principal from growing the file without limit.
DEFAULT_MAX_CHARGES = 4096

_SCHEMA = """
CREATE TABLE IF NOT EXISTS charges (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    scope TEXT NOT NULL,
    ts REAL NOT NULL,
    tokens INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS charges_scope ON charges (scope, seq);
"""


class TokenLedger:
    """Rolling token charges per scope in one SQLite file, shared by every process."""

    def __init__(self, path: str) -> None:
        self.path = os.path.abspath(os.path.expanduser(path))
        prepare(self.path, _SCHEMA)

    def charge(self, scope: str, now: float, tokens: int, *, window_s: float,
               max_scopes: int,
               max_charges: int = DEFAULT_MAX_CHARGES) -> float:
        """Charge *tokens* at *now* and return the window's total afterwards.

        The window is the half-open ``(now - window_s, now]``, the same one the
        in-process guard keeps, so a charge exactly ``window_s`` old has left
        it. A charge of zero tokens is only stored when the window already
        holds something else, exactly as the in-process list does.
        """
        with immediate(self.path) as db:
            return self._charge_locked(db, scope, now, tokens, window_s=window_s,
                                       max_scopes=max_scopes,
                                       max_charges=max_charges)

    def _charge_locked(self, db: sqlite3.Connection, scope: str, now: float,
                       tokens: int, *, window_s: float, max_scopes: int,
                       max_charges: int) -> float:
        self._claim_scope(db, scope, max_scopes)
        cutoff = now - window_s
        db.execute("DELETE FROM charges WHERE scope = ? AND ts <= ?", (scope, cutoff))
        used = float(db.execute(
            "SELECT COALESCE(SUM(tokens), 0) FROM charges WHERE scope = ?",
            (scope,)).fetchone()[0])
        if used or tokens:
            db.execute("INSERT INTO charges (scope, ts, tokens) VALUES (?, ?, ?)",
                       (scope, now, tokens))
            used += tokens
            db.execute(
                "DELETE FROM charges WHERE scope = ? AND seq NOT IN "
                "(SELECT seq FROM charges WHERE scope = ? "
                "ORDER BY seq DESC LIMIT ?)",
                (scope, scope, max_charges))
        return used

    @staticmethod
    def _claim_scope(db: sqlite3.Connection, scope: str, max_scopes: int) -> None:
        """Make room for ``scope``'s first charge by evicting the stalest scope."""
        if db.execute("SELECT 1 FROM charges WHERE scope = ? LIMIT 1",
                      (scope,)).fetchone():
            return
        scopes = [row[0] for row in db.execute(
            "SELECT scope FROM charges GROUP BY scope "
            "ORDER BY MIN(seq)").fetchall()]
        if len(scopes) >= max_scopes:
            db.execute("DELETE FROM charges WHERE scope = ?", (scopes[0],))

    def used(self, scope: str, now: float, *, window_s: float) -> int:
        """Tokens charged to *scope* inside ``(now - window_s, now]``."""
        db = connect(self.path)
        try:
            row = db.execute(
                "SELECT COALESCE(SUM(tokens), 0) FROM charges "
                "WHERE scope = ? AND ts > ?", (scope, now - window_s)).fetchone()
        finally:
            db.close()
        return int(row[0])


__all__ = ["DEFAULT_MAX_CHARGES", "TokenLedger"]
