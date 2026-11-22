"""A durable memory of poisoned fragments, for the flow tracker's taint label.

The flow tracker remembers which tool result a value came from, so a rule can
refuse "send what a tool returned" without refusing everything. It keeps that
memory in the process, and a hook host runs one process per tool call: a
poisoned page fetched under one call is forgotten by the next, exactly where a
later egress call needs the label. This file closes that gap for the one label
that cannot be recomputed from the current call: :data:`~interlock.taint.TAINT_INJECTION`.

What it stores is a **digest**, never a fragment: the tracker's match is a
substring test, but a durable one can only recognise a fragment copied
verbatim (a line, an identifier, a token) - and for that, equality is enough.
Storing hashes means the file cannot be read back into the text of a tool
result, and the same bounded-eviction discipline as every other ledger keeps
it small: at most *max_rows* fragments per scope, at most *max_scopes* scopes,
the stalest first.
"""
from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
from typing import Iterable, Set

from ._sqlite import LazyFile, connect, immediate, prepare

_log = logging.getLogger(__name__)

#: Fragments remembered per scope; the flow tracker's in-process memory keeps
#: the same count, so a durable tracker forgets at the same rate as a local one.
DEFAULT_MAX_ROWS = 512
#: Scopes with at least one remembered fragment. A session id is the usual scope.
DEFAULT_MAX_SCOPES = 256

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tainted (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    scope TEXT NOT NULL,
    digest TEXT NOT NULL,
    UNIQUE (scope, digest)
);
"""

__all__ = ["DEFAULT_MAX_ROWS", "DEFAULT_MAX_SCOPES", "TaintLedger", "digest_of",
           "durable"]


def digest_of(fragment: str) -> str:
    """The stored form of one fragment: a SHA-256 hex digest.

    Undecodable bytes are replaced rather than raising, so a result with an
    odd encoding still gets a stable digest.
    """
    return hashlib.sha256(fragment.encode("utf-8", "replace")).hexdigest()


class TaintLedger:
    """Poisoned-fragment digests in one SQLite file, shared by every process."""

    def __init__(self, path: str) -> None:
        self.path = os.path.abspath(os.path.expanduser(path))
        prepare(self.path, _SCHEMA)

    def remember(self, scope: str, digests: Iterable[str], *,
                 max_rows: int = DEFAULT_MAX_ROWS,
                 max_scopes: int = DEFAULT_MAX_SCOPES) -> int:
        """Record *digests* under *scope*; return how many are new.

        Re-seeing a digest refreshes its position (it is the newest row again),
        so the fragments an active run keeps copying are the last to be
        evicted. Each scope keeps its newest *max_rows* digests and the oldest
        scope goes once there are more than *max_scopes* - the same stalest-
        first order :mod:`interlock.flow` evicts in.
        """
        written = 0
        with immediate(self.path) as db:
            for digest in dict.fromkeys(digests):
                db.execute("DELETE FROM tainted WHERE scope = ? AND digest = ?",
                           (scope, digest))
                db.execute("INSERT INTO tainted (scope, digest) VALUES (?, ?)",
                           (scope, digest))
                db.execute(
                    "DELETE FROM tainted WHERE scope = ? AND seq NOT IN "
                    "(SELECT seq FROM tainted WHERE scope = ? "
                    "ORDER BY seq DESC LIMIT ?)",
                    (scope, scope, max_rows))
                written += 1
            scopes = [row[0] for row in db.execute(
                "SELECT scope FROM tainted GROUP BY scope ORDER BY MIN(seq)")]
            for stale in scopes[:-max_scopes] if max_scopes > 0 else scopes:
                db.execute("DELETE FROM tainted WHERE scope = ?", (stale,))
        return written

    def digests(self, scope: str) -> Set[str]:
        """The digests remembered under *scope*, as a set for membership tests.

        Loading once per call is what lets the tracker test every scanned
        string against the file without opening a connection for each.
        """
        db = self._db()
        try:
            return {row[0] for row in db.execute(
                "SELECT digest FROM tainted WHERE scope = ?", (scope,))}
        finally:
            db.close()

    def _db(self) -> sqlite3.Connection:
        return connect(self.path)

    def count(self) -> int:
        """Every remembered digest, across scopes."""
        db = self._db()
        try:
            return int(db.execute("SELECT COUNT(*) FROM tainted").fetchone()[0])
        finally:
            db.close()


def durable(path: str) -> LazyFile:
    """A keeper for *path*, opened on the first tainted result.

    Construction writes nothing, so a policy check or a call that never sees a
    poisoned result does not create the file. A storage failure is warned once
    and the tracker keeps its in-process memory only.
    """
    return LazyFile(path, TaintLedger, "taint ledger", _log)
