"""The small durable state a rule may keep across processes.

A hook host starts a new process for every tool call, so a rule whose history
lives in its closure forgets everything between calls - which is exactly the
state a sequence or a deadline needs. A rule that takes an absolute ``state=``
path keeps its history in a SQLite file instead, and this module is the part
every such ledger shares: where the file may live, how it is opened, how one
event is applied atomically, and what happens when the storage fails.

What a ledger stores is its own business - action names and timestamps, never
an argument value - and the receipt log remains the authority for anything the
ledger forgets.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Callable, Iterator, Optional

#: Seconds a writer waits for another process's transaction before giving up.
#: Every caller degrades to its in-process state on a failure, so this is a
#: patience bound, not a correctness one.
BUSY_TIMEOUT = 10.0


def check_state_path(value: object) -> Optional[str]:
    """Validate a rule's ``state=`` argument, returning it or None.

    None means "keep the state in this process". Anything else must be a
    non-empty, absolute path once ``~`` is expanded: a hook's working directory
    is the agent's, and the state must not sit where the guarded process can
    move it. A bad value raises ``ValueError`` at construction, where the
    operator can still see it.
    """
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError("state must be a non-empty path or None")
    if not os.path.isabs(os.path.expanduser(value)):
        raise ValueError(
            "state must be an absolute path: a hook's working directory is "
            "the agent's, and the state must not sit where the guarded "
            "process can move it")
    return value


def connect(path: str) -> sqlite3.Connection:
    """Open *path* in autocommit mode, waiting :data:`BUSY_TIMEOUT` for a lock."""
    return sqlite3.connect(path, timeout=BUSY_TIMEOUT, isolation_level=None)


def prepare(path: str, schema: str) -> None:
    """Create the file's directory and tables, then leave it owner-readable only."""
    expanded = os.path.abspath(os.path.expanduser(path))
    os.makedirs(os.path.dirname(expanded), mode=0o700, exist_ok=True)
    db = connect(expanded)
    try:
        db.executescript(schema)
    finally:
        db.close()
    try:
        os.chmod(expanded, 0o600)
    except OSError:
        pass


@contextmanager
def immediate(path: str) -> Iterator[sqlite3.Connection]:
    """One ``BEGIN IMMEDIATE`` transaction on a fresh connection, closed after.

    Two processes racing on the same event cannot both apply it: the second
    waits, then reads what the first committed.
    """
    db = connect(path)
    try:
        db.execute("BEGIN IMMEDIATE")
        try:
            yield db
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
    finally:
        db.close()


class LazyFile:
    """Open a file-backed ledger on first use; never raise, never retry forever.

    Construction is cheap and writes nothing, so a policy check that builds a
    rule does not create the file. The first event opens it. Any failure -
    locked too long, corrupt, unwritable directory, disk full - is warned once
    and the object stays off: the caller then falls back to its in-process
    state for the rest of the process, because one storage fault repeated on
    every call would be worse than the incident it guards against.
    """

    def __init__(self, path: str, factory: Callable[[str], Any], what: str,
                 logger: Any) -> None:
        self.path = path
        self._factory = factory
        self._what = what
        self._log = logger
        self._instance: Any = None
        self._off = False
        self._lock = threading.Lock()

    def get(self) -> Any:
        """The ledger, or None while it has never been opened or has failed."""
        with self._lock:
            if self._instance is not None or self._off:
                return self._instance
            try:
                self._instance = self._factory(self.path)
            except Exception as exc:
                self._warn(exc, "unavailable")
            return self._instance

    def fail(self, exc: Exception) -> None:
        """Record that a call against the ledger failed; fall back from now on."""
        with self._lock:
            self._instance = None
            self._warn(exc, "failed")

    def _warn(self, exc: Exception, outcome: str) -> None:
        first = not self._off
        self._off = True
        if first:
            self._log.warning(
                "interlock: %s %s %s (%s); falling back to process-local state",
                self._what, self.path, outcome, exc)


__all__ = ["BUSY_TIMEOUT", "LazyFile", "check_state_path", "connect", "immediate",
           "prepare"]
