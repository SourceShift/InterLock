"""A durable review queue: ask a human without holding the call (hoop review H3).

An in-process approver must answer while the call waits. Agents often can't
wait - a coding agent's hook has a timeout, a serverless function has a
deadline, Codex can't open a prompt at all. A review queue decouples the two:

1. The first time a call escalates, a **pending review** is filed and the call
   is refused with the review id: "review r-1a2b3c4d is pending; once a human
   approves it, retry this identical call".
2. A human runs ``interlock reviews approve r-1a2b3c4d`` (or ``reject``).
3. The agent retries. The retry is the **identical** request - same action,
   same arguments (by digest), same principal, same rule and reason - so it
   matches the approved review, which is **claimed exactly once** (a single
   conditional ``UPDATE ... WHERE status = 'approved'``: two concurrent retries
   cannot both win) and the call runs. A different call files its own review.

Reviews carry two clocks: ``pending_ttl`` (time to decide) and
``approval_ttl`` (time to use the approval, from the moment it is granted).
``min_approvals`` asks for that many distinct approvers, and
``allow_self_approval=False`` refuses an approval by the account that filed the
review (four-eyes). Every state is in one SQLite file (stdlib ``sqlite3``),
``~/.interlock/reviews.db`` by default; keep it where the agent can't write -
the coding-agent policy pack locks ``~/.interlock`` and refuses
``interlock reviews approve`` from inside an agent.

Every row is **signed** with an HMAC key that lives beside the database
(``reviews.key``, mode 0600) and never inside it. The signature covers the
binding, the preview, the decision, the approver names and the approval list,
so a writer who can edit the database file alone can no longer approve
anything or redirect a human's approval to a different call: the queue refuses
a row it did not write. The key is the boundary - a process that can read both
files can forge, so keep them somewhere the agent (and other accounts) cannot.
Point ``key_path=`` at a different file to separate the key from the database,
e.g. when the database lives on shared storage and decisions are made from
another machine.

A signature cannot see a *rollback*: an older copy of the database is a valid
set of signed rows, and replaying it restores old approvals. So every state
change also bumps a signed **high-water mark** (``<key>.head`` by default)
outside the database, and opening a database whose counter is behind that mark
is refused as a rollback. Put the mark on storage that is not restored with
the database (``head_path=``) to cover a restore of both the database and its
key; restoring the mark too is beyond what any file beside the queue can
detect, and the receipt log stays the independent record of what ran.

Statuses: ``pending``, ``approved``, ``rejected``, ``revoked``, ``expired``,
``executed`` (an approval that was used).
"""
from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterator, List, Optional

from .approval import ApprovalRequest, Declined, approve_once

STATUSES = ("pending", "approved", "rejected", "revoked", "expired", "executed")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS reviews (
    id TEXT PRIMARY KEY,
    binding TEXT NOT NULL,
    status TEXT NOT NULL,
    action TEXT NOT NULL,
    phase TEXT NOT NULL,
    principal TEXT,
    requester TEXT,
    policy_id TEXT,
    reason TEXT,
    args_digest TEXT,
    preview TEXT,
    created REAL NOT NULL,
    pending_until REAL NOT NULL,
    decided REAL,
    approval_until REAL,
    executed REAL,
    decided_by TEXT,
    rejection_reason TEXT,
    min_approvals INTEGER NOT NULL DEFAULT 1,
    allow_self_approval INTEGER NOT NULL DEFAULT 1,
    approval_ttl REAL NOT NULL DEFAULT 900,
    mac TEXT
);
CREATE INDEX IF NOT EXISTS reviews_binding ON reviews (binding, status);
CREATE TABLE IF NOT EXISTS approvals (
    review_id TEXT NOT NULL,
    approver TEXT NOT NULL,
    ts REAL NOT NULL,
    PRIMARY KEY (review_id, approver)
);
CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    allow_self_approval INTEGER NOT NULL,
    min_approvals INTEGER NOT NULL,
    approval_ttl REAL NOT NULL,
    seq INTEGER NOT NULL DEFAULT 0
);
"""

#: Columns added after the first release; ``ALTER TABLE`` needs a default that
#: keeps an older database's existing rows approveable.
_MIGRATED_COLUMNS = (
    ("allow_self_approval", "INTEGER NOT NULL DEFAULT 1"),
    ("approval_ttl", "REAL NOT NULL DEFAULT 900"),
    ("mac", "TEXT"),
)


def default_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".interlock", "reviews.db")


def default_key_path(path: str) -> str:
    """Where the signing key for the database at ``path`` lives by default."""
    return os.path.join(os.path.dirname(os.path.abspath(path)), "reviews.key")


#: The high-water mark's format. A future change bumps it and the reader refuses
#: a mark it does not understand rather than guessing.
HEAD_VERSION = 1


def default_head_path(key_path: str) -> str:
    """Where the rollback high-water mark lives by default: beside the key.

    The key and the mark travel together - a decision made on another machine
    is verified with the same key, and must see the same "how many writes has
    this queue ever seen" fact. Pass ``head_path=`` to put it on storage the
    database is not restored with; that is what catches a restore of the
    database *and* the key.
    """
    return key_path + ".head"


def _head_mac(key: bytes, seq: int) -> str:
    payload = json.dumps({"version": HEAD_VERSION, "seq": int(seq)},
                         separators=(",", ":")).encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _read_or_create_key(path: str) -> bytes:
    """The 32-byte review key at ``path``, created mode 0600 on first use."""
    try:
        with open(path, "rb") as fh:
            key = fh.read()
        if len(key) < 32:
            raise ReviewError(
                "review key {} is truncated ({} bytes). Restore it, or delete it to start a new one - "
                "which invalidates every decision signed with the old key.".format(path, len(key)))
        return key
    except FileNotFoundError:
        pass
    key = secrets.token_bytes(32)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:  # another process created it between the read and here
        return _read_or_create_key(path)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
    except BaseException:
        os.unlink(path)
        raise
    return key


def _mac_payload(row: sqlite3.Row, approvers: List[str]) -> bytes:
    """The canonical bytes a review's signature covers.

    Every field that can change a decision or what an approver was shown is in
    it, plus the approver list: adding a second approver to satisfy
    ``min_approvals`` is a write the signature must catch. Types are pinned so
    SQLite's int/float round-trip cannot make a legitimate row fail.
    """
    fields = [
        row["id"], row["binding"], row["status"], row["action"], row["phase"],
        row["principal"], row["requester"], row["policy_id"], row["reason"],
        row["args_digest"], row["preview"], float(row["created"]),
        float(row["pending_until"]), row["decided"], row["approval_until"],
        row["executed"], row["decided_by"], row["rejection_reason"],
        int(row["min_approvals"]), int(row["allow_self_approval"]),
        float(row["approval_ttl"]), list(approvers),
    ]
    return json.dumps(fields, separators=(",", ":"), default=str).encode("utf-8")


@dataclass(frozen=True)
class Review:
    id: str
    status: str
    action: str
    phase: str
    principal: Optional[str]
    requester: Optional[str]
    policy_id: Optional[str]
    reason: Optional[str]
    args_digest: Optional[str]
    preview: Optional[str]
    created: float
    pending_until: float
    decided: Optional[float]
    approval_until: Optional[float]
    executed: Optional[float]
    decided_by: Optional[str]
    rejection_reason: Optional[str]
    min_approvals: int
    approvers: List[str]
    #: The policy recorded when the review was filed. A decision obeys the
    #: stricter of this and the database's :class:`settings` row.
    allow_self_approval: bool = True
    approval_ttl: float = 900.0

    @property
    def next(self) -> str:
        """What the agent should do: ``wait``, ``retry_identical_call`` or ``stop``."""
        if self.status == "pending":
            return "wait"
        if self.status == "approved":
            return "retry_identical_call"
        return "stop"

    def to_dict(self) -> Dict[str, Any]:
        out = asdict(self)
        out["next"] = self.next
        return out


class ReviewError(ValueError):
    """A review action that isn't allowed (unknown id, wrong state, self-approval)."""


class ReviewQueue:
    """Pending and decided reviews in one SQLite file."""

    def __init__(self, path: Optional[str] = None, *, pending_ttl: float = 3600.0,
                 approval_ttl: float = 900.0, min_approvals: int = 1,
                 allow_self_approval: bool = True, key: Optional[bytes] = None,
                 key_path: Optional[str] = None, head_path: Optional[str] = None) -> None:
        if pending_ttl <= 0 or approval_ttl <= 0:
            raise ValueError("pending_ttl and approval_ttl must be positive")
        if min_approvals < 1:
            raise ValueError("min_approvals must be at least 1")
        if key is not None and len(key) < 16:
            raise ValueError("the review key must be at least 16 bytes")
        self.path = path or default_path()
        self.pending_ttl = float(pending_ttl)
        self.approval_ttl = float(approval_ttl)
        self.min_approvals = int(min_approvals)
        self.allow_self_approval = allow_self_approval
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, mode=0o700, exist_ok=True)
        self.key_path = key_path or default_key_path(self.path)
        self.head_path = head_path or default_head_path(self.key_path)
        self._key = key if key is not None else _read_or_create_key(self.key_path)
        #: The sequence this process has seen. Every write must make it larger;
        #: a database that moves backwards under a live process is a rollback.
        self._seq = 0
        with self._db() as db:
            db.executescript(_SCHEMA)
            self._migrate(db)
            self._ratchet(db)
            self._restore_head(db)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _migrate(self, db: sqlite3.Connection) -> None:
        """Add the later columns, then sign the rows a older release wrote.

        A pre-signature database was equally trusted at the moment it is first
        opened here - the upgrade happens in the reviewer's own process - so
        its rows are sealed rather than refused. Rows are signed once;
        a later edit to the file no longer verifies.
        """
        columns = {row[1] for row in db.execute("PRAGMA table_info(reviews)")}
        for name, declaration in _MIGRATED_COLUMNS:
            if name not in columns:
                db.execute("ALTER TABLE reviews ADD COLUMN {} {}".format(name, declaration))
        settings_columns = {row[1] for row in db.execute("PRAGMA table_info(settings)")}
        if "seq" not in settings_columns:
            db.execute("ALTER TABLE settings ADD COLUMN seq INTEGER NOT NULL DEFAULT 0")
        unsigned = [row[0] for row in db.execute("SELECT id FROM reviews WHERE mac IS NULL")]
        for review_id in unsigned:
            self._seal(db, review_id)

    def _mac(self, db: sqlite3.Connection, review_id: str) -> str:
        row = db.execute("SELECT * FROM reviews WHERE id = ?", (review_id,)).fetchone()
        approvers = [r[0] for r in db.execute(
            "SELECT approver FROM approvals WHERE review_id = ? ORDER BY approver", (review_id,))]
        return hmac.new(self._key, _mac_payload(row, approvers), hashlib.sha256).hexdigest()

    def _seal(self, db: sqlite3.Connection, review_id: str) -> None:
        db.execute("UPDATE reviews SET mac = ? WHERE id = ?", (self._mac(db, review_id), review_id))

    def _verify(self, db: sqlite3.Connection, row: sqlite3.Row) -> None:
        """Refuse a row the queue did not write (or one edited behind its back)."""
        approvers = [r[0] for r in db.execute(
            "SELECT approver FROM approvals WHERE review_id = ? ORDER BY approver", (row["id"],))]
        expected = hmac.new(self._key, _mac_payload(row, approvers), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(row["mac"] or "", expected):
            raise ReviewError(
                "review {} does not match its signature: the review database was edited outside "
                "`interlock reviews`; refusing to trust it".format(row["id"]))

    def _ratchet(self, db: sqlite3.Connection) -> None:
        """Record the most restrictive policy this database has ever seen.

        Construction only tightens: ``allow_self_approval`` can turn false,
        ``min_approvals`` can rise and ``approval_ttl`` can shrink. Nothing
        loosens it implicitly; deleting the database resets it.
        """
        db.execute("BEGIN IMMEDIATE")
        try:
            row = db.execute(
                "SELECT allow_self_approval, min_approvals, approval_ttl "
                "FROM settings WHERE id = 1").fetchone()
            allow = 1 if self.allow_self_approval else 0
            if row is None:
                db.execute(
                    "INSERT INTO settings (id, allow_self_approval, min_approvals, approval_ttl) "
                    "VALUES (1, ?, ?, ?)",
                    (allow, self.min_approvals, self.approval_ttl))
            else:
                recorded = (int(row[0]), int(row[1]), float(row[2]))
                tightened = (min(recorded[0], allow),
                             max(recorded[1], self.min_approvals),
                             min(recorded[2], self.approval_ttl))
                if tightened != recorded:
                    db.execute(
                        "UPDATE settings SET allow_self_approval = ?, min_approvals = ?, "
                        "approval_ttl = ? WHERE id = 1", tightened)
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise

    # --- the rollback high-water mark ---------------------------------------
    @staticmethod
    def _stored_seq(db: sqlite3.Connection) -> int:
        row = db.execute("SELECT seq FROM settings WHERE id = 1").fetchone()
        return 0 if row is None else int(row[0])

    def _read_head(self) -> Optional[int]:
        """The mark's sequence, ``None`` when it does not exist yet."""
        try:
            with open(self.head_path, "rb") as fh:
                raw = fh.read(4096)
        except FileNotFoundError:
            return None
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ReviewError(
                "review high-water mark {} is not valid JSON; refusing to use the queue"
                .format(self.head_path))
        seq = doc.get("seq") if isinstance(doc, dict) else None
        mac = doc.get("mac") if isinstance(doc, dict) else None
        if (not isinstance(seq, int) or seq < 0 or not isinstance(mac, str)
                or doc.get("version") != HEAD_VERSION):
            raise ReviewError(
                "review high-water mark {} is malformed; refusing to use the queue"
                .format(self.head_path))
        if not hmac.compare_digest(mac, _head_mac(self._key, seq)):
            raise ReviewError(
                "review high-water mark {} does not match its signature: it was signed with "
                "another key or edited. If the key was rotated on purpose, remove the mark too."
                .format(self.head_path))
        return seq

    def _write_head(self, seq: int) -> None:
        """Replace the mark atomically, mode 0600, never leaving a half file."""
        doc = json.dumps({"version": HEAD_VERSION, "seq": int(seq),
                          "mac": _head_mac(self._key, seq)}, separators=(",", ":")).encode("utf-8")
        directory = os.path.dirname(os.path.abspath(self.head_path))
        os.makedirs(directory, mode=0o700, exist_ok=True)
        tmp = os.path.join(directory, ".reviews-head-{}-{}".format(os.getpid(), secrets.token_hex(4)))
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(doc)
                    fh.flush()
                    os.fsync(fh.fileno())
            except BaseException:
                os.unlink(tmp)
                raise
            os.replace(tmp, self.head_path)
        except OSError as exc:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise ReviewError(
                "cannot write the review high-water mark {}: {}".format(self.head_path, exc))

    def _restore_head(self, db: sqlite3.Connection) -> None:
        """Refuse a database behind its mark, and heal a mark behind the database.

        Behind means rollback: the counter only ever rises, so an older copy of
        the file reports fewer writes than the mark recorded. Ahead means a
        crash between the SQLite commit and the mark write - legitimate, and
        re-synchronised rather than treated as tampering.
        """
        stored = self._stored_seq(db)
        recorded = self._read_head()
        if recorded is not None and recorded > stored:
            raise ReviewError(
                "review database {} is behind its high-water mark ({} writes recorded, {} "
                "present): the queue was restored from an older copy; refusing to use it. "
                "If the restore was intentional, remove {} to start a new history."
                .format(self.path, recorded, stored, self.head_path))
        self._seq = stored
        if recorded != stored:
            self._write_head(stored)

    def _bump(self, db: sqlite3.Connection) -> int:
        """Count one state change, inside the caller's transaction."""
        current = self._stored_seq(db)
        if current < self._seq:
            raise ReviewError(
                "review database {} went backwards under this process ({} -> {}): it was "
                "replaced while in use; refusing to continue".format(self.path, self._seq, current))
        db.execute("UPDATE settings SET seq = ? WHERE id = 1", (current + 1,))
        return current + 1

    def _advance(self, seq: int) -> None:
        """Record a committed change in memory and in the mark.

        The mark only ever rises. Between this process's commit and this call,
        another process may have committed and written a higher one; writing a
        stale value here would move the mark backwards and could make a
        perfectly good database look like it is *ahead* of its mark - which
        heals, but a crash before the heal leaves the rollback undetected. So
        read the current mark first, adopt it when it is higher, and skip the
        write when there is nothing to add.
        """
        self._seq = max(self._seq, seq)
        recorded = self._read_head()
        if recorded is not None and recorded >= self._seq:
            self._seq = recorded
            return
        self._write_head(self._seq)

    @staticmethod
    def _recorded_policy(db: sqlite3.Connection) -> Optional[tuple]:
        row = db.execute(
            "SELECT allow_self_approval, min_approvals, approval_ttl "
            "FROM settings WHERE id = 1").fetchone()
        if row is None:
            return None
        return bool(row[0]), int(row[1]), float(row[2])

    def _policy(self, db: sqlite3.Connection, row: sqlite3.Row) -> tuple:
        """The rules a decision on ``row`` must obey: stricter of row and database."""
        recorded = self._recorded_policy(db)
        if recorded is None:
            recorded = (bool(self.allow_self_approval), self.min_approvals, self.approval_ttl)
        return (bool(row["allow_self_approval"]) and recorded[0],
                max(int(row["min_approvals"]), recorded[1]),
                min(float(row["approval_ttl"]), recorded[2]))

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            yield db
        finally:
            db.close()

    # --- the agent side ---------------------------------------------------
    def lookup_or_file(self, binding: str, request: ApprovalRequest,
                       *, now: Optional[float] = None) -> Review:
        """The live review for this binding, or a new pending one."""
        now = time.time() if now is None else now
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                expired = self._expire(db, now)
                row = db.execute(
                    "SELECT * FROM reviews WHERE binding = ? AND (status IN ('pending', 'approved') "
                    "OR (status IN ('rejected', 'revoked') AND decided > ?)) "
                    "ORDER BY created DESC LIMIT 1", (binding, now - self.pending_ttl)).fetchone()
                # A recent rejection is the answer: retrying the identical call
                # must not file a fresh review and ask the human again.
                created = row is None
                if created:
                    review_id = "r-" + secrets.token_hex(4)
                    db.execute(
                        "INSERT INTO reviews (id, binding, status, action, phase, principal, "
                        "requester, policy_id, reason, args_digest, preview, created, "
                        "pending_until, min_approvals, allow_self_approval, approval_ttl) "
                        "VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (review_id, binding, request.action, request.phase, request.principal,
                         _whoami(), request.policy_id, request.reason, request.args_digest,
                         _preview(request), now, now + self.pending_ttl, self.min_approvals,
                         1 if self.allow_self_approval else 0, self.approval_ttl))
                    self._seal(db, review_id)
                    row = db.execute("SELECT * FROM reviews WHERE id = ?", (review_id,)).fetchone()
                seq = self._bump(db) if (created or expired) else None
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
            review = self._review(db, row)
        if seq is not None:
            self._advance(seq)
        return review

    def claim(self, review_id: str, *, now: Optional[float] = None) -> bool:
        """Use an approval, once. True for exactly one caller."""
        now = time.time() if now is None else now
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = self._row(db, review_id)
                self._verify(db, row)
                cursor = db.execute(
                    "UPDATE reviews SET status = 'executed', executed = ? "
                    "WHERE id = ? AND status = 'approved' AND approval_until > ?",
                    (now, review_id, now))
                if cursor.rowcount != 1:
                    db.execute("ROLLBACK")
                    return False
                self._seal(db, review_id)
                seq = self._bump(db)
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        self._advance(seq)
        return True

    # --- the human side -----------------------------------------------------
    def approve(self, review_id: str, approver: Optional[str] = None, *,
                now: Optional[float] = None) -> Review:
        now = time.time() if now is None else now
        approver = approver or _whoami()
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                self._expire(db, now)
                row = self._row(db, review_id)
                self._verify(db, row)
                if row["status"] != "pending":
                    raise ReviewError("review {} is {}, not pending".format(review_id, row["status"]))
                allow_self, min_approvals, approval_ttl = self._policy(db, row)
                if not allow_self and approver == row["requester"]:
                    raise ReviewError("{} filed review {} and may not approve it".format(
                        approver, review_id))
                db.execute("INSERT OR IGNORE INTO approvals (review_id, approver, ts) VALUES (?, ?, ?)",
                           (review_id, approver, now))
                count = db.execute("SELECT COUNT(*) FROM approvals WHERE review_id = ?",
                                   (review_id,)).fetchone()[0]
                if count >= min_approvals:
                    db.execute("UPDATE reviews SET status = 'approved', decided = ?, decided_by = ?, "
                               "approval_until = ? WHERE id = ?",
                               (now, approver, now + approval_ttl, review_id))
                self._seal(db, review_id)
                seq = self._bump(db)
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
            review = self._review(db, self._row(db, review_id))
        self._advance(seq)
        return review

    def reject(self, review_id: str, reason: str = "", approver: Optional[str] = None, *,
               now: Optional[float] = None) -> Review:
        return self._settle(review_id, "rejected", ("pending",), approver, reason, now)

    def revoke(self, review_id: str, approver: Optional[str] = None, *,
               now: Optional[float] = None) -> Review:
        return self._settle(review_id, "revoked", ("pending", "approved"), approver, "", now)

    def get(self, review_id: str, *, now: Optional[float] = None) -> Review:
        now = time.time() if now is None else now
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                expired = self._expire(db, now)
                review = self._review(db, self._row(db, review_id))
                seq = self._bump(db) if expired else None
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        if seq is not None:
            self._advance(seq)
        return review

    def list(self, status: Optional[str] = None, limit: int = 50, *,
             now: Optional[float] = None) -> List[Review]:
        if status is not None and status not in STATUSES:
            raise ReviewError("status must be one of {}".format(", ".join(STATUSES)))
        now = time.time() if now is None else now
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                expired = self._expire(db, now)
                if status:
                    rows = db.execute("SELECT * FROM reviews WHERE status = ? ORDER BY created DESC "
                                      "LIMIT ?", (status, int(limit))).fetchall()
                else:
                    rows = db.execute("SELECT * FROM reviews ORDER BY created DESC LIMIT ?",
                                      (int(limit),)).fetchall()
                reviews = [self._review(db, row) for row in rows]
                seq = self._bump(db) if expired else None
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        if seq is not None:
            self._advance(seq)
        return reviews

    def wait(self, review_id: str, timeout: float, *, poll: float = 1.0) -> Review:
        """Poll until the review is no longer pending, or ``timeout`` passes."""
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            review = self.get(review_id)
            if review.status != "pending" or time.monotonic() >= deadline:
                return review
            time.sleep(min(poll, max(0.01, deadline - time.monotonic())))

    # --- internals ------------------------------------------------------------
    def _settle(self, review_id: str, status: str, allowed: tuple, approver: Optional[str],
                reason: str, now: Optional[float]) -> Review:
        now = time.time() if now is None else now
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                self._expire(db, now)
                current = self._row(db, review_id)
                self._verify(db, current)
                cursor = db.execute(
                    "UPDATE reviews SET status = ?, decided = ?, decided_by = ?, rejection_reason = ? "
                    "WHERE id = ? AND status IN ({})".format(",".join("?" * len(allowed))),
                    (status, now, approver or _whoami(), reason or None, review_id) + tuple(allowed))
                if cursor.rowcount != 1:
                    raise ReviewError("review {} is {}; cannot mark it {}".format(
                        review_id, current["status"], status))
                self._seal(db, review_id)
                seq = self._bump(db)
                review = self._review(db, self._row(db, review_id))
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        self._advance(seq)
        return review

    def _expire(self, db: sqlite3.Connection, now: float) -> int:
        """Expire stale rows; returns how many changed (each one is a write)."""
        stale = [row[0] for row in db.execute(
            "SELECT id FROM reviews WHERE (status = 'pending' AND pending_until <= ?) "
            "OR (status = 'approved' AND approval_until <= ?)", (now, now))]
        for review_id in stale:
            db.execute("UPDATE reviews SET status = 'expired' WHERE id = ?", (review_id,))
            self._seal(db, review_id)
        return len(stale)

    @staticmethod
    def _row(db: sqlite3.Connection, review_id: str) -> sqlite3.Row:
        row = db.execute("SELECT * FROM reviews WHERE id = ?", (review_id,)).fetchone()
        if row is None:
            raise ReviewError("no review {}".format(review_id))
        return row

    def _review(self, db: sqlite3.Connection, row: sqlite3.Row) -> Review:
        self._verify(db, row)
        approvers = [r[0] for r in db.execute(
            "SELECT approver FROM approvals WHERE review_id = ? ORDER BY ts", (row["id"],))]
        data = {k: row[k] for k in row.keys() if k not in ("binding", "mac")}
        # SQLite has no boolean type: keep the dataclass' types honest.
        data["allow_self_approval"] = bool(data.get("allow_self_approval", True))
        data["approval_ttl"] = float(data.get("approval_ttl", 900.0))
        return Review(approvers=approvers, **data)


def _whoami() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def _preview(request: ApprovalRequest) -> str:
    """What a reviewer is shown: the arguments, truncated. Stored in the
    review database (which must stay private), never in receipts."""
    args = request.event.args if request.event is not None else {}
    try:
        text = json.dumps(args, default=str, sort_keys=True)
    except Exception:
        text = repr(args)
    return text if len(text) <= 4000 else text[:4000] + "..."


def binding_hash(request: ApprovalRequest, *, bind_epoch: bool = True) -> str:
    """SHA-256 over what a review approves. ``bind_epoch=False`` leaves the
    policy epoch out, for engines whose epoch changes with every process
    (a Python ``PolicyEngine``); a declarative policy's epoch is a content hash
    and stays bound."""
    parts = [request.action, request.phase, request.args_digest, request.principal,
             request.policy_id, request.reason]
    if bind_epoch:
        parts.append(request.policy_epoch)
    parts.append(request.cwd)
    return hashlib.sha256(json.dumps(parts).encode("utf-8")).hexdigest()


def queue_approver(queue: Optional[ReviewQueue] = None, *, wait: float = 0.0,
                   poll: float = 1.0, bind_epoch: bool = True):
    """An approver (for :func:`interlock.set_approver`) backed by a review queue.

    ``wait=0`` (default) never holds the call: a new or pending review refuses
    it with the review id and what to do next. ``wait=N`` polls for up to N
    seconds first, for callers that can afford to hold.
    """
    the_queue = queue or ReviewQueue()

    def approver(request: ApprovalRequest) -> Any:
        binding = binding_hash(request, bind_epoch=bind_epoch)
        review = the_queue.lookup_or_file(binding, request)
        if review.status == "pending" and wait > 0:
            review = the_queue.wait(review.id, wait, poll=poll)
        if review.status == "approved" and the_queue.claim(review.id):
            return approve_once()
        return Declined(pending_message(review), pending=review.status == "pending")

    approver.queue = the_queue  # type: ignore[attr-defined]
    return approver


def pending_message(review: Review) -> str:
    if review.status == "pending":
        return ("review {0} is pending; a human must run `interlock reviews approve {0}`, "
                "then retry this identical call".format(review.id))
    if review.status == "approved":
        return "review {} was approved but its approval was already used".format(review.id)
    detail = ": {}".format(review.rejection_reason) if review.rejection_reason else ""
    return "review {} is {}{}".format(review.id, review.status, detail)
