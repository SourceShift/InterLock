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

Statuses: ``pending``, ``approved``, ``rejected``, ``revoked``, ``expired``,
``executed`` (an approval that was used).
"""
from __future__ import annotations

import getpass
import hashlib
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
    min_approvals INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS reviews_binding ON reviews (binding, status);
CREATE TABLE IF NOT EXISTS approvals (
    review_id TEXT NOT NULL,
    approver TEXT NOT NULL,
    ts REAL NOT NULL,
    PRIMARY KEY (review_id, approver)
);
"""


def default_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".interlock", "reviews.db")


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
                 allow_self_approval: bool = True) -> None:
        if pending_ttl <= 0 or approval_ttl <= 0:
            raise ValueError("pending_ttl and approval_ttl must be positive")
        if min_approvals < 1:
            raise ValueError("min_approvals must be at least 1")
        self.path = path or default_path()
        self.pending_ttl = float(pending_ttl)
        self.approval_ttl = float(approval_ttl)
        self.min_approvals = int(min_approvals)
        self.allow_self_approval = allow_self_approval
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, mode=0o700, exist_ok=True)
        with self._db() as db:
            db.executescript(_SCHEMA)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

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
                self._expire(db, now)
                row = db.execute(
                    "SELECT * FROM reviews WHERE binding = ? AND (status IN ('pending', 'approved') "
                    "OR (status IN ('rejected', 'revoked') AND decided > ?)) "
                    "ORDER BY created DESC LIMIT 1", (binding, now - self.pending_ttl)).fetchone()
                # A recent rejection is the answer: retrying the identical call
                # must not file a fresh review and ask the human again.
                if row is None:
                    review_id = "r-" + secrets.token_hex(4)
                    db.execute(
                        "INSERT INTO reviews (id, binding, status, action, phase, principal, "
                        "requester, policy_id, reason, args_digest, preview, created, "
                        "pending_until, min_approvals) VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?, "
                        "?, ?, ?, ?, ?)",
                        (review_id, binding, request.action, request.phase, request.principal,
                         _whoami(), request.policy_id, request.reason, request.args_digest,
                         _preview(request), now, now + self.pending_ttl, self.min_approvals))
                    row = db.execute("SELECT * FROM reviews WHERE id = ?", (review_id,)).fetchone()
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
            return self._review(db, row)

    def claim(self, review_id: str, *, now: Optional[float] = None) -> bool:
        """Use an approval, once. True for exactly one caller."""
        now = time.time() if now is None else now
        with self._db() as db:
            cursor = db.execute(
                "UPDATE reviews SET status = 'executed', executed = ? "
                "WHERE id = ? AND status = 'approved' AND approval_until > ?",
                (now, review_id, now))
            return cursor.rowcount == 1

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
                if row["status"] != "pending":
                    raise ReviewError("review {} is {}, not pending".format(review_id, row["status"]))
                if not self.allow_self_approval and approver == row["requester"]:
                    raise ReviewError("{} filed review {} and may not approve it".format(
                        approver, review_id))
                db.execute("INSERT OR IGNORE INTO approvals (review_id, approver, ts) VALUES (?, ?, ?)",
                           (review_id, approver, now))
                count = db.execute("SELECT COUNT(*) FROM approvals WHERE review_id = ?",
                                   (review_id,)).fetchone()[0]
                if count >= row["min_approvals"]:
                    db.execute("UPDATE reviews SET status = 'approved', decided = ?, decided_by = ?, "
                               "approval_until = ? WHERE id = ?",
                               (now, approver, now + self.approval_ttl, review_id))
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
            return self._review(db, self._row(db, review_id))

    def reject(self, review_id: str, reason: str = "", approver: Optional[str] = None, *,
               now: Optional[float] = None) -> Review:
        return self._settle(review_id, "rejected", ("pending",), approver, reason, now)

    def revoke(self, review_id: str, approver: Optional[str] = None, *,
               now: Optional[float] = None) -> Review:
        return self._settle(review_id, "revoked", ("pending", "approved"), approver, "", now)

    def get(self, review_id: str, *, now: Optional[float] = None) -> Review:
        with self._db() as db:
            self._expire(db, time.time() if now is None else now)
            return self._review(db, self._row(db, review_id))

    def list(self, status: Optional[str] = None, limit: int = 50, *,
             now: Optional[float] = None) -> List[Review]:
        if status is not None and status not in STATUSES:
            raise ReviewError("status must be one of {}".format(", ".join(STATUSES)))
        with self._db() as db:
            self._expire(db, time.time() if now is None else now)
            if status:
                rows = db.execute("SELECT * FROM reviews WHERE status = ? ORDER BY created DESC "
                                  "LIMIT ?", (status, int(limit))).fetchall()
            else:
                rows = db.execute("SELECT * FROM reviews ORDER BY created DESC LIMIT ?",
                                  (int(limit),)).fetchall()
            return [self._review(db, row) for row in rows]

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
            self._expire(db, now)
            cursor = db.execute(
                "UPDATE reviews SET status = ?, decided = ?, decided_by = ?, rejection_reason = ? "
                "WHERE id = ? AND status IN ({})".format(",".join("?" * len(allowed))),
                (status, now, approver or _whoami(), reason or None, review_id) + tuple(allowed))
            row = self._row(db, review_id)
            if cursor.rowcount != 1:
                raise ReviewError("review {} is {}; cannot mark it {}".format(
                    review_id, row["status"], status))
            return self._review(db, row)

    @staticmethod
    def _expire(db: sqlite3.Connection, now: float) -> None:
        db.execute("UPDATE reviews SET status = 'expired' WHERE status = 'pending' AND pending_until <= ?",
                   (now,))
        db.execute("UPDATE reviews SET status = 'expired' WHERE status = 'approved' "
                   "AND approval_until <= ?", (now,))

    @staticmethod
    def _row(db: sqlite3.Connection, review_id: str) -> sqlite3.Row:
        row = db.execute("SELECT * FROM reviews WHERE id = ?", (review_id,)).fetchone()
        if row is None:
            raise ReviewError("no review {}".format(review_id))
        return row

    @staticmethod
    def _review(db: sqlite3.Connection, row: sqlite3.Row) -> Review:
        approvers = [r[0] for r in db.execute(
            "SELECT approver FROM approvals WHERE review_id = ? ORDER BY ts", (row["id"],))]
        data = {k: row[k] for k in row.keys() if k != "binding"}
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
