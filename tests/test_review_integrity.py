"""The review database alone is not enough to approve a call.

The queue signs every row with a key kept beside (not inside) the database, so
a process that can write the SQLite file - but not read the key - cannot
promote a pending review, redirect an approval to another call, or forge the
approver names. These tests edit the database behind the queue's back and
expect a refusal, not a release.
"""
from __future__ import annotations

import os
import sqlite3
import stat

import pytest

from interlock import Decision
from interlock.approval import make_request
from interlock.event import SensorEvent
from interlock.reviews import ReviewError, ReviewQueue, binding_hash, default_key_path


def request_for(cmd="npm publish", reason="publishing"):
    event = SensorEvent("run", {"cmd": cmd}, principal="agent")
    return make_request(event, Decision.escalate(reason, "publish"), "epoch1")


@pytest.fixture
def queue(tmp_path):
    return ReviewQueue(str(tmp_path / "reviews.db"), pending_ttl=60, approval_ttl=30)


def filed(queue, cmd="npm publish", now=1000.0):
    request = request_for(cmd)
    review = queue.lookup_or_file(binding_hash(request), request, now=now)
    return review.id, request


def edit(path, sql, params=()):
    db = sqlite3.connect(path)
    try:
        db.execute(sql, params)
        db.commit()
    finally:
        db.close()


def test_key_is_private_and_outside_the_database(queue):
    assert queue.key_path == default_key_path(queue.path)
    assert queue.key_path != queue.path
    assert os.path.exists(queue.key_path)
    mode = stat.S_IMODE(os.stat(queue.key_path).st_mode)
    assert mode == 0o600


def test_a_forged_approval_is_refused(queue):
    review_id, _ = filed(queue)
    edit(queue.path,
         "UPDATE reviews SET status = 'approved', decided = 1001, decided_by = 'attacker', "
         "approval_until = 2000 WHERE id = ?", (review_id,))

    with pytest.raises(ReviewError, match="does not match its signature"):
        queue.claim(review_id, now=1002)
    with pytest.raises(ReviewError, match="does not match its signature"):
        queue.get(review_id, now=1002)


def test_redirecting_a_pending_review_is_refused(queue):
    """An attacker swaps the binding so a human's approval covers another call."""
    review_id, _ = filed(queue)
    edit(queue.path, "UPDATE reviews SET binding = 'someone-elses-call' WHERE id = ?", (review_id,))

    with pytest.raises(ReviewError, match="does not match its signature"):
        queue.approve(review_id, "bob", now=1001)


def test_swapping_the_preview_is_refused(queue):
    """The approver decides on the preview; editing it after filing must fail."""
    review_id, _ = filed(queue)
    edit(queue.path, "UPDATE reviews SET preview = '{\"cmd\": \"ls\"}' WHERE id = ?", (review_id,))

    with pytest.raises(ReviewError, match="does not match its signature"):
        queue.approve(review_id, "bob", now=1001)


def test_a_forged_approver_does_not_count(tmp_path):
    queue = ReviewQueue(str(tmp_path / "reviews.db"), min_approvals=2,
                        allow_self_approval=False, pending_ttl=60, approval_ttl=30)
    review_id, _ = filed(queue)

    queue.approve(review_id, "bob", now=1001)          # one real approval; still pending
    edit(queue.path,
         "INSERT INTO approvals (review_id, approver, ts) VALUES (?, 'mallory', 1001)", (review_id,))

    with pytest.raises(ReviewError, match="does not match its signature"):
        queue.approve(review_id, "dave", now=1002)    # would have made two
    # The refused queue is unreadable until a human removes the forged row -
    # fail closed, and say why, rather than quietly trusting the rest.
    with pytest.raises(ReviewError, match="does not match its signature"):
        queue.get(review_id, now=1002)
    db = sqlite3.connect(queue.path)
    try:
        status = db.execute("SELECT status FROM reviews WHERE id = ?", (review_id,)).fetchone()[0]
    finally:
        db.close()
    assert status == "pending"


def test_a_legitimate_approval_still_claims_once(queue):
    review_id, _ = filed(queue)
    queue.approve(review_id, "bob", now=1001)

    assert queue.claim(review_id, now=1002) is True
    assert queue.claim(review_id, now=1003) is False
    assert queue.get(review_id, now=1004).status == "executed"


def test_a_decision_signed_with_another_key_is_refused(tmp_path):
    """Replacing the key file invalidates every decision it did not sign."""
    path = str(tmp_path / "reviews.db")
    queue = ReviewQueue(path, pending_ttl=60, approval_ttl=30)
    review_id, _ = filed(queue)
    queue.approve(review_id, "bob", now=1001)

    os.unlink(queue.key_path)
    # The high-water mark is signed with the old key, so the queue refuses to
    # open at all until a human decides the rotation was real.
    with pytest.raises(ReviewError, match="does not match its signature"):
        ReviewQueue(path)

    # Even then, an operator who deletes the mark to accept the rotation is
    # left with rows the new key cannot vouch for.
    os.unlink(queue.key_path + ".head")
    reopened = ReviewQueue(path)
    with pytest.raises(ReviewError, match="does not match its signature"):
        reopened.claim(review_id, now=1002)


def test_an_explicit_key_ignores_the_key_file(tmp_path):
    path = str(tmp_path / "reviews.db")
    first = ReviewQueue(path, key=b"k" * 32, pending_ttl=60, approval_ttl=30)
    review_id, _ = filed(first)
    first.approve(review_id, "bob", now=1001)

    second = ReviewQueue(path, key=b"k" * 32)          # same key elsewhere
    assert second.claim(review_id, now=1002) is True
