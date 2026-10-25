"""A signed row cannot see a rollback; the high-water mark can.

Every row in the review database is signed, but a stored copy of an older
database is a perfectly valid set of signatures: restoring it replays whatever
was approved back then. These tests restore older copies behind the queue's
back and expect a refusal, while a mark that is merely *behind* the database
(a crash between the commit and the mark write) must heal rather than block.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import stat
import time

import pytest

from interlock import Decision
from interlock.approval import make_request
from interlock.cli import main
from interlock.event import SensorEvent
from interlock.reviews import (HEAD_VERSION, ReviewError, ReviewQueue, binding_hash,
                              default_head_path)


def request_for(cmd="npm publish"):
    event = SensorEvent("run", {"cmd": cmd}, principal="agent")
    return make_request(event, Decision.escalate("publishing", "publish"), "epoch1")


def filed(queue, now=1000.0, cmd="npm publish"):
    request = request_for(cmd)
    return queue.lookup_or_file(binding_hash(request), request, now=now).id


def seq(path):
    db = sqlite3.connect(path)
    try:
        return db.execute("SELECT seq FROM settings WHERE id = 1").fetchone()[0]
    finally:
        db.close()


def head(path):
    with open(path, "rb") as fh:
        return json.loads(fh.read().decode("utf-8"))


def test_restoring_an_older_database_is_refused(tmp_path):
    path = str(tmp_path / "reviews.db")
    older = str(tmp_path / "older.db")
    queue = ReviewQueue(path, pending_ttl=60, approval_ttl=30)
    review_id = filed(queue)

    shutil.copyfile(path, older)                 # signed row, no decision yet
    queue.approve(review_id, "bob", now=1001)    # now there is something to lose
    shutil.copyfile(older, path)                 # roll the file back

    with pytest.raises(ReviewError, match="behind its high-water mark"):
        ReviewQueue(path)


def test_the_mark_survives_restoring_the_key_too(tmp_path):
    """Move the mark off the restored volume; a database+key restore is still seen."""
    path = str(tmp_path / "reviews.db")
    marks = str(tmp_path / "marks" / "reviews.head")
    older_db = str(tmp_path / "older.db")
    older_key = str(tmp_path / "older.key")
    queue = ReviewQueue(path, head_path=marks, pending_ttl=60, approval_ttl=30)
    review_id = filed(queue)

    shutil.copyfile(path, older_db)
    shutil.copyfile(queue.key_path, older_key)
    queue.approve(review_id, "bob", now=1001)

    shutil.copyfile(older_db, path)
    shutil.copyfile(older_key, queue.key_path)
    with pytest.raises(ReviewError, match="behind its high-water mark"):
        ReviewQueue(path, head_path=marks)


def test_a_crash_between_commit_and_mark_heals_forward(tmp_path):
    path = str(tmp_path / "reviews.db")
    queue = ReviewQueue(path, pending_ttl=60, approval_ttl=30)
    review_id = filed(queue)
    assert head(queue.head_path)["seq"] == 1

    db = sqlite3.connect(path)                   # what a crash would leave behind
    try:
        db.execute("UPDATE settings SET seq = 4")
        db.commit()
    finally:
        db.close()

    reopened = ReviewQueue(path)
    assert head(reopened.head_path)["seq"] == 4
    assert reopened.get(review_id, now=1000.5).status == "pending"


def test_a_mark_signed_with_another_key_is_refused(tmp_path):
    path = str(tmp_path / "reviews.db")
    queue = ReviewQueue(path, pending_ttl=60, approval_ttl=30)
    with open(queue.head_path, "w") as fh:
        json.dump({"version": HEAD_VERSION, "seq": 0, "mac": "0" * 64}, fh)

    with pytest.raises(ReviewError, match="does not match its signature"):
        ReviewQueue(path)


def test_an_unreadable_mark_is_refused(tmp_path):
    path = str(tmp_path / "reviews.db")
    queue = ReviewQueue(path, pending_ttl=60, approval_ttl=30)
    with open(queue.head_path, "w") as fh:
        fh.write("not json")

    with pytest.raises(ReviewError, match="not valid JSON"):
        ReviewQueue(path)


def test_reads_do_not_advance_the_mark(tmp_path):
    path = str(tmp_path / "reviews.db")
    queue = ReviewQueue(path, pending_ttl=60, approval_ttl=30)
    review_id = filed(queue)
    assert seq(path) == 1

    queue.get(review_id, now=1000.5)
    queue.list(now=1000.5)
    assert seq(path) == 1


def test_a_state_change_advances_the_mark_once(tmp_path):
    path = str(tmp_path / "reviews.db")
    queue = ReviewQueue(path, pending_ttl=60, approval_ttl=30)
    review_id = filed(queue)
    assert seq(path) == 1

    queue.approve(review_id, "bob", now=1001)
    assert seq(path) == 2
    queue.claim(review_id, now=1002)
    assert seq(path) == 3
    assert head(queue.head_path)["seq"] == 3


def test_the_mark_never_moves_backwards(tmp_path):
    """A second writer that commits first must not be overwritten by a stale one."""
    path = str(tmp_path / "reviews.db")
    slow = ReviewQueue(path, pending_ttl=60, approval_ttl=30)
    fast = ReviewQueue(path, pending_ttl=60, approval_ttl=30)
    filed(fast, now=1000.0)                       # seq 1
    filed(fast, now=1001.0, cmd="npm publish --tag next")   # seq 2, mark 2
    assert head(slow.head_path)["seq"] == 2

    slow._advance(1)                              # the stale write a race produces
    assert head(slow.head_path)["seq"] == 2


def test_an_expiry_counts_as_a_change(tmp_path):
    path = str(tmp_path / "reviews.db")
    queue = ReviewQueue(path, pending_ttl=60, approval_ttl=30)
    review_id = filed(queue, now=1000.0)

    assert queue.get(review_id, now=2000.0).status == "expired"
    assert seq(path) == 2


def test_the_mark_can_live_in_its_own_directory(tmp_path):
    path = str(tmp_path / "reviews.db")
    marks = str(tmp_path / "marks" / "reviews.head")
    queue = ReviewQueue(path, head_path=marks, pending_ttl=60, approval_ttl=30)
    filed(queue)

    assert os.path.exists(marks)
    assert not os.path.exists(default_head_path(queue.key_path))
    assert stat.S_IMODE(os.stat(marks).st_mode) == 0o600


def test_the_cli_accepts_an_explicit_key_and_mark(tmp_path, capsys):
    path = str(tmp_path / "reviews.db")
    key = str(tmp_path / "other.key")
    marks = str(tmp_path / "marks" / "reviews.head")
    queue = ReviewQueue(path, key_path=key, head_path=marks, pending_ttl=60, approval_ttl=30)
    filed(queue, now=time.time())

    base = ["reviews", "--db", path, "--key", key, "--head", marks]
    assert main(base + ["--json", "list"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["status"] == "pending"

    # A default-key open cannot verify the mark, and refuses before listing.
    assert main(["reviews", "--db", path, "list"]) == 1
    assert "does not match its signature" in capsys.readouterr().err
