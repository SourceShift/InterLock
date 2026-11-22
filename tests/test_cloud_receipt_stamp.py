"""The receipt stamp for a remote decision (C3, FR-030).

A call released by a cloud grant is stamped ``approval="cloud:<grant_id>"``
in the sealed receipt, survives the chain check, and appears as its own row
in ``interlock report``'s escalations. A local approval keeps the existing
``approved:review <id>`` note, and an older queue without ``grant_for`` still
runs.
"""
from __future__ import annotations

import json
import time

import pytest

from interlock.adapters import get_adapter, run_hook
from interlock.policy.declarative import load_policy
from interlock.receipt import verify_chain
from interlock.report import summarize
from interlock.reviews import ReviewQueue
from interlock.sink import InMemorySink

PAYLOAD = {
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "npm publish"},
    "session_id": "s",
    "cwd": "/w",
}


@pytest.fixture
def sink():
    return InMemorySink()


def _engine():
    return load_policy({"extends": "builtin:coding-agent"})


def _pending(queue):
    pending = queue.list("pending")
    assert pending, "the hook should have filed a review"
    return pending[0]


def _remote_approve(queue, review_id, grant_id="g-deadbeef", *, parent=None):
    now = time.time()
    body = {
        "v": 1, "grant_id": grant_id, "org_id": "org-1", "host_id": "host-1",
        "review_id": review_id, "binding": queue.binding_of(review_id),
        "decision": "approve",
        "approver": {"issuer": "https://idp.example", "subject": "alice",
                     "email": "alice@example.test"},
        "step_up": {"method": "webauthn", "at": now},
        "issued_at": now, "expires_at": now + 300, "seq": 1,
        "prev": "GENESIS", "sig": "00" * 64,
    }
    if parent is not None:
        body["parent_grant"] = parent
    queue.apply_grant(body, binding=queue.binding_of(review_id), now=now)


def test_a_remote_grant_is_stamped_and_the_chain_still_verifies(tmp_path, sink):
    queue = ReviewQueue(str(tmp_path / "reviews.db"))
    adapter = get_adapter("codex")

    from interlock.receipt import set_sink

    set_sink(sink)
    try:
        _stdout, stderr, code = run_hook(adapter, PAYLOAD, _engine(), reviews=queue)
        assert code == 2 and "review" in stderr
        assert sink.receipts[-1].approval.startswith("pending:r-")
        review = _pending(queue)

        _remote_approve(queue, review.id, grant_id="g-deadbeef")

        # A new hook process sees the grant and runs the call.
        assert run_hook(adapter, PAYLOAD, _engine(), reviews=queue) == ("", "", 0)

        receipt = sink.receipts[-1]
        assert receipt.approval == "cloud:g-deadbeef"
        assert receipt.verdict == "ALLOW"
        # The stamp is part of the sealed receipt, not a reporting-only note.
        assert verify_chain(sink.receipts, sink._signer, sink._key) is None
        assert sink.verify() is None
        assert queue.get(review.id).status == "executed"
    finally:
        set_sink(None)


def test_the_stamp_appears_as_its_own_escalation_row(tmp_path, sink):
    queue = ReviewQueue(str(tmp_path / "reviews.db"))
    from interlock.receipt import set_sink

    set_sink(sink)
    try:
        run_hook(get_adapter("codex"), PAYLOAD, _engine(), reviews=queue)
        review = _pending(queue)
        _remote_approve(queue, review.id, grant_id="g-42")
        run_hook(get_adapter("codex"), PAYLOAD, _engine(), reviews=queue)

        report = summarize(sink.receipts)
        # The first, refused attempt is its own pending row; the released call
        # is attributed to the grant that released it.
        assert report["escalations"]["cloud:g-42"] == 1
        assert report["escalations"]["pending:" + review.id] == 1
        assert report["verdicts"]["ALLOW"] == 1
        assert report["totals"]["calls"] >= 1
        # The report's escalation row carries the grant id verbatim.
        assert "cloud:g-42" in json.dumps(report)
    finally:
        set_sink(None)


def test_a_local_approval_keeps_the_review_note(tmp_path, sink):
    queue = ReviewQueue(str(tmp_path / "reviews.db"))
    from interlock.receipt import set_sink

    set_sink(sink)
    try:
        run_hook(get_adapter("codex"), PAYLOAD, _engine(), reviews=queue)
        review = _pending(queue)
        queue.approve(review.id, "alice")
        run_hook(get_adapter("codex"), PAYLOAD, _engine(), reviews=queue)

        assert sink.receipts[-1].approval == "approved:review " + review.id
        escalations = summarize(sink.receipts)["escalations"]
        assert escalations["approved:review " + review.id] == 1
        assert sink.verify() is None
    finally:
        set_sink(None)


def test_a_queue_without_grant_for_still_uses_the_local_note(tmp_path, sink):
    queue = ReviewQueue(str(tmp_path / "reviews.db"))

    class _OlderQueue(ReviewQueue):
        # A pre-C3 queue has no method at all; the adapter must fall back.
        grant_for = None

    from interlock.receipt import set_sink

    set_sink(sink)
    try:
        run_hook(get_adapter("codex"), PAYLOAD, _engine(), reviews=queue)
        review = _pending(queue)
        _remote_approve(queue, review.id, grant_id="g-hidden")

        older = _OlderQueue(str(queue.path))
        assert run_hook(get_adapter("codex"), PAYLOAD, _engine(),
                        reviews=older) == ("", "", 0)
        assert sink.receipts[-1].approval == "approved:review " + review.id
    finally:
        set_sink(None)


def test_a_cloud_stamp_does_not_confuse_the_one_use_claim(tmp_path, sink):
    queue = ReviewQueue(str(tmp_path / "reviews.db"))
    from interlock.receipt import set_sink

    set_sink(sink)
    try:
        run_hook(get_adapter("codex"), PAYLOAD, _engine(), reviews=queue)
        review = _pending(queue)
        _remote_approve(queue, review.id, grant_id="g-once")
        assert run_hook(get_adapter("codex"), PAYLOAD, _engine(),
                        reviews=queue)[2] == 0
        assert sink.receipts[-1].approval == "cloud:g-once"

        # The identical retry is a fresh escalation, not a second execution.
        _stdout, stderr, code = run_hook(get_adapter("codex"), PAYLOAD,
                                         _engine(), reviews=queue)
        assert code == 2
        assert "review" in stderr
        assert sink.receipts[-1].approval.startswith("pending:r-")
    finally:
        set_sink(None)


def test_a_delegated_grant_stamps_the_chain_it_descends_from(tmp_path, sink):
    """A grant released under another grant's authority names that chain.

    ``approval`` answers "which grant settled this call"; ``authority``
    answers "which grant authorised that one", which is the question an
    auditor asks when the review itself is no longer the interesting part.
    """
    queue = ReviewQueue(str(tmp_path / "reviews.db"))
    from interlock.receipt import set_sink

    set_sink(sink)
    try:
        run_hook(get_adapter("codex"), PAYLOAD, _engine(), reviews=queue)
        operator_review = _pending(queue)
        _remote_approve(queue, operator_review.id, grant_id="g-operator")

        # A different cwd is a different binding, so this is a second review
        # rather than a retry of the first one.
        second = dict(PAYLOAD, cwd="/w2")
        run_hook(get_adapter("codex"), second, _engine(), reviews=queue)
        review = [item for item in queue.list("pending")
                  if item.id != operator_review.id][0]
        _remote_approve(queue, review.id, grant_id="g-review",
                        parent="g-operator")

        assert run_hook(get_adapter("codex"), second, _engine(),
                        reviews=queue) == ("", "", 0)

        receipt = sink.receipts[-1]
        assert receipt.approval == "cloud:g-review"
        assert receipt.authority == "cloud:g-operator"
        # The chain rides inside the sealed receipt and its MAC still verifies.
        assert verify_chain(sink.receipts, sink._signer, sink._key) is None
        assert sink.verify() is None
    finally:
        set_sink(None)


def test_a_direct_grant_stamps_no_authority(tmp_path, sink):
    queue = ReviewQueue(str(tmp_path / "reviews.db"))
    from interlock.receipt import set_sink

    set_sink(sink)
    try:
        run_hook(get_adapter("codex"), PAYLOAD, _engine(), reviews=queue)
        review = _pending(queue)
        _remote_approve(queue, review.id, grant_id="g-direct")

        assert run_hook(get_adapter("codex"), PAYLOAD, _engine(),
                        reviews=queue) == ("", "", 0)

        receipt = sink.receipts[-1]
        assert receipt.approval == "cloud:g-direct"
        # A grant the plane signed itself delegates from nothing: the field is
        # omitted entirely, so the receipt is byte-identical to a pre-F8 one.
        assert receipt.authority is None
        assert "authority" not in receipt.fields()
    finally:
        set_sink(None)
