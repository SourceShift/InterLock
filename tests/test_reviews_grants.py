"""The local queue's remote-decision bridge (C3, FR-027 .. FR-029).

``apply_grant`` is the *only* way a plane decision reaches a host's queue. It
is fail-closed and atomic: a bad binding, an expired grant, an unknown
decision or a review that is no longer pending changes nothing, and a
successful apply is indistinguishable from a local decision in the sealed row
except for ``decided_by``. These tests exercise that contract and prove the
one-use claim still holds afterwards.
"""
from __future__ import annotations

import pytest

from interlock import Decision
from interlock.approval import make_request
from interlock.event import SensorEvent
from interlock.reviews import (
    GrantRefused,
    ReviewError,
    ReviewQueue,
    binding_hash,
)


def _request(cmd="npm publish"):
    event = SensorEvent("run", {"cmd": cmd}, principal="agent")
    return make_request(event, Decision.escalate("publishing", "publish"), "epoch1")


def _file(queue, *, now=1000.0, cmd="npm publish"):
    request = _request(cmd)
    return queue.lookup_or_file(binding_hash(request), request, now=now)


def _grant(review_id, *, decision="approve", expires_at=1100.0,
           grant_id="g-1", approver=None):
    return {
        "v": 1, "grant_id": grant_id, "org_id": "org-1", "host_id": "host-1",
        "review_id": review_id, "binding": "ignored-by-local-check",
        "decision": decision,
        "approver": approver or {"issuer": "https://idp", "subject": "alice",
                                 "email": "alice@example.test"},
        "step_up": {"method": "webauthn", "at": 1001.0},
        "issued_at": 1000.0, "expires_at": expires_at, "seq": 1,
        "prev": "GENESIS", "sig": "00" * 64,
    }


@pytest.fixture
def queue(tmp_path):
    return ReviewQueue(str(tmp_path / "reviews.db"), pending_ttl=60,
                       approval_ttl=30)


def test_binding_of_is_the_stored_hash_and_unknown_ids_raise(queue):
    review = _file(queue)
    assert queue.binding_of(review.id) == binding_hash(_request())
    with pytest.raises(KeyError):
        queue.binding_of("r-missing")


def test_an_applied_approve_settles_and_stamps_the_grant(queue):
    review = _file(queue)
    settled = queue.apply_grant(_grant(review.id), binding=queue.binding_of(review.id),
                                now=1001.0)
    assert settled.status == "approved"
    assert settled.decided_by == "https://idp#alice"
    assert settled.approval_until == 1031.0  # min(now + 30, expires)
    assert queue.grant_for(review.id) == "g-1"
    assert queue.get(review.id, now=1002.0).status == "approved"  # MAC verifies
    assert queue.claim(review.id, now=1002.0)
    assert not queue.claim(review.id, now=1002.0)  # one use, remote or local


def test_a_local_approval_has_no_grant_stamp(queue):
    review = _file(queue)
    queue.approve(review.id, "alice", now=1001.0)
    assert queue.grant_for(review.id) is None


def test_the_local_ttl_and_grant_expiry_clamp_to_the_earlier(queue):
    review = _file(queue)
    settled = queue.apply_grant(
        _grant(review.id, expires_at=1010.0),
        binding=queue.binding_of(review.id), now=1001.0)
    assert settled.approval_until == 1010.0  # the grant, not now + 30


def test_a_wrong_binding_refuses_and_leaves_the_review_pending(queue):
    review = _file(queue)
    with pytest.raises(GrantRefused) as exc:
        queue.apply_grant(_grant(review.id), binding="not-the-binding", now=1001.0)
    assert exc.value.check == "binding"
    assert queue.get(review.id, now=1001.0).status == "pending"
    assert queue.grant_for(review.id) is None


def test_an_expired_grant_refuses_before_any_write(queue):
    review = _file(queue)
    with pytest.raises(GrantRefused) as exc:
        queue.apply_grant(_grant(review.id, expires_at=1000.0),
                          binding=queue.binding_of(review.id), now=1001.0)
    assert exc.value.check == "expiry"
    assert queue.get(review.id, now=1001.0).status == "pending"


def test_decision_must_be_approve_reject_or_revoke(queue):
    review = _file(queue)
    with pytest.raises(GrantRefused) as exc:
        queue.apply_grant(_grant(review.id, decision="maybe"),
                          binding=queue.binding_of(review.id), now=1001.0)
    assert exc.value.check == "decision"
    assert queue.get(review.id, now=1001.0).status == "pending"


def test_redelivery_is_an_idempotent_no_op(queue):
    review = _file(queue)
    grant = _grant(review.id)
    binding = queue.binding_of(review.id)
    first = queue.apply_grant(grant, binding=binding, now=1001.0)
    second = queue.apply_grant(grant, binding=binding, now=1002.0)
    assert first.status == second.status == "approved"
    assert queue.grant_for(review.id) == "g-1"
    assert queue.get(review.id, now=1002.0).approvers == ["https://idp#alice"]


def test_a_grant_id_reused_for_another_review_is_not_a_no_op(queue):
    first = _file(queue)
    second = _file(queue, cmd="npm publish --tag beta")
    queue.apply_grant(_grant(first.id), binding=queue.binding_of(first.id),
                      now=1001.0)
    with pytest.raises(GrantRefused) as exc:
        queue.apply_grant(_grant(second.id), binding=queue.binding_of(second.id),
                          now=1001.0)
    assert exc.value.check == "version"
    assert queue.get(second.id, now=1001.0).status == "pending"


def test_a_settled_review_refuses_a_different_grant(queue):
    review = _file(queue)
    binding = queue.binding_of(review.id)
    queue.apply_grant(_grant(review.id, grant_id="g-1"),
                      binding=binding, now=1001.0)
    with pytest.raises(GrantRefused) as exc:
        queue.apply_grant(_grant(review.id, decision="reject", grant_id="g-2"),
                          binding=binding, now=1002.0)
    assert exc.value.check == "status"
    assert queue.get(review.id, now=1002.0).status == "approved"


def test_reject_and_revoke_settle_their_own_statuses(tmp_path):
    queue = ReviewQueue(str(tmp_path / "r.db"))
    rejected = _file(queue)
    queue.apply_grant(_grant(rejected.id, decision="reject"),
                      binding=queue.binding_of(rejected.id), now=1001.0)
    assert queue.get(rejected.id, now=1001.0).status == "rejected"

    revoked = _file(queue, cmd="npm publish --tag beta")
    queue.apply_grant(_grant(revoked.id, decision="revoke", grant_id="g-2"),
                      binding=queue.binding_of(revoked.id), now=1001.0)
    assert queue.get(revoked.id, now=1001.0).status == "revoked"


def test_four_eyes_is_not_bypassed_by_a_grant(tmp_path):
    queue = ReviewQueue(str(tmp_path / "r.db"), min_approvals=2)
    review = _file(queue)
    with pytest.raises(GrantRefused) as exc:
        queue.apply_grant(_grant(review.id),
                          binding=queue.binding_of(review.id), now=1001.0)
    assert exc.value.check == "approvers"
    assert queue.get(review.id, now=1001.0).status == "pending"


def test_self_approval_is_not_bypassed_by_a_grant(tmp_path, monkeypatch):
    # The local requester label and the remote approver label are the same
    # person; the strict queue must refuse either way.
    identity = "https://idp#alice"
    monkeypatch.setattr("interlock.reviews._whoami", lambda: identity)
    strict = ReviewQueue(str(tmp_path / "r.db"), allow_self_approval=False)
    review = _file(strict)
    assert review.requester == identity
    with pytest.raises(GrantRefused) as exc:
        strict.apply_grant(_grant(review.id),
                           binding=strict.binding_of(review.id), now=1001.0)
    assert exc.value.check == "self_approval"
    assert strict.get(review.id, now=1001.0).status == "pending"


def test_a_malformed_grant_is_refused_before_the_transaction(queue):
    review = _file(queue)
    with pytest.raises(GrantRefused) as exc:
        queue.apply_grant({"decision": "approve"}, binding="x", now=1001.0)
    assert exc.value.check == "version"
    assert queue.get(review.id, now=1001.0).status == "pending"


def test_local_approve_and_reject_keep_working_after_a_refusal(queue):
    """A refused remote grant must not change local-first behaviour."""
    review = _file(queue)
    with pytest.raises(GrantRefused):
        queue.apply_grant(_grant(review.id), binding="wrong", now=1001.0)
    assert queue.approve(review.id, "alice", now=1002.0).status == "approved"

    other = _file(queue, cmd="npm publish --tag beta")
    with pytest.raises(GrantRefused):
        queue.apply_grant(_grant(other.id, expires_at=900.0),
                          binding=queue.binding_of(other.id), now=1000.5)
    assert queue.reject(other.id, "not today", "bob", now=1002.0).status == "rejected"


def test_unknown_review_is_a_review_error_not_a_silent_success(queue):
    with pytest.raises(ReviewError):
        queue.apply_grant(_grant("r-missing"), binding="b", now=1001.0)
