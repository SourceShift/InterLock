"""A grant that names the grant that delegated its authority (F8).

The plane has always signed *who* decided. These tests cover the harder
auditor question - was that authority valid at the moment it was used - by
walking ``parent_grant``: the parent envelope must be one the host was given,
verify under the same approval key for the same org and host, be an
``approve``, and have been inside its own lifetime when the child was issued.
A grant with no parent behaves exactly as before, so every existing chain
still verifies.
"""
from __future__ import annotations

import time

import pytest

from interlock.cloud.connector.grants import GrantProcessor, initial_state, load_state
from interlock.cloud.grants import (
    GENESIS,
    MAX_ANCESTRY_DEPTH,
    GrantError,
    ancestry_chain,
    approval_public_key,
    sign_grant,
    verify_grant,
)
from interlock.reviews import ReviewQueue

SEED = bytes(range(32))
OTHER_SEED = bytes(range(1, 33))
KEY = approval_public_key(SEED)

#: Wall-clock "now": the queue interprets its own timestamps against real
#: time, while ``verify_grant`` is pinned here.
NOW = time.time()


def _body(grant_id, *, review_id="r-1", decision="approve", issued=NOW,
          expires=NOW + 300, parent=None, seq=1, prev=GENESIS,
          org="org-1", host="host-1", binding="b" * 64):
    body = {
        "v": 1, "grant_id": grant_id, "org_id": org, "host_id": host,
        "review_id": review_id, "binding": binding, "decision": decision,
        "approver": {"issuer": "https://idp", "subject": "alice"},
        "step_up": {"method": "webauthn", "at": issued},
        "issued_at": issued, "expires_at": expires, "seq": seq, "prev": prev,
    }
    if parent is not None:
        body["parent_grant"] = parent
    return body


def _grant(grant_id, *, seed=SEED, **kwargs):
    return sign_grant(seed, _body(grant_id, **kwargs))


def _verify(grant, *, parents=None, now=NOW + 10, key=KEY):
    return verify_grant(grant, key, org_id="org-1", host_id="host-1",
                        now=now, parents=parents)


# --- the signing side ------------------------------------------------------

def test_a_parent_link_must_be_a_non_empty_id():
    with pytest.raises(GrantError, match="parent_grant"):
        sign_grant(SEED, _body("g-2", parent=""))
    with pytest.raises(GrantError, match="parent_grant"):
        sign_grant(SEED, _body("g-2", parent=7))


def test_a_grant_may_not_name_itself_as_its_parent():
    with pytest.raises(GrantError, match="itself"):
        sign_grant(SEED, _body("g-loop", parent="g-loop"))


# --- the verification side -------------------------------------------------

def test_a_grant_without_a_parent_verifies_with_no_parents_at_all():
    assert _verify(_grant("g-1")) is None


def test_a_grant_with_a_valid_parent_verifies():
    parent = _grant("g-operator")
    child = _grant("g-review", parent="g-operator")
    assert _verify(child, parents={"g-operator": parent}) is None


def test_a_parent_the_host_was_not_given_is_refused():
    child = _grant("g-review", parent="g-operator")
    assert _verify(child, parents={}) == "ancestry"
    assert _verify(child) == "ancestry"


def test_a_parent_under_another_key_cannot_delegate():
    parent = _grant("g-operator", seed=OTHER_SEED)
    child = _grant("g-review", parent="g-operator")
    assert _verify(child, parents={"g-operator": parent}) == "ancestry"


def test_only_an_approval_can_delegate_authority():
    parent = _grant("g-operator", decision="reject")
    child = _grant("g-review", parent="g-operator")
    assert _verify(child, parents={"g-operator": parent}) == "ancestry"


def test_a_parent_for_another_org_or_host_is_refused():
    other_org = _grant("g-operator", org="org-2")
    other_host = _grant("g-host2", host="host-2")
    child = _grant("g-review", parent="g-operator")
    assert _verify(child, parents={"g-operator": other_org}) == "ancestry"
    child2 = _grant("g-review", parent="g-host2")
    assert _verify(child2, parents={"g-host2": other_host}) == "ancestry"


def test_a_child_issued_before_its_parent_cannot_claim_it():
    parent = _grant("g-operator")
    child = _grant("g-review", parent="g-operator",
                   issued=NOW - 100, expires=NOW + 50)
    assert _verify(child, parents={"g-operator": parent}) == "ancestry"


def test_a_lapsed_parent_cannot_delegate_at_the_moment_of_use():
    # The parent was valid an hour ago and is expired now; the child was
    # issued after the parent lapsed, so the authority had already gone.
    parent = _grant("g-operator", issued=NOW - 400, expires=NOW - 100)
    child = _grant("g-review", parent="g-operator",
                   issued=NOW - 10, expires=NOW + 200)
    assert _verify(child, parents={"g-operator": parent}) == "ancestry"


def test_a_grandparent_chain_is_walked_oldest_link_last():
    operator = _grant("g-operator")
    reviewer = _grant("g-reviewer", parent="g-operator")
    child = _grant("g-review", parent="g-reviewer")
    parents = {"g-operator": operator, "g-reviewer": reviewer}
    assert _verify(child, parents=parents) is None


def test_a_chain_longer_than_the_cap_is_refused():
    parents = {}
    previous = None
    envelope = None
    for index in range(MAX_ANCESTRY_DEPTH + 2):
        grant_id = "g-{}".format(index)
        envelope = _grant(grant_id, parent=previous, seq=index + 1)
        parents[grant_id] = envelope
        previous = grant_id
    assert envelope is not None
    assert _verify(envelope, parents=parents) == "ancestry"


def test_the_parent_source_may_be_a_callable():
    parent = _grant("g-operator")
    child = _grant("g-review", parent="g-operator")
    asked = []

    def lookup(grant_id):
        asked.append(grant_id)
        return parent if grant_id == "g-operator" else None

    assert _verify(child, parents=lookup) is None
    assert asked == ["g-operator"]


def test_a_parent_source_that_raises_is_a_missing_parent_not_a_crash():
    def broken(grant_id):
        raise RuntimeError("storage went away")

    child = _grant("g-review", parent="g-operator")
    assert _verify(child, parents=broken) == "ancestry"


def test_a_parent_whose_id_differs_from_the_link_is_refused():
    # Names g-operator but its signed body says something else: the host
    # looks up by id, so a mismatch means the store handed back a wrong row.
    parent = _grant("g-somebody-else")
    child = _grant("g-review", parent="g-operator")
    assert _verify(child, parents={"g-operator": parent}) == "ancestry"


# --- naming the chain ------------------------------------------------------

def test_ancestry_chain_names_grants_oldest_first():
    operator = _grant("g-operator")
    reviewer = _grant("g-reviewer", parent="g-operator")
    child = _grant("g-review", parent="g-reviewer")
    parents = {"g-operator": operator, "g-reviewer": reviewer}
    assert ancestry_chain(child, parents) == ["g-operator", "g-reviewer"]


def test_ancestry_chain_of_a_direct_grant_is_empty():
    assert ancestry_chain(_grant("g-1")) == []


def test_ancestry_chain_stops_at_a_repeated_id():
    # Two hand-made envelopes pointing at each other: the walk is bounded, so
    # a corrupt store cannot make a receipt's authority list unbounded.
    looped = {"grant_id": "a", "parent_grant": "b"}
    parents = {"b": {"grant_id": "b", "parent_grant": "a"}}
    assert ancestry_chain(looped, parents) == ["b"]


# --- the host side ---------------------------------------------------------

@pytest.fixture
def queue(tmp_path):
    return ReviewQueue(str(tmp_path / "reviews.db"))


def _file(queue, cmd="npm publish", *, now=None):
    from interlock import Decision
    from interlock.approval import make_request
    from interlock.event import SensorEvent
    from interlock.reviews import binding_hash

    event = SensorEvent("run", {"cmd": cmd}, principal="agent")
    request = make_request(event, Decision.escalate("publishing", "publish"),
                           "epoch1")
    return queue.lookup_or_file(binding_hash(request), request,
                                now=time.time() if now is None else now)


def _processor(queue):
    return GrantProcessor(queue, public_key=KEY, org_id="org-1",
                          host_id="host-1")


def _apply(queue, grant):
    queue.apply_grant(grant, binding=queue.binding_of(grant["review_id"]))


def _bound(queue, review, **kwargs):
    """A grant whose binding is the review's own - what the plane signs."""
    return _grant(binding=queue.binding_of(review.id), review_id=review.id,
                  **kwargs)


def test_the_queue_records_the_parent_and_names_the_chain(queue):
    parent_review = _file(queue, "npm publish")
    child_review = _file(queue, "git push")
    operator = _bound(queue, parent_review, grant_id="g-operator")
    review = _bound(queue, child_review, grant_id="g-review", parent="g-operator",
                    seq=2, prev=operator["sig"])
    _apply(queue, operator)
    _apply(queue, review)

    assert queue.grant_for(child_review.id) == "g-review"
    assert queue.grant_ancestry(child_review.id) == ["g-operator"]
    # The grant that settled the parent review has no delegation behind it.
    assert queue.grant_ancestry(parent_review.id) == []


def test_a_local_decision_has_no_ancestry(queue):
    review = _file(queue, "npm publish")
    assert queue.grant_ancestry(review.id) == []


def test_the_connector_applies_a_child_whose_parent_it_applied(queue):
    parent_review = _file(queue, "npm publish")
    child_review = _file(queue, "git push")
    operator = _bound(queue, parent_review, grant_id="g-operator")
    review = _bound(queue, child_review, grant_id="g-review", parent="g-operator",
                    seq=2, prev=operator["sig"])
    state = initial_state()

    result = _processor(queue).process([operator, review], state)

    assert result["applied"] == ["g-operator", "g-review"]
    assert result["refusals"] == []
    assert state["last_grant_applied"]["authority"] == ["g-operator"]
    assert queue.grant_ancestry(child_review.id) == ["g-operator"]


def test_the_connector_refuses_a_child_before_its_parent(queue):
    child_review = _file(queue, "git push")
    review = _bound(queue, child_review, grant_id="g-review", parent="g-operator")
    state = initial_state()

    result = _processor(queue).process([review], state)

    assert result["applied"] == []
    assert result["refusals"] == [{"grant_id": "g-review", "code": "ancestry"}]
    assert state["last_grant_refusal"]["code"] == "ancestry"
    assert queue.get(child_review.id).status == "pending"


def test_the_connector_refuses_a_child_of_a_rejected_grant(queue):
    # The parent is a live, applied-looking envelope the host was given, but
    # it rejected its review: a rejection delegates nothing, so the child is
    # refused even though the parent's signature and timing are fine.
    parent_review = _file(queue, "npm publish")
    child_review = _file(queue, "git push")
    operator = _bound(queue, parent_review, grant_id="g-operator", decision="reject")
    review = _bound(queue, child_review, grant_id="g-review", parent="g-operator",
                    seq=2, prev=operator["sig"])
    state = initial_state()

    result = _processor(queue).process([operator, review], state)

    assert result["refusals"] == [{"grant_id": "g-review", "code": "ancestry"}]
    assert queue.get(child_review.id).status == "pending"


def test_the_kept_envelopes_are_bounded_and_reloadable(queue):
    state = initial_state()
    parent_review = _file(queue, "npm publish")
    operator = _bound(queue, parent_review, grant_id="g-operator")
    processor = GrantProcessor(queue, public_key=KEY, org_id="org-1",
                               host_id="host-1", ancestry_cap=1)
    processor.process([operator], state)
    assert list(state["grant_envelopes"]) == ["g-operator"]

    reloaded = load_state(state)
    assert reloaded["grant_envelopes"]["g-operator"]["grant_id"] == "g-operator"
    # A malformed store entry is dropped rather than trusted.
    assert load_state({"grant_envelopes": {"x": "not-an-envelope"}})["grant_envelopes"] == {}
