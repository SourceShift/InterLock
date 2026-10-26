"""Grant verification, application and acknowledgement on the host (C3).

The connector is the untrusted side of the decision: it checks the chain,
applies a grant atomically through the local queue, and acknowledges only
what it has applied or refused. These tests drive a real
:class:`~interlock.reviews.ReviewQueue` and real Ed25519 envelopes, so a
signature, seq/prev link or binding failure is the same one production hits.
"""
from __future__ import annotations

import json
import time

import pytest

from interlock import Decision
from interlock.approval import make_request
from interlock.cloud.connector.config import CloudHome
from interlock.cloud.connector.grants import (
    DEDUPE_CAP,
    GrantProcessor,
    initial_state,
    load_state,
    public_key_from_config,
)
from interlock.cloud.connector.runner import Connector
from interlock.cloud.connector.transport import FakeTransport, TransportError
from interlock.cloud.enrollment import generate_agent_key
from interlock.cloud.grants import (
    GENESIS,
    approval_public_key,
    approval_public_key_hex,
    generate_seed,
    sign_grant,
)
from interlock.cloud.identity import (
    generate_host_seed,
    key_id,
    public_key_hex,
)
from interlock.event import SensorEvent
from interlock.reviews import ReviewQueue, binding_hash

#: Wall-clock "now": the queue is a local store and interprets its own
#: timestamps against real time, while the processor's clock is pinned here.
NOW = time.time()


class _Clock:
    def __init__(self, value=NOW):
        self.value = float(value)

    def __call__(self):
        return self.value


def _request(cmd):
    event = SensorEvent("run", {"cmd": cmd}, principal="agent")
    return make_request(event, Decision.escalate("publishing", "publish"),
                        "epoch1")


def _file(queue, cmd="npm publish", *, now=NOW):
    request = _request(cmd)
    return queue.lookup_or_file(binding_hash(request), request, now=now)


def _grant(seed, review_id, binding, *, seq=1, prev=GENESIS,
           decision="approve", org="org-1", host="host-1",
           grant_id=None, issued=NOW, expires=NOW + 300):
    return sign_grant(seed, {
        "v": 1, "grant_id": grant_id or "g-{}".format(seq),
        "org_id": org, "host_id": host, "review_id": review_id,
        "binding": binding, "decision": decision,
        "approver": {"issuer": "https://idp", "subject": "alice",
                     "email": "alice@example.test"},
        "step_up": {"method": "webauthn", "at": issued},
        "issued_at": issued, "expires_at": expires, "seq": seq, "prev": prev,
    })


def _queue(tmp_path, name="reviews.db", **kwargs):
    return ReviewQueue(str(tmp_path / name), **kwargs)


def _processor(queue, seed, *, clock=None, org="org-1", host="host-1"):
    return GrantProcessor(queue, public_key=approval_public_key(seed),
                          org_id=org, host_id=host, clock=clock or _Clock())


class _Adapter:
    """What the processor needs; deliberately no ``list`` so the connector
    does not upload anything during a grant test."""

    def __init__(self, queue):
        self.queue = queue

    def binding_of(self, review_id):
        return self.queue.binding_of(review_id)

    def get(self, review_id):
        return self.queue.get(review_id)

    def apply_grant(self, grant, *, binding):
        return self.queue.apply_grant(grant, binding=binding)


def _home(tmp_path, approval_hex):
    home = CloudHome(tmp_path / "home")
    raw, _prefix, _digest = generate_agent_key()
    seed = generate_host_seed()
    host_public = public_key_hex(seed)
    home.save({
        "url": "https://cloud.example",
        "org_id": "org-1",
        "host_id": "host-1",
        "agent_key_id": "key-1",
        "agent_key": raw,
        "host_key_id": key_id(host_public),
        "host_public_key": host_public,
        "plane_public_keys": {"approval": approval_hex, "policy": "",
                              "receipt": ""},
        "spool_dir": "spool",
        "state_dir": "state",
    })
    home.save_seed(seed)
    return home, raw


def _connector(tmp_path, responses, *, seed, queue=None, clock=None,
               max_attempts=4):
    home, _raw = _home(tmp_path, approval_public_key_hex(seed))
    transport = FakeTransport(responses)
    connector = Connector(home, transport, queue=queue,
                          clock=clock or _Clock(), max_attempts=max_attempts)
    return connector, transport


def _state(connector):
    return json.loads(connector.state_path.read_text(encoding="utf-8"))


# -- the processor ------------------------------------------------------

def test_a_valid_grant_is_applied_and_the_chain_advances(tmp_path):
    seed = generate_seed()
    queue = _queue(tmp_path)
    review = _file(queue)
    grant = _grant(seed, review.id, queue.binding_of(review.id))
    state = initial_state()

    outcome = _processor(queue, seed).process([grant], state)

    assert outcome == {"applied": [grant["grant_id"]],
                       "acked": [grant["grant_id"]],
                       "refusals": [], "local": []}
    assert queue.get(review.id).status == "approved"
    assert queue.grant_for(review.id) == grant["grant_id"]
    assert state["grant_last_seq"] == 1
    assert state["grant_last_sig"] == grant["sig"]
    assert state["grants_applied"] == 1
    assert state["grants_acked"] == 1
    assert state["last_grant_applied"] == {
        "grant_id": grant["grant_id"], "review_id": review.id,
        "decision": "approve", "seq": 1, "at": NOW,
    }


def test_bad_signatures_are_refused_and_reported_but_not_acked(tmp_path):
    seed = generate_seed()
    queue = _queue(tmp_path)
    review = _file(queue)
    grant = _grant(seed, review.id, queue.binding_of(review.id))
    grant["sig"] = ("00" * 64)
    state = initial_state()

    outcome = _processor(queue, seed).process([grant], state)

    assert outcome["applied"] == [] and outcome["acked"] == []
    assert outcome["refusals"] == [{"grant_id": grant["grant_id"],
                                    "code": "signature"}]
    assert queue.get(review.id).status == "pending"
    assert state["grants_refused"] == 1
    assert state["last_grant_refusal"] == {
        "grant_id": grant["grant_id"], "code": "signature", "at": NOW,
    }
    assert state["grant_last_seq"] == 0


def test_org_host_and_binding_are_checked_before_anything_is_applied(tmp_path):
    seed = generate_seed()
    queue = _queue(tmp_path)
    review = _file(queue)
    binding = queue.binding_of(review.id)
    processor = _processor(queue, seed)

    wrong_org = _grant(seed, review.id, binding, org="org-2",
                       grant_id="g-org")
    wrong_host = _grant(seed, review.id, binding, host="host-2",
                        grant_id="g-host")
    wrong_binding = _grant(seed, review.id, "f" * 64, grant_id="g-binding")
    state = initial_state()

    outcome = processor.process([wrong_org, wrong_host, wrong_binding], state)

    assert [item["code"] for item in outcome["refusals"]] == [
        "org", "host", "binding"]
    assert outcome["acked"] == []
    assert queue.get(review.id).status == "pending"
    assert state["grants_refused"] == 3


def test_an_unknown_review_is_a_binding_refusal(tmp_path):
    seed = generate_seed()
    queue = _queue(tmp_path)
    state = initial_state()
    grant = _grant(seed, "r-missing", "b" * 64)

    outcome = _processor(queue, seed).process([grant], state)

    assert outcome["refusals"] == [{"grant_id": grant["grant_id"],
                                    "code": "binding"}]
    assert state["grant_last_seq"] == 0


def test_the_seq_prev_chain_refuses_gaps_replays_and_orphans(tmp_path):
    seed = generate_seed()
    queue = _queue(tmp_path)
    processor = _processor(queue, seed)
    state = initial_state()

    first_review = _file(queue)
    first = _grant(seed, first_review.id, queue.binding_of(first_review.id),
                   seq=1, prev=GENESIS)
    assert processor.process([first], state)["applied"] == [first["grant_id"]]

    # An orphan: seq 3 whose prev names a signature this host never accepted.
    gap_review = _file(queue, "npm publish --tag gap")
    gap = _grant(seed, gap_review.id, queue.binding_of(gap_review.id),
                 seq=3, prev="ab" * 64, grant_id="g-gap")
    assert processor.process([gap], state)["refusals"][0]["code"] == "prev"

    # A replay of an old seq, even with a fresh signature.
    replay_review = _file(queue, "npm publish --tag replay")
    replay = _grant(seed, replay_review.id,
                    queue.binding_of(replay_review.id), seq=1,
                    prev=GENESIS, grant_id="g-replay")
    assert processor.process([replay], state)["refusals"][0]["code"] == "seq"

    # The honest continuation applies.
    second_review = _file(queue, "npm publish --tag next")
    second = _grant(seed, second_review.id,
                    queue.binding_of(second_review.id), seq=2,
                    prev=first["sig"], grant_id="g-second")
    assert processor.process([second], state)["applied"] == ["g-second"]
    assert state["grant_last_seq"] == 2
    assert state["grant_last_sig"] == second["sig"]


def test_a_redelivery_is_acked_once_and_never_reapplied(tmp_path):
    seed = generate_seed()
    queue = _queue(tmp_path)
    review = _file(queue)
    grant = _grant(seed, review.id, queue.binding_of(review.id))
    processor = _processor(queue, seed)
    state = initial_state()

    processor.process([grant], state)
    second = processor.process([grant], state)

    assert second["applied"] == []
    assert second["acked"] == [grant["grant_id"]]
    assert queue.get(review.id).approvers == ["https://idp#alice"]
    assert state["grants_applied"] == 1
    assert state["grants_acked"] == 2


def test_a_locally_settled_review_wins_and_is_acked_without_a_second_decision(
        tmp_path):
    seed = generate_seed()
    queue = _queue(tmp_path)
    review = _file(queue)
    queue.approve(review.id, "alice", now=NOW)
    grant = _grant(seed, review.id, queue.binding_of(review.id))
    state = initial_state()

    outcome = _processor(queue, seed).process([grant], state)

    assert outcome["applied"] == []
    assert outcome["acked"] == [grant["grant_id"]]
    assert outcome["local"] == [{"grant_id": grant["grant_id"],
                                 "status": "approved"}]
    assert queue.grant_for(review.id) is None
    assert state["grant_last_seq"] == 1
    assert state["grants_applied"] == 0


def test_reject_and_revoke_grants_settle_their_own_statuses(tmp_path):
    seed = generate_seed()
    queue = _queue(tmp_path)
    processor = _processor(queue, seed)
    state = initial_state()

    rejected = _file(queue)
    reject = _grant(seed, rejected.id, queue.binding_of(rejected.id),
                    decision="reject", grant_id="g-reject")
    assert processor.process([reject], state)["applied"] == ["g-reject"]
    assert queue.get(rejected.id).status == "rejected"

    revoked = _file(queue, "npm publish --tag beta")
    revoke = _grant(seed, revoked.id, queue.binding_of(revoked.id),
                    decision="revoke", seq=2, prev=reject["sig"],
                    grant_id="g-revoke")
    assert processor.process([revoke], state)["applied"] == ["g-revoke"]
    assert queue.get(revoked.id).status == "revoked"


def test_a_malformed_grant_is_a_version_refusal_not_a_crash(tmp_path):
    queue = _queue(tmp_path)
    state = initial_state()

    outcome = GrantProcessor(queue, public_key=b"\x00" * 32, org_id="org-1",
                             host_id="host-1", clock=_Clock()).process(
        [{"decision": "approve"}, "not-an-object", {"grant_id": "g"}], state)

    assert [item["code"] for item in outcome["refusals"]] == [
        "version", "version", "version"]
    assert outcome["acked"] == []


def test_the_dedupe_set_is_capped_and_drops_the_oldest(tmp_path):
    seed = generate_seed()
    queue = _queue(tmp_path)
    processor = _processor(queue, seed)
    processor.dedupe_cap = 2  # type: ignore[misc]
    state = initial_state()

    grants = []
    previous = GENESIS
    for index in range(3):
        review = _file(queue, "npm publish --tag {}".format(index))
        grant = _grant(seed, review.id, queue.binding_of(review.id),
                       seq=index + 1, prev=previous,
                       grant_id="g-{}".format(index + 1))
        previous = grant["sig"]
        grants.append(grant)

    for grant in grants:
        assert processor.process([grant], state)["applied"] == [grant["grant_id"]]

    assert state["seen_grants"] == ["g-2", "g-3"]
    assert state["grants_applied"] == 3
    # The evicted grant is still not applied: its seq is no longer ahead.
    assert processor.process([grants[0]], state)["refusals"][0]["code"] == "seq"


# -- persisted state ----------------------------------------------------

def test_state_defaults_and_normalisation():
    assert load_state({}) == initial_state()
    normalised = load_state({
        "grant_last_seq": 4,
        "grant_last_sig": "abc",
        "seen_grants": ["g-1", 7, "g-2"],
        "grants_applied": 2,
        "grants_refused": 1,
        "grants_acked": 3,
        "last_grant_refusal": {"grant_id": "g-2", "code": "signature"},
        "last_grant_applied": None,
    })
    assert normalised == {
        "grant_last_seq": 4, "grant_last_sig": "abc",
        "seen_grants": ["g-1", "g-2"], "grants_applied": 2,
        "grants_refused": 1, "grants_acked": 3,
        "last_grant_refusal": {"grant_id": "g-2", "code": "signature"},
        "last_grant_applied": None,
    }


@pytest.mark.parametrize("bad", [-1, True, "4", 1.5, None])
def test_bad_state_never_overrides_the_safe_defaults(bad):
    state = load_state({"grant_last_seq": bad, "grants_applied": bad,
                        "grants_acked": bad})
    assert state["grant_last_seq"] == 0
    assert state["grants_applied"] == 0
    assert state["grants_acked"] == 0


def test_public_key_from_config_reads_only_the_pinned_hex():
    seed = generate_seed()
    config = {"plane_public_keys": {
        "approval": approval_public_key_hex(seed), "policy": "ff"}}
    assert public_key_from_config(config) == approval_public_key(seed)
    assert public_key_from_config({}) == b""
    assert public_key_from_config({"plane_public_keys": "nope"}) == b""
    assert public_key_from_config(
        {"plane_public_keys": {"approval": "not-hex"}}) == b""


def test_the_dedupe_cap_is_the_documented_bound():
    assert DEDUPE_CAP == 10_000


# -- the connector's cycle ---------------------------------------------

def test_a_cycle_applies_acks_and_persists_the_chain(tmp_path):
    seed = generate_seed()
    queue = _queue(tmp_path)
    review = _file(queue)
    grant = _grant(seed, review.id, queue.binding_of(review.id))
    connector, transport = _connector(
        tmp_path,
        [
            (200, {}, json.dumps({"grants": [grant], "cursor": 0,
                                  "next_cursor": 1, "poll_after": 30})),
            (200, {}, json.dumps({"acked": 1, "last_ack_seq": 1})),
            (200, {}, b"{}"),
        ],
        seed=seed, queue=_Adapter(queue),
    )

    result = connector.run_once()

    assert result["ok"] is True
    paths = [(method, path.split("?")[0]) for method, path, _b, _h
             in transport.calls]
    assert paths == [("GET", "/v1/grants"), ("POST", "/v1/grants/ack"),
                     ("POST", "/v1/hosts/self")]
    ack = json.loads(transport.calls[1][2])
    assert ack == {"grant_ids": [grant["grant_id"]]}
    assert "refusals" not in ack
    assert queue.get(review.id).status == "approved"
    assert queue.grant_for(review.id) == grant["grant_id"]
    state = _state(connector)
    assert state["cursor"] == 1
    assert state["grant_last_seq"] == 1
    assert state["grant_last_sig"] == grant["sig"]
    assert state["last_ack_seq"] == 1
    assert state["grants_applied"] == 1
    assert state["grants_acked"] == 1
    status = connector.status()
    assert status["grant_seq"] == 1
    assert status["last_ack_seq"] == 1
    assert status["grants_applied"] == 1
    assert status["last_grant_applied"]["review_id"] == review.id


def test_an_ack_failure_keeps_the_cursor_and_a_redelivery_is_not_reapplied(
        tmp_path):
    seed = generate_seed()
    queue = _queue(tmp_path)
    review = _file(queue)
    grant = _grant(seed, review.id, queue.binding_of(review.id))
    grants_body = json.dumps({"grants": [grant], "cursor": 0,
                              "next_cursor": 1, "poll_after": 30})
    connector, transport = _connector(
        tmp_path,
        [
            (200, {}, grants_body),
            (500, {}, b'{"error":{"code":"unavailable"}}'),
            (200, {}, b"{}"),
            (200, {}, grants_body),
            (200, {}, json.dumps({"acked": 1, "last_ack_seq": 1})),
            (200, {}, b"{}"),
        ],
        seed=seed, queue=_Adapter(queue), max_attempts=1,
    )

    first = connector.run_once()

    assert first["ok"] is False
    assert _state(connector)["cursor"] == 0
    assert queue.get(review.id).status == "approved"

    second = connector.run_once()

    assert second["ok"] is True
    state = _state(connector)
    assert state["cursor"] == 1
    assert state["grants_applied"] == 1
    assert queue.get(review.id).approvers == ["https://idp#alice"]
    acks = [json.loads(body) for method, path, body, _h in transport.calls
            if (method, path.split("?")[0]) == ("POST", "/v1/grants/ack")]
    assert acks[-1] == {"grant_ids": [grant["grant_id"]]}


def test_a_refusal_is_reported_in_the_ack(tmp_path):
    seed = generate_seed()
    queue = _queue(tmp_path)
    review = _file(queue)
    grant = _grant(seed, review.id, "f" * 64, grant_id="g-bad-binding")
    connector, transport = _connector(
        tmp_path,
        [
            (200, {}, json.dumps({"grants": [grant], "next_cursor": 4})),
            (200, {}, json.dumps({"acked": 0, "last_ack_seq": 0})),
            (200, {}, b"{}"),
        ],
        seed=seed, queue=_Adapter(queue),
    )

    connector.run_once()

    ack = json.loads(transport.calls[1][2])
    assert ack == {"grant_ids": [],
                   "refusals": [{"grant_id": "g-bad-binding",
                                 "code": "binding"}]}
    assert queue.get(review.id).status == "pending"
    state = _state(connector)
    assert state["grants_refused"] == 1
    assert state["last_grant_refusal"]["code"] == "binding"
    assert state["cursor"] == 4  # the refusal was reported, not lost


def test_the_local_decision_wins_the_race_and_the_grant_is_only_acked(
        tmp_path):
    seed = generate_seed()
    queue = _queue(tmp_path)
    review = _file(queue)
    queue.approve(review.id, "alice", now=NOW)
    grant = _grant(seed, review.id, queue.binding_of(review.id))
    connector, transport = _connector(
        tmp_path,
        [
            (200, {}, json.dumps({"grants": [grant], "next_cursor": 2})),
            (200, {}, json.dumps({"acked": 1, "last_ack_seq": 1})),
            (200, {}, b"{}"),
        ],
        seed=seed, queue=_Adapter(queue),
    )

    connector.run_once()

    assert json.loads(transport.calls[1][2]) == {
        "grant_ids": [grant["grant_id"]]}
    assert queue.grant_for(review.id) is None
    assert queue.get(review.id).approvers == ["alice"]
    state = _state(connector)
    assert state["grant_last_seq"] == 1
    assert state["grants_applied"] == 0
    assert state["last_ack_seq"] == 1


def test_an_outage_does_not_block_local_approval_or_rejection(tmp_path):
    seed = generate_seed()
    queue = _queue(tmp_path)
    approve_me = _file(queue, "npm publish --tag one")
    reject_me = _file(queue, "npm publish --tag two")
    connector, _transport = _connector(
        tmp_path, [TransportError("plane down")], seed=seed,
        queue=_Adapter(queue), max_attempts=1)

    result = connector.run_once()

    assert result["ok"] is False
    assert "plane down" in result["error"]
    assert queue.approve(approve_me.id, "alice", now=NOW).status == "approved"
    assert queue.reject(reject_me.id, "not today", "bob", now=NOW).status \
        == "rejected"


def test_grants_are_not_consumed_without_a_local_queue(tmp_path):
    seed = generate_seed()
    connector, transport = _connector(
        tmp_path,
        [
            (200, {}, json.dumps({"grants": [{"grant_id": "g-1"}],
                                  "next_cursor": 9})),
            (200, {}, b"{}"),
        ],
        seed=seed, queue=None,
    )

    connector.run_once()

    paths = [(method, path.split("?")[0]) for method, path, _b, _h
             in transport.calls]
    assert paths == [("GET", "/v1/grants"), ("POST", "/v1/hosts/self")]
    assert _state(connector)["cursor"] == 0


def test_the_grant_chain_survives_a_connector_restart(tmp_path):
    seed = generate_seed()
    queue = _queue(tmp_path)
    first_review = _file(queue)
    first = _grant(seed, first_review.id, queue.binding_of(first_review.id),
                   seq=1, prev=GENESIS, grant_id="g-1")
    second_review = _file(queue, "npm publish --tag two")
    second = _grant(seed, second_review.id,
                    queue.binding_of(second_review.id), seq=2,
                    prev=first["sig"], grant_id="g-2")
    home, _raw = _home(tmp_path, approval_public_key_hex(seed))
    bridge = _Adapter(queue)
    clock = _Clock()

    one = Connector(home, FakeTransport([
        (200, {}, json.dumps({"grants": [first], "next_cursor": 1})),
        (200, {}, b"{}"),
        (200, {}, b"{}"),
    ]), queue=bridge, clock=clock)
    one.run_once()

    # A fresh Connector object re-reads connector.json instead of the cache.
    two = Connector(home, FakeTransport([
        (200, {}, json.dumps({"grants": [second], "next_cursor": 2})),
        (200, {}, b"{}"),
        (200, {}, b"{}"),
    ]), queue=bridge, clock=clock)
    two.run_once()

    assert queue.get(first_review.id).status == "approved"
    assert queue.get(second_review.id).status == "approved"
    state = _state(two)
    assert state["grant_last_seq"] == 2
    assert state["grant_last_sig"] == second["sig"]
    assert state["grants_applied"] == 2
    assert state["cursor"] == 2
