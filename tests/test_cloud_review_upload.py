"""The masked review upload record (C3, FR-015, FR-016, FR-018).

The connector uploads exactly sixteen keys: the metadata a reviewer decides
with, an argument digest, and the masking engine's preview output. The raw
call - event or arguments under any spelling - never enters the record, and
the requester's name is either an opaque per-host HMAC label or, for an org
that opted in, the plain name.
"""
from __future__ import annotations

import json

import pytest

from interlock.cloud.connector.reviews import (
    ALLOWED_FIELDS,
    FORBIDDEN_FIELDS,
    REQUESTER_LABEL_PREFIX,
    assert_allow_list,
    build_record,
    requester_label,
)


def _full(**overrides):
    record = {
        "review_id": "rev-1",
        "binding": "b" * 64,
        "action": "shell",
        "phase": "call",
        "principal": "agent",
        "requester": "hmac:" + "0" * 32,
        "policy_id": "p-1",
        "reason": "publishing",
        "args_digest": "d" * 64,
        "preview": "npm publish",
        "mask_counts": {},
        "created": 1000.0,
        "pending_until": 2000.0,
        "min_approvals": 1,
        "allow_self_approval": True,
        "approval_ttl": 900.0,
    }
    record.update(overrides)
    return record


def _review(**overrides):
    review = {
        "id": "rev-7",
        "action": "shell",
        "phase": "propose",
        "principal": "agent",
        "requester": "bob",
        "policy_id": "p-1",
        "reason": "publishing",
        "args_digest": "abc123",
        "preview": "publish ada@example.com with sk-live-ABCDEFGH12345678",
        "created": 10.0,
        "pending_until": 20.0,
    }
    review.update(overrides)
    return review


def test_the_allow_list_is_exactly_the_sixteen_wire_keys():
    assert ALLOWED_FIELDS == (
        "review_id", "binding", "action", "phase", "principal", "requester",
        "policy_id", "reason", "args_digest", "preview", "mask_counts",
        "created", "pending_until", "min_approvals", "allow_self_approval",
        "approval_ttl",
    )
    assert FORBIDDEN_FIELDS == ("event", "args", "raw", "arguments")


def test_a_complete_record_passes_and_nothing_else_does():
    assert_allow_list(_full())
    with pytest.raises(ValueError):
        assert_allow_list("not-an-object")
    with pytest.raises(ValueError):
        assert_allow_list(_full(extra=1))
    missing = _full()
    missing.pop("preview")
    with pytest.raises(ValueError):
        assert_allow_list(missing)


@pytest.mark.parametrize("forbidden", FORBIDDEN_FIELDS)
def test_the_raw_call_under_any_name_is_refused(forbidden):
    record = _full()
    record[forbidden] = {"cmd": "npm publish"}
    with pytest.raises(ValueError):
        assert_allow_list(record)


def test_the_builder_masks_the_preview_and_counts_every_entity():
    record = build_record(_review(), binding="b" * 64, agent_key="agent-secret")

    assert set(record) == set(ALLOWED_FIELDS)
    assert record["review_id"] == "rev-7"
    assert record["binding"] == "b" * 64
    assert record["mask_counts"] == {"EMAIL_ADDRESS": 1, "API_KEY": 1}
    assert "ada@example.com" not in json.dumps(record)
    assert "sk-live-ABCDEFGH12345678" not in json.dumps(record)
    assert "[REDACTED:EMAIL_ADDRESS]" in record["preview"]
    assert "[REDACTED:API_KEY]" in record["preview"]
    # The digest is uploaded; the arguments themselves are not in the record.
    assert record["args_digest"] == "abc123"


def test_the_builder_never_echoes_an_event_or_arguments_key():
    record = build_record(
        _review(event={"cmd": "npm publish"}, args={"cmd": "npm publish"}),
        binding="b" * 64, agent_key="k")
    assert set(record) == set(ALLOWED_FIELDS)
    assert "npm publish" not in json.dumps(record["principal"])
    # Only the masked preview may mention the call at all.
    assert record["mask_counts"] == {"EMAIL_ADDRESS": 1, "API_KEY": 1}


def test_a_missing_preview_is_none_and_produces_no_counts():
    record = build_record(_review(preview=None), binding="b" * 64,
                          agent_key="k")
    assert record["preview"] is None
    assert record["mask_counts"] == {}


def test_an_injected_masker_is_the_one_used():
    class _Masker:
        def mask_text(self, text):
            return ("<masked>", {"CUSTOM": 1})

    record = build_record(_review(preview="secret"), binding="b",
                          agent_key="k", masker=_Masker())
    assert record["preview"] == "<masked>"
    assert record["mask_counts"] == {"CUSTOM": 1}


def test_defaults_fill_the_wire_types_when_the_review_is_sparse():
    record = build_record({"id": "rev-1"}, binding="b", agent_key="k")
    assert record["phase"] == "call"
    assert record["action"] == ""
    assert record["args_digest"] == ""
    assert record["min_approvals"] == 1
    assert record["allow_self_approval"] is True
    assert record["approval_ttl"] == 900.0
    assert record["preview"] is None
    assert record["mask_counts"] == {}


def test_the_requester_label_is_a_stable_per_host_hmac():
    first = requester_label("bob", "agent-secret")
    second = requester_label("bob", "agent-secret")
    other_key = requester_label("bob", "another-agent")
    other_name = requester_label("carol", "agent-secret")

    assert first == second
    assert first != other_key
    assert first != other_name
    assert first.startswith(REQUESTER_LABEL_PREFIX)
    assert len(first) == len(REQUESTER_LABEL_PREFIX) + 32
    assert "bob" not in first
    assert all(ch in "0123456789abcdef" for ch in first[len(REQUESTER_LABEL_PREFIX):])


def test_share_usernames_is_the_only_way_the_plain_name_travels():
    assert requester_label("bob", "k", share_usernames=True) == "bob"
    assert requester_label(None, "k") is None
    assert build_record(_review(), binding="b", agent_key="k",
                        share_usernames=True)["requester"] == "bob"
    assert build_record(_review(), binding="b", agent_key="k")["requester"] \
        != "bob"


def test_a_review_object_from_the_local_queue_also_builds(tmp_path):
    from interlock import Decision
    from interlock.approval import make_request
    from interlock.event import SensorEvent
    from interlock.reviews import ReviewQueue, binding_hash

    queue = ReviewQueue(str(tmp_path / "r.db"))
    event = SensorEvent("run", {"cmd": "npm publish"}, principal="agent")
    request = make_request(event, Decision.escalate("publishing", "publish"),
                           "epoch1")
    review = queue.lookup_or_file(binding_hash(request), request, now=1.0)

    record = build_record(review, binding=queue.binding_of(review.id),
                          agent_key="k")
    assert set(record) == set(ALLOWED_FIELDS)
    assert record["review_id"] == review.id
    assert record["binding"] == binding_hash(request)
    assert record["action"] == "run"
    assert record["requester"].startswith(REQUESTER_LABEL_PREFIX)
