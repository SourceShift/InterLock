"""RAG source allowlist: permit retrieval only from vetted sources.

Covers the allow path, the BLOCK path for an off-list source, the fail-closed
path when no source can be read, the ``collection`` fallback, each retrieval
action name, the non-retrieval no-opinion path, odd input that must block
rather than crash, and end-to-end verdicts through the engine.
"""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.rag_source_allowlist import (
    POLICY_ID,
    RETRIEVAL_ACTIONS,
    rag_source_allowlist,
)


def _guard(allowed=("internal_kb",)):
    return rag_source_allowlist(allowed)


def _event(action="retrieve", **args):
    return SensorEvent(action=action, args=args)


# --- the allow path ---------------------------------------------------------


def test_allowlisted_source_gets_no_opinion():
    assert _guard()(_event(source="internal_kb", q="x")) is None


def test_every_retrieval_action_is_covered_on_the_allow_path():
    guard = _guard()
    for action in RETRIEVAL_ACTIONS:
        assert guard(_event(action=action, source="internal_kb")) is None, action


def test_collection_fallback_is_allowlisted_too():
    # Vector stores use "collection"; a vetted collection must pass.
    assert _guard()(_event(collection="internal_kb", q="x")) is None


def test_source_wins_over_collection_when_both_present():
    # An explicit off-list source is not rescued by a vetted collection.
    decision = _guard()(_event(source="public_web", collection="internal_kb"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- the block path ---------------------------------------------------------


def test_off_list_source_is_blocked():
    decision = _guard()(_event(source="public_web", q="x"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_rejected_source():
    decision = _guard()(_event(source="public_web"))
    assert decision is not None
    assert decision.reason == "rag_source_allowlist: source public_web not allowed"


def test_off_list_collection_is_blocked():
    decision = _guard()(_event(collection="public_web"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_empty_allowlist_blocks_every_source():
    decision = rag_source_allowlist([])(_event(source="internal_kb"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_allowlist_is_snapshotted_against_later_mutation():
    allowed = ["internal_kb"]
    guard = rag_source_allowlist(allowed)
    allowed.append("public_web")  # must not widen the built policy
    decision = guard(_event(source="public_web"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- fail-closed: a retrieval with no readable source -----------------------


def test_missing_source_is_blocked():
    decision = _guard()(_event(q="x"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_empty_string_source_is_blocked():
    decision = _guard()(_event(source=""))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_non_string_source_is_blocked():
    for bad in (42, None, {"nested": "internal_kb"}, ["internal_kb"]):
        decision = _guard()(_event(source=bad))
        assert decision is not None, bad
        assert decision.verdict is Verdict.BLOCK, bad


def test_non_dict_args_block_a_retrieval():
    # Deliberately malformed args: the rule must fail closed, not raise.
    assert _guard()(SensorEvent(action="retrieve", args=None)) is not None  # type: ignore[arg-type]
    assert _guard()(SensorEvent(action="retrieve", args="internal_kb")) is not None  # type: ignore[arg-type]


# --- non-retrieval actions are not this rule's business ---------------------


def test_non_retrieval_action_from_a_bad_source_gets_no_opinion():
    assert _guard()(_event(action="write_file", source="public_web")) is None


def test_non_retrieval_action_with_no_source_gets_no_opinion():
    assert _guard()(SensorEvent(action="send_email", args={})) is None


# --- robustness: never raise on odd input -----------------------------------


def test_odd_inputs_never_raise():
    guard = _guard()
    for event in (
        SensorEvent(action="retrieve", args=None),  # type: ignore[arg-type]
        SensorEvent(action="retrieve", args={"source": 42}),
        SensorEvent(action="retrieve", args={"source": {"deep": ["x"]}}),
        SensorEvent(action="retrieve", args={"source": ["internal_kb"]}),
        SensorEvent(action="", args={}),
    ):
        guard(event)  # must not raise


def test_allowed_iterable_with_non_strings_is_ignored():
    # A junk entry in the allowlist does not make a junk source acceptable.
    decision = rag_source_allowlist(["internal_kb", None, 7])(_event(source="public_web"))  # type: ignore[list-item]
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "rag_source_allowlist"
    assert RETRIEVAL_ACTIONS == {"retrieve", "rag_query", "search_docs"}


# --- end to end through the engine ------------------------------------------


def test_engine_blocks_bad_source_and_allows_vetted_source():
    engine = PolicyEngine(rules=[rag_source_allowlist(["internal_kb"])])

    blocked = engine.evaluate(SensorEvent(action="retrieve", args={"source": "public_web"}))
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID

    allowed = engine.evaluate(SensorEvent(action="retrieve", args={"source": "internal_kb"}))
    assert allowed.verdict is Verdict.ALLOW


def test_engine_fail_closed_on_missing_source():
    engine = PolicyEngine(rules=[rag_source_allowlist(["internal_kb"])])
    decision = engine.evaluate(SensorEvent(action="rag_query", args={}))
    assert decision.verdict is Verdict.BLOCK
