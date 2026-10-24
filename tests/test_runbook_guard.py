"""Runbook guard: a string command or an already-split argv, judged alike.

Covers the two argument shapes, the non-string and empty-sequence refusals, the
option-shaped placeholder rule (refused by default, allowed by
``allow_option``), and a normal value that the new rules leave alone.
"""
from interlock import SensorEvent, Verdict
from interlock.detectors.runbook_guard import POLICY_ID, runbook_guard

RUNBOOKS = [
    {
        "name": "get",
        "templates": ["kubectl get {target}"],
        "params": {"target": {"pattern": "^[a-z0-9-]+$"}},
    },
    {
        "name": "restart-deployment",
        "templates": ["kubectl rollout restart deployment/{name} -n {namespace}"],
        "params": {
            "name": {"pattern": "^[a-z0-9-]{1,63}$"},
            "namespace": {"options": ["staging", "prod"]},
        },
    },
]


def _event(**args):
    return SensorEvent(action="Bash", args=args)


def _book():
    return runbook_guard(runbooks=RUNBOOKS)


# --- the argv-list form -----------------------------------------------------


def test_a_matching_argv_list_is_allowed():
    assert _book()(_event(argv=["kubectl", "get", "pods"])) is None


def test_a_non_matching_argv_list_is_blocked():
    decision = _book()(_event(argv=["kubectl", "delete", "pods"]))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert decision.attributed_to == "argv"


def test_an_argv_list_is_judged_by_the_template_params():
    assert _book()(_event(argv=["kubectl", "rollout", "restart",
                                "deployment/api", "-n", "prod"])) is None
    decision = _book()(_event(argv=["kubectl", "rollout", "restart",
                                    "deployment/api", "-n", "production"]))
    assert decision is not None
    assert decision.attributed_to == "argv"


def test_a_nested_list_block_is_named_in_the_reason():
    decision = _book()(_event(argv=["kubectl", "get", ["pods"]]))
    assert decision is not None
    assert decision.reason == "runbook: argv holds a non-string word"


def test_a_non_string_word_is_named_in_the_reason():
    decision = _book()(_event(argv=["kubectl", "get", 3]))
    assert decision is not None
    assert decision.reason == "runbook: argv holds a non-string word"


def test_an_empty_argv_list_is_not_a_single_command():
    decision = _book()(_event(argv=[]))
    assert decision is not None
    assert decision.reason == "runbook: argv is not a single plain command"


def test_the_string_form_still_works():
    assert _book()(_event(command="kubectl get pods")) is None
    assert _book()(_event(cmd="kubectl get pods")) is None
    decision = _book()(_event(command="kubectl get pods && rm -rf /"))
    assert decision is not None
    assert decision.reason == "runbook: command is not a single plain command"


# --- option-shaped placeholders ---------------------------------------------


def _option_book():
    return runbook_guard(runbooks=[
        {"name": "get", "templates": ["kubectl get {target}"], "params": {"target": {}}},
    ])


def test_an_option_shaped_value_is_refused_by_default():
    decision = _option_book()(_event(argv=["kubectl", "get", "--server=https://evil"]))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    # The reason names the parameter, never the value.
    assert "target may not start with an option" in decision.reason
    assert "--server" not in decision.reason


def test_an_option_shaped_value_is_refused_in_the_string_form():
    decision = _option_book()(_event(command="kubectl get --server=https://evil"))
    assert decision is not None
    assert "target may not start with an option" in decision.reason


def test_an_unspecified_placeholder_refuses_an_option_too():
    book = runbook_guard(runbooks=[
        {"name": "get", "templates": ["kubectl get {target}"]},
    ])
    decision = book(_event(argv=["kubectl", "get", "--server=https://evil"]))
    assert decision is not None
    assert "target may not start with an option" in decision.reason


def test_allow_option_lets_the_option_shaped_value_through():
    book = runbook_guard(runbooks=[
        {"name": "get", "templates": ["kubectl get {target}"],
         "params": {"target": {"allow_option": True}}},
    ])
    assert book(_event(argv=["kubectl", "get", "--server=https://evil"])) is None


def test_a_normal_value_is_unaffected_by_the_option_rule():
    assert _book()(_event(argv=["kubectl", "get", "prod"])) is None
    decision = _book()(_event(command="kubectl get PaymentsAPI"))
    assert decision is not None  # still refused, but by the pattern
    assert "does not match its pattern" in decision.reason
