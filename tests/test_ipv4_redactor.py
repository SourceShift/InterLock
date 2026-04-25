"""Private IPv4 redaction guard: mask internal addresses out of an egress payload
without blocking the send. Covers the MODIFY contract (only changed keys
returned, the destination untouched), the RFC-1918 ranges it must catch and the
near-miss addresses it must leave alone, non-string and nested input that must
be skipped rather than crashed on, and end-to-end merge through the engine."""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.ipv4_redactor import (
    CONTENT_KEYS,
    EGRESS_ACTIONS,
    MARKER,
    PATTERN,
    POLICY_ID,
    ipv4_redactor,
)

# Real private addresses, one from each RFC-1918 range.
PRIVATE_10 = "10.4.2.19"
PRIVATE_172 = "172.16.31.7"
PRIVATE_192 = "192.168.1.100"


def _event(action="http_post", **args):
    return SensorEvent(action=action, args=args)


# --- the modify contract ----------------------------------------------------


def test_masks_private_ipv4_and_returns_modify():
    decision = ipv4_redactor()(
        _event(url="https://api.x/y", data="the db host is {} on the vpc".format(PRIVATE_10))
    )
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.policy_id == POLICY_ID
    assert MARKER in decision.modified_args["data"]
    assert PRIVATE_10 not in decision.modified_args["data"]
    # Surrounding prose is preserved, only the address is masked.
    assert decision.modified_args["data"] == "the db host is {} on the vpc".format(MARKER)


def test_modify_returns_only_the_changed_content_key():
    # The destination must survive untouched, or the (now-safe) send breaks.
    decision = ipv4_redactor()(_event(url="https://api.x/y", data="host " + PRIVATE_10))
    assert set(decision.modified_args) == {"data"}
    assert "url" not in decision.modified_args


def test_destination_key_carrying_a_private_ip_is_never_masked():
    # No content key changed, so there is nothing to redact - an address that
    # only appears in the destination is left to the egress allowlist.
    guard = ipv4_redactor()
    assert guard(_event(url="http://{}:8080/x".format(PRIVATE_10), data="clean body")) is None


def test_every_private_range_is_masked():
    guard = ipv4_redactor()
    for addr in (PRIVATE_10, PRIVATE_172, PRIVATE_192):
        decision = guard(_event(data="reach {}".format(addr)))
        assert decision is not None, addr
        assert addr not in decision.modified_args["data"], addr
        assert decision.modified_args["data"] == "reach {}".format(MARKER), addr


def test_multiple_private_ips_in_one_field_all_masked():
    decision = ipv4_redactor()(
        _event(body="{} and {}".format(PRIVATE_10, PRIVATE_192))
    )
    out = decision.modified_args["body"]
    assert out.count(MARKER) == 2
    assert PRIVATE_10 not in out
    assert PRIVATE_192 not in out


def test_several_content_keys_changed_at_once():
    decision = ipv4_redactor()(_event(data="d " + PRIVATE_10, text="t " + PRIVATE_192))
    assert set(decision.modified_args) == {"data", "text"}


def test_every_declared_content_key_is_scanned():
    for key in CONTENT_KEYS:
        decision = ipv4_redactor()(_event(**{key: "host " + PRIVATE_10}))
        assert decision is not None, key
        assert decision.modified_args == {key: "host " + MARKER}, key


# --- no-opinion paths -------------------------------------------------------


def test_clean_payload_gets_no_opinion():
    guard = ipv4_redactor()
    assert guard(_event(url="https://api.x/y", data="the db host is on the vpc")) is None


def test_non_egress_action_carrying_a_private_ip_is_ignored():
    guard = ipv4_redactor()
    assert guard(_event(action="read_file", data=PRIVATE_10)) is None
    assert guard(_event(action="think", msg=PRIVATE_10)) is None


def test_every_declared_egress_action_is_watched():
    for action in EGRESS_ACTIONS:
        decision = ipv4_redactor()(_event(action=action, data=PRIVATE_10))
        assert decision is not None, action
        assert decision.verdict is Verdict.MODIFY, action


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_content_values_are_skipped():
    guard = ipv4_redactor()
    assert guard(_event(data=None, body=42, payload={"host": PRIVATE_10})) is None
    assert guard(_event(text=None)) is None
    assert guard(_event(value=["nested", PRIVATE_10])) is None


def test_non_dict_args_get_no_opinion():
    assert ipv4_redactor()(SensorEvent(action="http_post", args=PRIVATE_10)) is None
    assert ipv4_redactor()(SensorEvent(action="http_post", args=None)) is None


def test_public_and_loopback_addresses_are_left_alone():
    # 8.8.8.8 is public and 127.0.0.1 is loopback: neither leaks internal
    # topology, so neither is this rule's business.
    guard = ipv4_redactor()
    assert guard(_event(data="dns 8.8.8.8 local 127.0.0.1")) is None


def test_172_boundary_is_respected():
    # 172.15 and 172.32 fall outside 172.16/12 and must not be masked.
    guard = ipv4_redactor()
    assert guard(_event(data="a 172.15.1.1 b 172.32.1.1")) is None


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "ipv4_redact"
    assert MARKER == "[REDACTED IP]"
    assert PATTERN.search("host " + PRIVATE_10 + " done") is not None


# --- end to end through the engine ------------------------------------------


def test_engine_returns_modify_for_dirty_and_allow_for_clean():
    engine = PolicyEngine(rules=[ipv4_redactor()])

    dirty = _event(url="https://api.x/y", data="the db host is {} on the vpc".format(PRIVATE_10))
    decision = engine.evaluate(dirty)
    assert decision.verdict is Verdict.MODIFY
    assert PRIVATE_10 not in decision.modified_args["data"]

    clean = _event(url="https://api.x/y", data="the db host is on the vpc")
    assert engine.evaluate(clean).verdict is Verdict.ALLOW
