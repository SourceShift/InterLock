"""PEM private-key redaction guard: mask ``-----BEGIN ... PRIVATE KEY-----``
blocks out of an egress payload without blocking the send. Covers the MODIFY
contract (only changed keys returned, the destination untouched), the fence-anchored
pattern and its algorithm tags, non-string and nested input that must be skipped
rather than crashed on, and end-to-end merge through the engine."""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.pem_private_key_redactor import (
    CONTENT_KEYS,
    EGRESS_ACTIONS,
    MARKER,
    PATTERN,
    POLICY_ID,
    pem_private_key_redactor,
)

# A real, complete PEM block: the reader is the key the fence guards.
RSA_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIBOgIBAAJBAK\n"
    "-----END RSA PRIVATE KEY-----\n"
)

# A second, structurally different block (EC tag, body on one line).
EC_KEY = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIA\n-----END EC PRIVATE KEY-----"


def _event(action="http_post", **args):
    return SensorEvent(action=action, args=args)


# --- the modify contract ----------------------------------------------------


def test_masks_private_key_and_returns_modify():
    decision = pem_private_key_redactor()(
        _event(url="https://api.x/y", data="key:\n" + RSA_KEY)
    )
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.policy_id == POLICY_ID
    assert MARKER in decision.modified_args["data"]
    assert RSA_KEY not in decision.modified_args["data"]
    assert "key:" in decision.modified_args["data"]  # context preserved


def test_modify_returns_only_the_changed_content_key():
    # The destination must survive untouched, or the (now-safe) send breaks.
    decision = pem_private_key_redactor()(
        _event(url="https://api.x/y", data="key:\n" + RSA_KEY)
    )
    assert set(decision.modified_args) == {"data"}
    assert "url" not in decision.modified_args


def test_destination_key_carrying_a_key_is_never_masked():
    # No content key changed, so there is nothing to redact - a key that only
    # appears in the destination is left to the egress allowlist.
    guard = pem_private_key_redactor()
    assert guard(_event(url="https://api.x/" + RSA_KEY, data="clean body")) is None


def test_multiple_blocks_in_one_field_all_masked():
    decision = pem_private_key_redactor()(_event(body=RSA_KEY + " and " + EC_KEY))
    out = decision.modified_args["body"]
    assert out.count(MARKER) == 2
    assert RSA_KEY not in out
    assert EC_KEY not in out


def test_several_content_keys_changed_at_once():
    decision = pem_private_key_redactor()(_event(data="d " + RSA_KEY, text="t " + EC_KEY))
    assert set(decision.modified_args) == {"data", "text"}


def test_every_declared_content_key_is_scanned():
    for key in CONTENT_KEYS:
        decision = pem_private_key_redactor()(_event(**{key: RSA_KEY}))
        assert decision is not None, key
        assert decision.modified_args == {key: MARKER + "\n"}, key


def test_every_declared_egress_action_is_watched():
    for action in EGRESS_ACTIONS:
        decision = pem_private_key_redactor()(_event(action=action, data=RSA_KEY))
        assert decision is not None, action
        assert decision.verdict is Verdict.MODIFY, action


# --- algorithm tags ---------------------------------------------------------


def test_all_algorithm_tags_are_masked():
    for tag in ("RSA ", "EC ", "OPENSSH ", "DSA ", "PGP ", ""):
        block = (
            "-----BEGIN {0}PRIVATE KEY-----\nMIIB\n"
            "-----END {0}PRIVATE KEY-----".format(tag)
        )
        decision = pem_private_key_redactor()(_event(data=block))
        assert decision is not None, tag
        assert MARKER in decision.modified_args["data"], tag
        assert "MIIB" not in decision.modified_args["data"], tag


# --- no-opinion paths -------------------------------------------------------


def test_clean_payload_gets_no_opinion():
    guard = pem_private_key_redactor()
    assert guard(_event(url="https://api.x/y", data="key is stored in the vault")) is None


def test_non_egress_action_carrying_a_key_is_ignored():
    guard = pem_private_key_redactor()
    assert guard(_event(action="read_file", data=RSA_KEY)) is None
    assert guard(_event(action="think", msg=RSA_KEY)) is None


def test_prose_mentioning_private_key_gets_no_opinion():
    # The fence pair is the anchor: prose is not rewritten.
    guard = pem_private_key_redactor()
    assert guard(_event(data="the private key lives in the vault")) is None


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_content_values_are_skipped():
    guard = pem_private_key_redactor()
    assert guard(_event(data=None, body=42, payload={"nested": RSA_KEY})) is None
    assert guard(_event(text=None)) is None


def test_non_dict_args_get_no_opinion():
    assert pem_private_key_redactor()(SensorEvent(action="http_post", args=RSA_KEY)) is None
    assert pem_private_key_redactor()(SensorEvent(action="http_post", args=None)) is None


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "pem_key_redact"
    assert MARKER == "[REDACTED PRIVATE_KEY]"
    assert PATTERN.search(RSA_KEY) is not None


# --- end to end through the engine ------------------------------------------


def test_engine_returns_modify_for_dirty_and_allow_for_clean():
    engine = PolicyEngine(rules=[pem_private_key_redactor()])

    dirty = _event(url="https://api.x/y", data="key:\n" + RSA_KEY)
    decision = engine.evaluate(dirty)
    assert decision.verdict is Verdict.MODIFY
    assert RSA_KEY not in decision.modified_args["data"]
    assert "url" not in decision.modified_args

    clean = _event(url="https://api.x/y", data="key is stored in the vault")
    assert engine.evaluate(clean).verdict is Verdict.ALLOW
