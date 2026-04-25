"""DB-URI credential redaction: mask user:password out of an egress payload
without blocking the send. Covers the MODIFY contract (only changed keys
returned, the destination untouched), the credential-shaped pattern (a URI with
no password does not match), non-string and nested input that must be skipped
rather than crashed on, and end-to-end merge through the engine."""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.db_uri_redactor import (
    CONTENT_KEYS,
    EGRESS_ACTIONS,
    MARKER,
    PATTERN,
    POLICY_ID,
    db_uri_redactor,
)

# A connection string with an inline username and password.
DB_URI = "postgres://admin:s3cr3t@10.0.0.5:5432/prod"


def _event(action="http_post", **args):
    return SensorEvent(action=action, args=args)


# --- the modify contract ----------------------------------------------------


def test_masks_db_uri_and_returns_modify():
    decision = db_uri_redactor()(
        _event(url="https://api.x/y", data="db is {}".format(DB_URI))
    )
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.policy_id == POLICY_ID
    assert MARKER in decision.modified_args["data"]
    assert "s3cr3t" not in decision.modified_args["data"]
    assert DB_URI not in decision.modified_args["data"]
    assert "db is" in decision.modified_args["data"]  # context preserved


def test_modify_returns_only_the_changed_content_key():
    # The destination must survive untouched, or the (now-safe) send breaks.
    decision = db_uri_redactor()(_event(url="https://api.x/y", data=DB_URI))
    assert set(decision.modified_args) == {"data"}
    assert "url" not in decision.modified_args


def test_destination_key_carrying_a_db_uri_is_never_masked():
    # No content key changed, so there is nothing to redact - a DB URI that only
    # appears in the destination is left to the egress allowlist.
    guard = db_uri_redactor()
    assert guard(_event(url=DB_URI, data="clean body")) is None


def test_username_and_password_are_both_removed():
    decision = db_uri_redactor()(_event(body=DB_URI))
    out = decision.modified_args["body"]
    assert "admin" not in out
    assert "s3cr3t" not in out
    # The host and path are not credentials; the match stops at the first "/",
    # so the database name survives the mask.
    assert out == MARKER + "/prod"


def test_multiple_db_uris_in_one_field_all_masked():
    other = "mysql://root:hunter2@db.internal:3306/app"
    decision = db_uri_redactor()(_event(body="a {} b {}".format(DB_URI, other)))
    out = decision.modified_args["body"]
    assert out.count(MARKER) == 2
    assert "s3cr3t" not in out
    assert "hunter2" not in out


def test_several_content_keys_changed_at_once():
    decision = db_uri_redactor()(_event(data="d " + DB_URI, text="t " + DB_URI))
    assert set(decision.modified_args) == {"data", "text"}


def test_every_declared_content_key_is_scanned():
    for key in CONTENT_KEYS:
        decision = db_uri_redactor()(_event(**{key: "db " + DB_URI}))
        assert decision is not None, key
        assert decision.modified_args == {key: "db " + MARKER + "/prod"}, key


def test_every_supported_scheme_is_masked():
    # No path component, so the credential match consumes the whole URI.
    uris = (
        "postgres://u:passw0rd@h:5432",
        "postgresql://u:passw0rd@h",
        "mysql://u:passw0rd@h:3306",
        "mongodb://u:passw0rd@h",
        "mongodb+srv://u:passw0rd@cluster.example.net",
        "redis://u:passw0rd@h:6379",
        "amqp://u:passw0rd@h:5672",
    )
    guard = db_uri_redactor()
    for uri in uris:
        decision = guard(_event(data=uri))
        assert decision is not None, uri
        assert decision.modified_args == {"data": MARKER}, uri


# --- no-opinion paths -------------------------------------------------------


def test_clean_payload_gets_no_opinion():
    guard = db_uri_redactor()
    assert guard(
        _event(url="https://api.x/y", data="db is reachable on the internal network")
    ) is None


def test_uri_without_credentials_gets_no_opinion():
    # No ":password@" segment: nothing credential-shaped to mask.
    guard = db_uri_redactor()
    assert guard(_event(data="postgres://10.0.0.5:5432/prod is up")) is None
    assert guard(_event(data="mysql://db.internal/app")) is None


def test_non_egress_action_carrying_a_db_uri_is_ignored():
    guard = db_uri_redactor()
    assert guard(_event(action="read_file", data=DB_URI)) is None
    assert guard(_event(action="think", msg=DB_URI)) is None


def test_every_declared_egress_action_is_watched():
    for action in EGRESS_ACTIONS:
        decision = db_uri_redactor()(_event(action=action, data=DB_URI))
        assert decision is not None, action
        assert decision.verdict is Verdict.MODIFY, action


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_content_values_are_skipped():
    guard = db_uri_redactor()
    assert guard(_event(data=None, body=42, payload={"nested": DB_URI})) is None
    assert guard(_event(text=None)) is None


def test_non_dict_args_get_no_opinion():
    assert db_uri_redactor()(SensorEvent(action="http_post", args=DB_URI)) is None
    assert db_uri_redactor()(SensorEvent(action="http_post", args=None)) is None


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "db_uri_redact"
    assert MARKER == "[REDACTED DB_URI]"
    assert PATTERN.search("x " + DB_URI + " y") is not None


# --- end to end through the engine ------------------------------------------


def test_engine_returns_modify_for_dirty_and_allow_for_clean():
    engine = PolicyEngine(rules=[db_uri_redactor()])

    dirty = _event(url="https://api.x/y", data="db is " + DB_URI)
    decision = engine.evaluate(dirty)
    assert decision.verdict is Verdict.MODIFY
    assert "s3cr3t" not in decision.modified_args["data"]
    assert MARKER in decision.modified_args["data"]

    clean = _event(url="https://api.x/y", data="db is reachable on the internal network")
    assert engine.evaluate(clean).verdict is Verdict.ALLOW
