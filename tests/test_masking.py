"""The masking engine (hoop review H2): validated entities, strategies,
structure-aware walking, and the detectors and receipts built on it."""
import json

import pytest

from interlock import PolicyEngine, SensorEvent, Verdict, install
from interlock.detectors.data_masking_guard import data_masking_guard
from interlock.detectors.pii_argument_guard import pii_argument_guard
from interlock.interceptors.mcp import enforce_tool_call, enforce_tool_result
from interlock.masking import (
    ENTITIES,
    Masker,
    MaskRule,
    aba_routing,
    br_cnpj,
    br_cpf,
    de_tax_id,
    iban,
    jwt,
    luhn,
    summary,
    us_ssn,
    verhoeff,
)
from interlock.receipt import set_sink
from interlock.report import summarize
from interlock.sink import InMemorySink


def with_verhoeff(eleven: str) -> str:
    """Append the Verhoeff check digit to 11 digits."""
    for digit in "0123456789":
        if verhoeff(eleven + digit):
            return eleven + digit
    raise AssertionError("no check digit")


# --- validators ----------------------------------------------------------------


@pytest.mark.parametrize("fn, good, bad", [
    (luhn, "4111 1111 1111 1111", "4111 1111 1111 1112"),
    (iban, "DE89 3704 0044 0532 0130 00", "DE89 3704 0044 0532 0130 01"),
    (iban, "GB82WEST12345698765432", "GB82WEST1234569876543"),
    (us_ssn, "123-45-6789", "666-45-6789"),
    (us_ssn, "123-45-6789", "123-00-6789"),
    (aba_routing, "021000021", "021000022"),
    (br_cpf, "529.982.247-25", "529.982.247-26"),
    (br_cpf, "52998224725", "11111111111"),
    (br_cnpj, "11.222.333/0001-81", "11.222.333/0001-82"),
    (de_tax_id, "65929970489", "65929970488"),
    (de_tax_id, "65929970489", "12345678901"),
])
def test_validators(fn, good, bad):
    assert fn(good) and not fn(bad)


def test_verhoeff():
    number = with_verhoeff("23412341234")
    assert verhoeff(number)
    assert not verhoeff(number[:-1] + str((int(number[-1]) + 1) % 10))


def test_jwt_needs_a_real_header():
    import base64
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip("=")
    assert jwt(header + ".payload.signature")
    assert not jwt("eyJub3Rqc29u.payload.signature")


# --- strategies -------------------------------------------------------------------


CARD = "4111 1111 1111 1111"


@pytest.mark.parametrize("rule, expected", [
    (MaskRule(entities=["CREDIT_CARD"]), "[REDACTED:CREDIT_CARD]"),
    (MaskRule(entities=["CREDIT_CARD"], strategy="mask"), "*" * len(CARD)),
    (MaskRule(entities=["CREDIT_CARD"], strategy="mask", mask_char="#"), "#" * len(CARD)),
    (MaskRule(entities=["CREDIT_CARD"], strategy="partial"), "**** **** **** 1111"),
    (MaskRule(entities=["CREDIT_CARD"], strategy="partial", keep_last=0), "**** **** **** ****"),
])
def test_strategies(rule, expected):
    text, counts = Masker([rule]).mask_text("card " + CARD + " ok")
    assert text == "card " + expected + " ok"
    assert counts == {"CREDIT_CARD": 1}


def test_hash_is_keyed_and_deterministic():
    rule = MaskRule(entities=["EMAIL_ADDRESS"], strategy="hash")
    one = Masker([rule], hash_key=b"k1").mask_text("ada@example.com")[0]
    again = Masker([rule], hash_key=b"k1").mask_text("ada@example.com")[0]
    other_key = Masker([rule], hash_key=b"k2").mask_text("ada@example.com")[0]
    assert one == again != other_key
    assert one.startswith("hash:") and len(one) == len("hash:") + 16


def test_rule_validation():
    with pytest.raises(ValueError):
        MaskRule(strategy="encrypt")
    with pytest.raises(ValueError):
        MaskRule(entities=["NOT_AN_ENTITY"])
    with pytest.raises(ValueError):
        MaskRule(mask_char="**")


# --- detection --------------------------------------------------------------------


@pytest.mark.parametrize("text, entity", [
    ("mail ada@example.com now", "EMAIL_ADDRESS"),
    ("iban DE89 3704 0044 0532 0130 00", "IBAN_CODE"),
    ("ssn 123-45-6789", "US_SSN"),
    ("cpf 529.982.247-25", "BR_CPF"),
    ("cnpj 11.222.333/0001-81", "BR_CNPJ"),
    ("Steuer-ID 65929970489", "DE_TAX_ID"),
    ("routing number 021000021", "ABA_ROUTING"),
    ("call +1 415 555 0132", "PHONE_NUMBER"),
    ("client ip 203.0.113.9", "IP_ADDRESS"),
    ("NINO AB 12 34 56 C", "UK_NINO"),
    ("postgres://app:" + "s3cretpw" + "@db/x", "URL_PASSWORD"),
])
def test_entities_found(text, entity):
    found = [e for e, _, _ in Masker().find(text)]
    assert entity in found


@pytest.mark.parametrize("text", [
    "order 4111 1111 1111 1112",        # fails Luhn
    "batch 021000022",                  # fails the ABA checksum
    "ticket 12345678901",               # an 11-digit number, no context, no valid tax id
    "version 1.2.3",
    "cpf 111.111.111-11",
])
def test_invalid_or_noisy_values_left_alone(text):
    assert Masker().mask_text(text)[0] == text


def test_context_words_lift_noisy_entities():
    assert Masker().find("021000021") == []
    assert Masker().find("aba 021000021")[0][0] == "ABA_ROUTING"
    assert Masker(threshold=0.3).find("021000021")[0][0] == "ABA_ROUTING"


def test_allow_list_and_already_masked_values():
    masker = Masker(allow_list=["support@example.com"])
    assert masker.mask_text("write support@example.com")[0] == "write support@example.com"
    assert masker.mask_text("[REDACTED:EMAIL_ADDRESS]")[1] == {}


def test_secrets_built_at_runtime():
    key = "AKIA" + "Q" * 16
    text, counts = Masker().mask_text("key=" + key)
    assert key not in text and counts == {"AWS_ACCESS_KEY": 1}


def test_private_key_and_url_password():
    pem = "-----BEGIN " + "PRIVATE KEY-----\nabc\n-----END " + "PRIVATE KEY-----"
    text, _ = Masker().mask_text("k=" + pem)
    assert "abc" not in text
    text, _ = Masker().mask_text("dsn mysql://root:" + "pw12345" + "@db:3306/x")
    assert text == "dsn mysql://root:[REDACTED:URL_PASSWORD]@db:3306/x"


# --- structure ---------------------------------------------------------------------


def test_nested_dicts_and_lists():
    masker = Masker()
    out, counts = masker.mask({"users": [{"email": "a@example.com"}, {"email": "b@example.com"}],
                               "n": 3, "flag": True, "none": None})
    assert out["users"][0]["email"] == "[REDACTED:EMAIL_ADDRESS]"
    assert out["n"] == 3 and out["flag"] is True and out["none"] is None
    assert counts == {"EMAIL_ADDRESS": 2}


def test_column_rules_beat_detection_and_pick_the_most_specific():
    masker = Masker([MaskRule(columns=["password"], strategy="mask", name="pw"),
                     MaskRule(columns=["billing.card"], strategy="partial", keep_last=2),
                     MaskRule(columns=["card"], strategy="redact"),
                     MaskRule()])
    out, counts = masker.mask({"password": "hunter2", "billing": {"card": "abcdef"},
                               "card": "xyz", "note": "a@example.com"})
    assert out["password"] == "*******"
    assert out["billing"]["card"] == "****ef"
    assert out["card"] == "[REDACTED:COLUMN]"
    assert out["note"] == "[REDACTED:EMAIL_ADDRESS]"
    assert counts["pw"] == 1


def test_tables_map_cells_to_columns_and_keep_siblings_masked():
    masker = Masker([MaskRule(columns=["ssn"], strategy="mask"), MaskRule()])
    table = {"columns": ["name", "ssn", "email"],
             "rows": [["Ada", "123-45-6789", "ada@example.com"], ("Bob", "987-65-4321", "-")],
             "note": "contact bob@example.com"}
    out, counts = masker.mask(table)
    assert out["rows"][0] == ["Ada", "***********", "[REDACTED:EMAIL_ADDRESS]"]
    assert out["rows"][1] == ("Bob", "***********", "-")
    assert out["note"] == "contact [REDACTED:EMAIL_ADDRESS]"
    assert out["columns"] == ["name", "ssn", "email"]


def test_summary():
    assert summary({"A": 1, "B": 3}) == "B x3, A x1"


# --- the detectors ------------------------------------------------------------------


@pytest.fixture
def sink():
    s = InMemorySink()
    set_sink(s)
    yield s
    set_sink(None)


def test_data_masking_guard_on_results(sink):
    install(rules=[data_masking_guard(rules=[
        {"columns": ["password"], "strategy": "mask"},
        {"entities": ["EMAIL_ADDRESS"], "strategy": "hash"}], hash_key="k")])
    out = enforce_tool_result("fetch_user", {"email": "ada@example.com", "password": "pw"})
    assert out["password"] == "**" and out["email"].startswith("hash:")
    receipt = sink.receipts[-1]
    assert receipt.masked == {"EMAIL_ADDRESS": 1, "COLUMN": 1}
    assert "ada@example.com" not in receipt.to_json()
    assert summarize(sink.receipts)["masked"] == {"EMAIL_ADDRESS": 1, "COLUMN": 1}


def test_data_masking_guard_plain_string_result():
    install(rules=[data_masking_guard()])
    assert enforce_tool_result("cat", "ssn 123-45-6789") == "ssn [REDACTED:US_SSN]"


def test_data_masking_guard_scoping_and_call_phase():
    rule = data_masking_guard(actions=["db"])
    assert rule(SensorEvent("other", {"result": "a@example.com"}, phase="result")) is None
    assert rule(SensorEvent("db", {"x": "a@example.com"})) is None  # call phase


def test_pii_argument_guard_block_escalate_mask(sink):
    query = {"query": "select * from people where cpf = '529.982.247-25'"}
    block = pii_argument_guard(entities=["BR_CPF"])(SensorEvent("run_sql", query))
    assert block.verdict is Verdict.BLOCK and block.reason == "pii_argument: BR_CPF in query"
    ask = pii_argument_guard(entities=["BR_CPF"], verdict="escalate")(SensorEvent("run_sql", query))
    assert ask.verdict is Verdict.ESCALATE
    install(rules=[pii_argument_guard(entities=["EMAIL_ADDRESS"], verdict="mask")])
    args = enforce_tool_call("search", {"q": "orders for ada@example.com", "limit": 5})
    assert args == {"q": "orders for [REDACTED:EMAIL_ADDRESS]", "limit": 5}
    assert sink.receipts[-1].masked == {"EMAIL_ADDRESS": 1}
    with pytest.raises(ValueError):
        pii_argument_guard(verdict="warn")


def test_masked_counts_combine_across_rewrites():
    engine = PolicyEngine([pii_argument_guard(entities=["EMAIL_ADDRESS"], verdict="mask"),
                           pii_argument_guard(entities=["US_SSN"], verdict="mask")])
    decision = engine.evaluate(SensorEvent("x", {"a": "ada@example.com", "b": "123-45-6789"}))
    assert decision.masked == {"EMAIL_ADDRESS": 1, "US_SSN": 1}


def test_every_entity_has_a_name_and_pattern():
    for name, entity in ENTITIES.items():
        assert name == entity.name and entity.pattern.pattern
        assert 0 < entity.score <= 1


def test_policy_detector_rule():
    from interlock.policy.declarative import load_policy
    engine = load_policy({"rules": [{"id": "mask-results", "detector": "data_masking_guard",
                                     "with": {"rules": [{"entities": ["EMAIL_ADDRESS"]}]}}]})
    d = engine.evaluate(SensorEvent("db", {"result": "x@example.com"}, phase="result"))
    assert d.verdict is Verdict.MODIFY and d.modified_result == "[REDACTED:EMAIL_ADDRESS]"
