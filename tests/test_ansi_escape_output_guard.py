"""ANSI-escape guard: block an argument carrying a terminal escape sequence.

Covers the BLOCK contract (the offending arg is named in the reason), the allow
path (ordinary build output gets no opinion), each shape the pattern declares
(the live ESC byte, the C1 introducer, and the escaped textual spellings),
non-string / non-dict input that must be skipped rather than crashed on, and
end-to-end verdicts through the engine.
"""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.ansi_escape_output_guard import (
    PATTERN,
    POLICY_ID,
    ansi_escape_output_guard,
)


def _event(**args):
    return SensorEvent(action="respond", args=args)


# --- the block path ---------------------------------------------------------


def test_live_esc_sequence_is_blocked():
    event = SensorEvent(
        action="respond", args={"text": "ok\x1b[2J\x1b[31mFAKE ERROR"}
    )
    decision = ansi_escape_output_guard()(event)
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "ansi_escape_output"


def test_block_reason_names_the_offending_argument():
    decision = ansi_escape_output_guard()(_event(text="ok\x1b[2J"))
    assert decision is not None
    assert decision.reason == "ansi_escape_output: text"


def test_reason_names_whichever_argument_matched():
    decision = ansi_escape_output_guard()(
        _event(body="clean", rendered="\x1b[31mred")
    )
    assert decision is not None
    assert decision.reason == "ansi_escape_output: rendered"


def test_escaped_textual_forms_are_blocked():
    # Inert in the producer, but a live escape once a consumer unescapes it.
    guard = ansi_escape_output_guard()
    assert guard(_event(text="run \\x1b[2J now")) is not None
    assert guard(_event(text="run \\033[2J now")) is not None
    assert guard(_event(text="run \\u001b[2J now")) is not None


def test_c1_single_byte_introducer_is_blocked():
    decision = ansi_escape_output_guard()(_event(text="\x9b2J"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_bare_escape_without_bracket_is_not_blocked():
    # The pattern requires the CSI introducer; a stray ESC alone is not one.
    assert ansi_escape_output_guard()(_event(text="tab\there")) is None


def test_first_matching_argument_wins():
    decision = ansi_escape_output_guard()(
        _event(first="clean", second="\x1b[2J")
    )
    assert decision is not None
    assert decision.reason == "ansi_escape_output: second"


# --- the allow path ---------------------------------------------------------


def test_ordinary_build_output_gets_no_opinion():
    event = SensorEvent(action="respond", args={"text": "Build succeeded in 3.2s"})
    assert ansi_escape_output_guard()(event) is None


def test_clean_multi_argument_call_gets_no_opinion():
    guard = ansi_escape_output_guard()
    assert guard(_event(text="done", code="0", channel="stdout")) is None


def test_empty_args_get_no_opinion():
    assert ansi_escape_output_guard()(SensorEvent(action="respond", args={})) is None


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_values_are_skipped_without_crashing():
    guard = ansi_escape_output_guard()
    assert guard(_event(text=None, size=42, flag=True)) is None
    assert guard(_event(blob={"nested": "\x1b[2J"})) is None
    assert guard(_event(lines=["\x1b[2J"])) is None


def test_non_dict_args_get_no_opinion():
    assert ansi_escape_output_guard()(SensorEvent(action="respond", args=None)) is None
    assert ansi_escape_output_guard()(
        SensorEvent(action="respond", args="\x1b[2J")
    ) is None


def test_a_non_str_sibling_does_not_mask_a_real_match():
    # The int must be skipped, not abort the scan before "text" is reached.
    decision = ansi_escape_output_guard()(_event(size=42, text="\x1b[2J"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "ansi_escape_output"
    assert PATTERN.search("ok\x1b[2J") is not None
    assert PATTERN.search("\\x1b[2J") is not None
    assert PATTERN.search("Build succeeded in 3.2s") is None


# --- end to end through the engine ------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[ansi_escape_output_guard()])

    malicious = SensorEvent(
        action="respond", args={"text": "ok\x1b[2J\x1b[31mFAKE ERROR"}
    )
    decision = engine.evaluate(malicious)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID

    benign = SensorEvent(action="respond", args={"text": "Build succeeded in 3.2s"})
    assert engine.evaluate(benign).verdict is Verdict.ALLOW
