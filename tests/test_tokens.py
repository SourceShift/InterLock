"""interlock.tokens: the chars-per-token estimator. Covers the default ratio,
the per-model table (prefix, case-insensitive, longest-match), odd-input safety,
the non-empty floor, and the documented 0.5x-2.0x error band."""
import math

from interlock.tokens import (
    DEFAULT_CHARS_PER_TOKEN,
    MODEL_CHARS_PER_TOKEN,
    chars_per_token,
    estimate_tokens,
)


# --- default behaviour ------------------------------------------------------


def test_default_ratio_is_the_chars_over_four_baseline():
    assert DEFAULT_CHARS_PER_TOKEN == 4.0
    assert chars_per_token() == DEFAULT_CHARS_PER_TOKEN
    assert chars_per_token("some-unknown-model-9000") == DEFAULT_CHARS_PER_TOKEN


def test_estimate_is_ceil_of_length_over_ratio():
    # 10 chars / 4 -> 2.5 -> ceil 3.
    assert estimate_tokens("a" * 10) == 3


def test_non_empty_text_never_estimates_zero():
    assert estimate_tokens("a") == 1
    assert estimate_tokens(" ") == 1


# --- odd-input safety -------------------------------------------------------


def test_empty_none_and_non_string_estimate_zero():
    assert estimate_tokens("") == 0
    assert estimate_tokens(None) == 0
    assert estimate_tokens(12345) == 0
    assert estimate_tokens(["a", "b"]) == 0
    assert estimate_tokens(b"bytes") == 0


def test_non_string_model_falls_back():
    assert chars_per_token(None) == DEFAULT_CHARS_PER_TOKEN
    assert chars_per_token("") == DEFAULT_CHARS_PER_TOKEN
    assert chars_per_token(7) == DEFAULT_CHARS_PER_TOKEN  # type: ignore[arg-type]


# --- the per-model table ----------------------------------------------------


def test_known_model_uses_its_ratio():
    assert chars_per_token("claude-3-5-sonnet") == MODEL_CHARS_PER_TOKEN["claude"]
    assert chars_per_token("gpt-4") == MODEL_CHARS_PER_TOKEN["gpt-4"]


def test_model_lookup_ignores_case_and_version_suffix():
    # A dated snapshot resolves through its family prefix, whatever the case.
    assert chars_per_token("Claude-3-5-Sonnet-20241022") == MODEL_CHARS_PER_TOKEN["claude"]
    assert chars_per_token("GPT-4o-2024-08-06") == MODEL_CHARS_PER_TOKEN["gpt-4o"]


def test_longest_prefix_wins():
    # "gpt-4o" is more specific than "gpt-4"; both start with "gpt-4".
    assert chars_per_token("gpt-4o-mini") == MODEL_CHARS_PER_TOKEN["gpt-4o"]


def test_every_ratio_is_at_least_one():
    # A token is at least one character, so a ratio below 1 would be nonsense.
    for ratio in MODEL_CHARS_PER_TOKEN.values():
        assert ratio >= 1.0


def test_model_changes_the_estimate():
    # Claude's tighter ratio yields more tokens for the same text than GPT-4's.
    text = "x" * 100
    assert estimate_tokens(text, model="claude-3") > estimate_tokens(text, model="gpt-4")


# --- the documented error band ----------------------------------------------


def test_estimate_is_monotonic_in_length():
    short = estimate_tokens("word " * 10)
    long = estimate_tokens("word " * 100)
    assert long > short


def test_prose_stays_within_the_documented_factor_of_two_band():
    # The bound the detector catalog documents: within [0.5x, 2.0x] of len/4.
    samples = [
        "the quick brown fox " * 40,
        "The quick brown fox jumps over the lazy dog. " * 20,
        "interlock guards an agent's tool calls before they run. " * 15,
    ]
    for sample in samples:
        estimate = estimate_tokens(sample)
        baseline = len(sample) / 4
        assert 0.5 * baseline <= estimate <= 2.0 * baseline, (estimate, baseline)


def test_estimate_is_roughly_the_char_count_over_the_ratio():
    for length in (40, 400, 4000):
        assert estimate_tokens("a" * length) == math.ceil(length / DEFAULT_CHARS_PER_TOKEN)
