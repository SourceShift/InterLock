"""Dependency-free token estimation: a chars-per-token heuristic.

Truncating to a model's context window and budgeting spend both need a token
count, but the real tokenizers (tiktoken, Anthropic's, the HF tokenizers) are
third-party dependencies that ``interlock`` must not take - it stays
``dependencies = []``. So this module *estimates* instead of measuring: it
divides the text length by a per-model characters-per-token ratio drawn from a
small table.

The estimate is deliberately coarse, and honest about being one. For ordinary
English prose it lands within ``[0.5x, 2.0x]`` of a rough ``len(text) / 4``
baseline - the factor-two band the detector catalog documents - which is enough
to refuse a call that would obviously blow a budget, and useless for anything
that needs the exact count. Treat the number as a bound to budget against,
never as a usage figure to bill on: real text varies with language, code,
whitespace and punctuation, so a multilingual or code-heavy payload can sit
further from the ratio than the band suggests.
"""
from __future__ import annotations

import math
from typing import Optional

# The characters-per-token ratio assumed when the model is unknown or None.
DEFAULT_CHARS_PER_TOKEN = 4.0

# Rough English-prose ratios, keyed by a model-name prefix. Lookup matches on a
# prefix (ignoring case), so "claude-3-5-sonnet-20241022" resolves through the
# "claude" entry. Several prefixes can match; the longest wins, so a more
# specific entry registered later overrides a family default without editing
# the shorter key. All ratios stay >= 1.0: a token is at least one character,
# so a ratio below 1 would claim more tokens than characters.
MODEL_CHARS_PER_TOKEN = {
    "gpt-4o": 4.0,
    "gpt-4": 4.0,
    "gpt-3.5": 4.0,
    "o1": 4.0,
    "claude": 3.5,
    "gemini": 4.0,
    "llama": 3.8,
    "mistral": 3.8,
    "command": 4.0,
}


def chars_per_token(model: Optional[str] = None) -> float:
    """The characters-per-token ratio to divide by for *model*.

    A model is looked up by prefix, ignoring case and version suffix:
    ``"claude-3-5-sonnet-20241022"`` resolves through the ``"claude"`` entry.
    When several prefixes match, the longest wins - a specific entry overrides
    its family default. An unknown, empty, or non-string model falls back to
    :data:`DEFAULT_CHARS_PER_TOKEN`. Never raises.
    """
    if not isinstance(model, str) or not model:
        return DEFAULT_CHARS_PER_TOKEN
    lowered = model.lower()
    best: Optional[str] = None
    for prefix in MODEL_CHARS_PER_TOKEN:
        if lowered.startswith(prefix) and (best is None or len(prefix) > len(best)):
            best = prefix
    if best is None:
        return DEFAULT_CHARS_PER_TOKEN
    return MODEL_CHARS_PER_TOKEN[best]


def estimate_tokens(text: object, model: Optional[str] = None) -> int:
    """Estimate how many tokens *text* costs *model*, without a tokenizer.

    The heuristic is ``ceil(len(text) / chars_per_token(model))``: character
    count over a per-model ratio. Empty text, ``None`` and any non-string value
    estimate ``0``; any non-empty string estimates at least ``1``, because a
    real tokenizer never returns zero for non-empty input.

    This is a bound, not a measurement - see the module docstring. For ordinary
    prose it sits within a factor of two of a real tokenizer; for code,
    non-Latin scripts, or long runs of punctuation it can be worse.
    """
    if not isinstance(text, str) or not text:
        return 0
    return max(1, math.ceil(len(text) / chars_per_token(model)))
