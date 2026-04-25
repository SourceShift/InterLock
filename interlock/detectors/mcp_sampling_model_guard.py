"""MCP sampling model allowlist: pin server-initiated sampling to vetted models.

MCP lets a *server* ask the *client* to run an LLM completion - "sampling". That
flips the trust direction of every other guard in this package: the server is the
untrusted party, and the ``model`` it names in the sampling request is entirely
its choice. Left unconstrained, a server can steer the client onto an arbitrary
model - a weaker, cheaper, or attacker-controlled endpoint - while the human's
consent prompt only ever showed the server's own framing. This Rule closes that
gap *before* the completion is dispatched by pinning sampling to a reviewed set
of model identifiers.

The rule has an opinion only about sampling events:

- ``args["model"]`` in the allowlist   -> None (no opinion; the engine may allow)
- ``args["model"]`` not in the allowlist -> BLOCK (unvetted model)
- any non-sampling action               -> None (out of scope)

Fail-closed where it counts: a sampling event that names no usable model - a
missing key, a non-str value, a non-mapping ``args`` - is blocked rather than
waved through. "Which model did this server pick?" is precisely the question the
allowlist exists to answer, so a request that cannot answer it is refused. A
``None``/non-iterable allowlist yields an empty set and admits nothing: a config
that named no model must not silently fabricate coverage.

Model identifiers are matched exactly and case-sensitively, unlike the host
allowlist's lowercased comparison - a model id is an opaque routing token, not a
case-insensitive DNS name, so ``gpt-safe`` and ``GPT-Safe`` are different
strings to the provider and must be to us too.
"""
from __future__ import annotations

from typing import Any, FrozenSet, Iterable, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "mcp_sampling_model"

# The only action in scope: a server asking the client to sample from an LLM.
_SAMPLING_ACTION = "mcp.sampling"

# The args key carrying the model the server wants the client to invoke.
_MODEL_KEY = "model"

# Rendered in the block reason when the request names no usable model.
_MISSING_MODEL = "<missing>"


def _as_model_frozenset(allowed_models: Optional[Iterable[str]]) -> FrozenSet[str]:
    """Collect allowed model ids into a frozenset, skipping junk.

    A bare string is wrapped rather than iterated character-by-character, a
    non-iterable config (an int, a stray object) degrades to the empty set, and
    non-str entries are skipped - so a malformed allowlist narrows the permit set
    instead of raising at construction time, or worse, silently admitting single
    characters. No case folding: model ids are opaque tokens, matched verbatim.
    """
    if allowed_models is None:
        return frozenset()
    if isinstance(allowed_models, str):
        items: Iterable[Any] = (allowed_models,)
    else:
        try:
            items = list(allowed_models)
        except TypeError:
            return frozenset()
    return frozenset(model for model in items if isinstance(model, str))


def _model_of(args: Any) -> Optional[str]:
    """Return the model id declared in `args`, or None if there isn't a usable one.

    Args are server-controlled and may be anything - None, an int, a list. A
    non-mapping args, a missing key, and a non-str value all mean "no usable
    model here"; the caller blocks, since an unpinnable sampling request is the
    case this guard exists to refuse.
    """
    if not isinstance(args, dict):
        return None
    model = args.get(_MODEL_KEY)
    if not isinstance(model, str):
        return None
    return model


def mcp_sampling_model_guard(allowed_models: Iterable[str]) -> Rule:
    """Rule: permit MCP sampling only for models in `allowed_models`; deny the rest.

    Returns None (no opinion) for a sampling request whose model is allowlisted,
    and for any action that is not ``"mcp.sampling"``. Blocks every other
    sampling request - an unvetted model, or one whose model cannot be read at
    all - so the permit branch is a strict membership test and a missing or
    malformed model cannot slip through.
    """
    allowed = _as_model_frozenset(allowed_models)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if event.action != _SAMPLING_ACTION:
            return None
        model = _model_of(event.args)
        if model is not None and model in allowed:
            return None
        return Decision.block(
            "mcp_sampling_model_guard: model {} not allowed".format(
                model if model is not None else _MISSING_MODEL
            ),
            policy_id=POLICY_ID,
        )

    return rule
