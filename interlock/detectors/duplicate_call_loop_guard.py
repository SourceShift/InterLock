"""Stuck-agent loop guard: block on identical calls repeated in a row.

An agent that has lost the plot does not usually do something *dangerous* - it
does the same harmless thing forever. It re-reads the same file, re-queries the
same endpoint, re-runs the same tool, each call looking perfectly fine on its
own. The single-call detectors never fire: no payload is too big, no argument is
a secret, no command is destructive. Only the *repetition* is the symptom, and
it is also the cost, because every repeat burns tokens and budget.

This Rule remembers the signature of the call it saw last and counts how many
times that same signature has repeated consecutively. A different call is a new
signature and resets the run back to one, so an agent that keeps moving never
trips the guard - only one that is genuinely stuck. Once the run exceeds
``limit`` (the Nth repeat passes, the (N+1)th is refused, matching call_rate's
inclusive reading of "N allowed") it returns a BLOCK Decision.

The signature is ``repr((action, tuple(sorted((k, str(v)) for k, v in
args.items()))))``: sorting the items makes argument order irrelevant, so two
calls that differ only in dict insertion order count as the same call. State
lives in the closure by default, so each ``duplicate_call_loop_guard()`` call
owns its own run and two rules cannot trip each other - but a hook host starts
a new process per call, so it remembers nothing and this guard never fires;
``state=`` is what makes it enforceable there. Anything it cannot read - a
non-dict ``args``, an argument whose ``str()`` explodes - is skipped by
returning None rather than raising.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from .._sqlite import LazyFile, check_state_path
from ..enforce import Decision
from ..event import SensorEvent
from ..loop_ledger import LoopLedger, digest_of
from ..obligations import subject_of
from ..policy.engine import Rule

_log = logging.getLogger(__name__)

POLICY_ID = "duplicate_call_loop"

DEFAULT_LIMIT = 3

DEFAULT_MAX_SCOPES = 1024


def _signature(event: SensorEvent) -> Optional[str]:
    """Stable identity of a call, or None when the event cannot be read.

    Argument order is normalised away by sorting, so dict insertion order does
    not distinguish two otherwise-identical calls. Returns None for anything
    unexpected (non-dict args, an argument whose str() raises) so the caller can
    skip the event instead of crashing.
    """
    try:
        args: Any = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None
        items = tuple(sorted((k, str(v)) for k, v in args.items()))
        return repr((getattr(event, "action", None), items))
    except Exception:
        return None


def duplicate_call_loop_guard(limit: int = DEFAULT_LIMIT, *,
                              state: Optional[str] = None,
                              max_scopes: int = DEFAULT_MAX_SCOPES) -> Rule:
    """Rule: block once the same call signature repeats more than *limit* times.

    The rule tracks the signature seen on the previous event and how many times
    it has repeated consecutively. A signature different from the last resets the
    run to one. While the run is <= *limit* the rule returns None; once it is
    strictly greater it returns a BLOCK Decision. Each call to this factory
    returns a Rule with its own fresh run state.

    *state* is an absolute path to a SQLite file that makes the runs survive the
    process, which is the only way the guard can fire on a hook host: it starts
    one process per call, so a closure remembers no previous call at all. With
    *state* the run is kept per scope - ``span_id``, else ``principal``, else
    ``"<anon>"`` - because one file serves every process; at most *max_scopes*
    scopes are tracked, the stalest evicted first. What the file stores is a
    SHA-256 digest of the signature, never the argument text, so it cannot leak
    more than the receipt log.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("limit must be a positive integer")
    if (isinstance(max_scopes, bool) or not isinstance(max_scopes, int)
            or max_scopes <= 0):
        raise ValueError("max_scopes must be a positive integer")
    checked = check_state_path(state)
    durable = (LazyFile(checked, LoopLedger, "loop ledger", _log)
               if checked is not None else None)

    last_sig: Optional[str] = None
    run_length = 0

    def rule(event: SensorEvent) -> Optional[Decision]:
        nonlocal last_sig, run_length

        sig = _signature(event)
        if sig is None:
            # Unreadable call: no opinion, and do not corrupt the run we are
            # tracking for well-formed events.
            return None

        run: Optional[int] = None
        if durable is not None:
            ledger = durable.get()
            if ledger is not None:
                try:
                    run = ledger.apply(subject_of(event), digest_of(sig),
                                       max_scopes=max_scopes)
                except Exception as exc:  # locked, full disk, a corrupted file
                    durable.fail(exc)

        if run is None:
            if sig == last_sig:
                run_length += 1
            else:
                last_sig = sig
                run_length = 1
            run = run_length

        if run > limit:
            return Decision.block(
                reason="duplicate_call_loop_guard: repeated call",
                policy_id=POLICY_ID,
            )
        return None

    return rule
