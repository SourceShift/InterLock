"""Block shell commands by what they do, not how they are spelled.

A policy that says "no force-pushes to main" or "no package publishing" should
not depend on the agent writing ``git push --force`` rather than
``git -C repo push origin +main``. This rule parses each command-carrying
argument with :mod:`interlock.shell`, which looks through pipes, chains,
``sudo``/``env``/``xargs`` wrappers, ``sh -c`` scripts, substitutions and
inline interpreter code, then names the acts it finds - ``git.push.force``,
``pkg.publish``, ``net.fetch_exec``, ``persist.shell_init`` and the rest listed
in :mod:`interlock.shell.intents`.

You choose the acts with selectors. A selector is an intent kind or a prefix of
one (``"git"`` covers every ``git.*`` intent), optionally narrowed with
``:qualifier`` - the intent's detail, or ``critical``::

    command_intent_guard(block=[
        "git.push.force:default",      # force-push to main/master/trunk/...
        "pkg.publish",                 # npm/cargo/twine/gem/... publish
        "net.fetch_exec",              # curl ... | sh, bash -c "$(curl ...)"
        "fs.delete.recursive:critical",
    ])

Selectors listed under ``escalate`` pause the call for a human instead of
blocking it (see :class:`interlock.Verdict`). A block selector wins over an
escalate selector for the same command.

A command the parser could only partly read (an unclosed quote, nesting deeper
than it follows) may run more than the intents it shows, so it is never let
through as harmless: with no block selector matched it escalates, naming the
argument. ``"partial"`` is a selector of its own for that case -
``block=["partial"]`` refuses an unreadable command outright, and
``escalate=["partial"]`` builds a rule that only asks about one.

Parsing is best-effort and is not a boundary: obfuscated commands
(``$'\\x72\\x6d'``, base64) pass it. Contain untrusted code with the BRACE
sandbox.
"""
from __future__ import annotations

from typing import Iterable, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule
from ..shell import first_match, read_command

POLICY_ID = "command_intent"

#: The selector naming a command that could only be partly read.
PARTIAL = "partial"


def command_intent_guard(
    block: Iterable[str] = (),
    *,
    escalate: Iterable[str] = (),
    keys: Optional[Iterable[str]] = None,
    actions: Optional[Iterable[str]] = None,
) -> Rule:
    """Build a Rule that blocks (or escalates) commands carrying chosen intents.

    block:    selectors whose match blocks the call.
    escalate: selectors whose match escalates the call to a human approver.
    keys:     argument names that carry commands; default every top-level str
              argument.
    actions:  action names the rule applies to; default every call.

    The first argument (in argument order) carrying a matched intent decides.
    A partly read argument with no block match escalates, unless a later
    argument blocks. The reason names the intent (or that the argument could
    not be fully read) and the argument, never the command text. A non-dict
    ``args`` or a fully read event with no matching intent returns None. The
    rule never raises.
    """
    block_selectors = tuple(block)
    escalate_selectors = tuple(escalate)
    if not block_selectors and not escalate_selectors:
        raise ValueError("command_intent_guard needs at least one selector")
    block_partial = PARTIAL in block_selectors
    block_intents = tuple(s for s in block_selectors if s != PARTIAL)
    escalate_intents = tuple(s for s in escalate_selectors if s != PARTIAL)
    key_set = None if keys is None else frozenset(keys)
    action_set = None if actions is None else frozenset(actions)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if action_set is not None and event.action not in action_set:
            return None
        args = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None
        unread = None
        for name, value in args.items():
            if not isinstance(value, str):
                continue
            if key_set is not None and name not in key_set:
                continue
            try:
                intents, partial = read_command(value, getattr(event, "cwd", None))
            except Exception:  # the parser never raises; an unread value is partial
                intents, partial = (), True
            hit = first_match(intents, block_intents)
            if hit is not None:
                return Decision.block(
                    reason=_reason(hit[0], name), policy_id=POLICY_ID,
                    attributed_to=name,
                )
            if partial and block_partial:
                return Decision.block(
                    reason=_unread(name), policy_id=POLICY_ID, attributed_to=name,
                )
            hit = first_match(intents, escalate_intents)
            if hit is not None:
                return Decision.escalate(
                    reason=_reason(hit[0], name), policy_id=POLICY_ID,
                    attributed_to=name,
                )
            if partial and unread is None:
                unread = name
        if unread is not None:
            return Decision.escalate(
                reason=_unread(unread), policy_id=POLICY_ID, attributed_to=unread,
            )
        return None

    return rule


def _reason(intent, name: str) -> str:
    label = intent.kind + (":" + intent.detail if intent.detail else "")
    return "command_intent: {} in {}".format(label, name)


def _unread(name: str) -> str:
    return "command_intent: {} could not be fully read".format(name)
