"""Skill activation digest: refuse a skill whose files changed since pinning.

Claude Code activates a skill when the model calls the ``Skill`` tool with the
skill's name. The name is what a human reviewed and trusted; the files under the
skill directory are what the agent actually reads. Nothing else in interlock
reads those files, so a ``SKILL.md`` edited or swapped after review runs under a
name that was already trusted.

This rule binds the name to the content. ``Skill`` activation events read the
skill name from ``args["skill"]`` (falling back to ``args["name"]``), locate the
directory under the configured roots, hash it with
:func:`interlock.skills.skill_digest`, and compare the hash with the pin for
that name.

The rule has an opinion only about skills it can judge:

- a pinned skill whose digest matches        -> None (no opinion)
- a pinned skill whose digest differs        -> ``on_mismatch`` (default block)
- a skill with no pin, or no directory found -> ``on_unknown`` (default allow)
- a directory that cannot be read or hashed  -> ``on_error`` (default escalate)

Pins come either from an explicit ``pins`` mapping or from ``pins_path``, which
is read on every call so a re-pin takes effect without rebuilding the rule. When
both are omitted the documented default ``~/.interlock/skills.json`` is read, so
``interlock skills pin`` then the guard protects the skill out of the box. An
unreadable or malformed pin file is treated as "unknown", never as a crash. The
rule never raises on odd input, because an exception inside a guard becomes a
crash in the agent loop.

Reason strings name only the skill and whether its content changed - never a
path and never a byte of a file, which would turn a diagnostic into a
disclosure. Every non-ALLOW decision stamps ``policy_id`` and
``attributed_to="skill"``.
"""
from __future__ import annotations

from typing import Mapping, Optional, Sequence

from ..actions import CanonicalActionSet, action_matches, canonical_actions
from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule
from ..skills import DEFAULT_PINS_PATH, find_skill, load_pins, skill_digest

POLICY_ID = "skill_digest"

#: The action Claude Code emits for a skill activation, with its Node spelling.
SKILL_ACTIONS: CanonicalActionSet = canonical_actions({"Skill"})

_POLICIES = ("allow", "block", "escalate")


def skill_digest_guard(
    *,
    pins: Optional[Mapping[str, str]] = None,
    pins_path: Optional[str] = None,
    roots: Optional[Sequence[str]] = None,
    on_mismatch: str = "block",
    on_unknown: str = "allow",
    on_error: str = "escalate",
) -> Rule:
    """Build a Rule that refuses an activated skill whose digest drifted.

    pins:        an explicit ``{name: digest}`` mapping.
    pins_path:   a JSON pin file, read on each call when ``pins`` is None
                 (default ``~/.interlock/skills.json``).
    roots:       directories to search for the skill (default
                 ``~/.claude/skills``), expanded per call.
    on_mismatch: ``allow``, ``block`` (default) or ``escalate``.
    on_unknown:  verdict when a skill is unpinned or missing (default ``allow``).
    on_error:    verdict when a skill cannot be read or hashed (default
                 ``escalate``).
    """
    for policy in (on_mismatch, on_unknown, on_error):
        if policy not in _POLICIES:
            raise ValueError(
                "on_mismatch/on_unknown/on_error must be one of {}".format(
                    ", ".join(_POLICIES)))

    def decide(policy: str, reason: str) -> Optional[Decision]:
        if policy == "allow":
            return None
        if policy == "escalate":
            return Decision.escalate(
                reason, policy_id=POLICY_ID, attributed_to="skill")
        return Decision.block(
            reason, policy_id=POLICY_ID, attributed_to="skill")

    def evaluate(event: SensorEvent) -> Optional[Decision]:
        if not action_matches(getattr(event, "action", None), SKILL_ACTIONS):
            return None
        args = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None
        name = args.get("skill")
        if not isinstance(name, str) or not name:
            name = args.get("name")
        if not isinstance(name, str) or not name:
            return None

        if pins is not None:
            pin_map: Mapping[str, str] = pins
        else:
            try:
                pin_map = load_pins(
                    DEFAULT_PINS_PATH if pins_path is None else pins_path)
            except (OSError, ValueError):
                return decide(
                    on_unknown, "skill_digest: cannot read pins for {}".format(name))

        expected = pin_map.get(name) if isinstance(pin_map, Mapping) else None
        if not isinstance(expected, str):
            return decide(on_unknown, "skill_digest: {} is not pinned".format(name))

        try:
            directory = find_skill(name, roots)
            if directory is None:
                return decide(
                    on_unknown,
                    "skill_digest: directory for {} not found".format(name))
            digest = skill_digest(directory)
        except (OSError, ValueError):
            return decide(
                on_error, "skill_digest: cannot verify {}".format(name))

        if digest != expected:
            return decide(
                on_mismatch, "skill_digest: {} content changed since pinning".format(name))
        return None

    def rule(event: SensorEvent) -> Optional[Decision]:
        try:
            return evaluate(event)
        except Exception:  # never let a guard crash the agent loop
            return decide(on_error, "skill_digest: skill check failed")

    return rule
