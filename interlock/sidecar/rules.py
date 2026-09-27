"""Resolve a rules module into the one engine the daemon serves.

The policy is a Python module, not a data file: rules are callables
(:mod:`interlock.policy.engine`). Making the policy *portable* is R10's job
(declarative YAML/JSON); until it lands, the daemon ships the rules module and
only the *evaluation* moves across the language boundary. That is why this
daemon does not wait on R10.
"""
from __future__ import annotations

import importlib
from typing import Iterable, Union

from ..policy.engine import PolicyEngine, Rule


class RulesError(Exception):
    """The ``module:attr`` spec does not name a usable rule set."""


class EmptyRules(RulesError):
    """The named engine has no rules.

    Its own exception because it is the one failure that must stop the daemon
    from starting rather than warn: an engine with no rules allows everything,
    so serving it would be a guard that reports success while enforcing nothing.
    """


Spec = Union[PolicyEngine, Iterable[Rule]]


def load_rules(spec: str) -> PolicyEngine:
    """Import ``module:attr`` and return it as a non-empty PolicyEngine.

    ``attr`` must be either a :class:`PolicyEngine` or an iterable of rules
    (a list or tuple a rules module exports). Both spellings are accepted
    because a module that exports plain rules is the more natural thing to
    write and the engine is a trivial wrapper around them.

    Raises :class:`RulesError` for a malformed spec, an import that fails, a
    missing attribute, or an attribute of the wrong shape; :class:`EmptyRules`
    when the result has zero rules.
    """
    module_name, sep, attr_name = spec.partition(":")
    if not sep or not module_name or not attr_name:
        raise RulesError(
            "rules must be given as module:attr, got {!r}".format(spec)
        )
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:
        raise RulesError("cannot import {!r}: {}".format(module_name, exc))

    try:
        loaded = getattr(module, attr_name)
    except AttributeError:
        raise RulesError(
            "{} has no attribute {!r}".format(module_name, attr_name)
        )

    engine = _as_engine(loaded, spec)
    if len(engine) == 0:
        raise EmptyRules(
            "{} resolved to an engine with no rules; refusing to serve an "
            "engine that would allow every action".format(spec)
        )
    return engine


def _as_engine(loaded: Spec, spec: str) -> PolicyEngine:
    if isinstance(loaded, PolicyEngine):
        return loaded
    if isinstance(loaded, (list, tuple)):
        return PolicyEngine(rules=list(loaded))
    raise RulesError(
        "{} resolved to a {}, expected a PolicyEngine or a list of rules".format(
            spec, type(loaded).__name__
        )
    )
