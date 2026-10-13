"""Parse shell command strings into invocations and semantic intents.

``parse`` recovers which programs a command string would run (looking through
pipes, chains, wrappers such as ``sudo``, ``sh -c`` scripts, substitutions and
inline interpreter code). ``analyze`` names what those invocations do -
``fs.delete.recursive``, ``git.push.force``, ``net.fetch_exec`` - so a rule can
judge the act rather than its spelling. Pure standard library; never raises.
"""
from .intents import (
    SYSTEM_DIRS,
    Intent,
    analyze,
    first_match,
    intents_in,
    is_critical_path,
)
from .parser import MAX_DEPTH, MAX_INPUT, MAX_INVOCATIONS, Invocation, ParsedCommand, parse

__all__ = [
    "parse",
    "analyze",
    "intents_in",
    "first_match",
    "is_critical_path",
    "Invocation",
    "ParsedCommand",
    "Intent",
    "SYSTEM_DIRS",
    "MAX_DEPTH",
    "MAX_INPUT",
    "MAX_INVOCATIONS",
]
