"""Argument guard: block a shell call whose words name a configured secret path.

A file tool that reads ``~/.ssh/id_rsa`` is easy to guard: the path is its own
argument. The same read through the shell is not - ``cat ~/.ssh/id_rsa``,
``grep -r TOKEN ~/.aws`` and ``curl --netrc-file $HOME/.netrc`` name the
credential store among arbitrary words, after option parsing and quoting. This
rule parses a command argument with :mod:`interlock.shell`, takes every word of
every invocation it recovers (the program, its arguments, and its redirect
targets), resolves a leading ``~`` or ``$HOME``, collapses ``.`` and ``..``
segments, and compares the result with the configured paths.

The comparison is case-insensitive because the default macOS filesystem is:
``~/.SSH/ID_RSA`` opens the same key as ``~/.ssh/id_rsa`` there. Prefixes name a
directory (``~/.ssh`` and everything below it, including the directory itself);
``exact`` names one file.

Only top-level string values under ``keys`` are scanned. A non-dict ``args``, a
non-string value, and a value naming no configured path all return None, and
the rule never raises on odd input. ``verdict="escalate"`` asks for approval
instead of blocking, which lets one detector serve a pack's ``block`` and
``ask`` rules.
"""
from __future__ import annotations

import os
from typing import Iterable, List, Optional, Sequence, Set

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule
from ..shell import ParsedCommand, parse

POLICY_ID = "secret_path_command"


def _prepare(path: str) -> str:
    """A configured path in the same form candidates are compared in."""
    return os.path.normpath(os.path.expanduser(path)).casefold()


def _resolve(word: str) -> Optional[str]:
    """Expand ``~``/``$HOME`` in a command word and collapse its dot segments."""
    word = word.strip("\"'")
    if not word:
        return None
    home = os.path.expanduser("~")
    if word.startswith("~"):
        word = os.path.expanduser(word)
    if word == "$HOME":
        word = home
    elif word.startswith("$HOME/"):
        word = home + word[len("$HOME"):]
    elif word.startswith("${HOME}"):
        word = home + word[len("${HOME}"):]
    return os.path.normpath(word)


def _words(parsed: ParsedCommand) -> Iterable[str]:
    """Every word of every invocation: program, arguments, redirect targets."""
    for inv in parsed.invocations:
        yield inv.binary
        for arg in inv.args:
            yield arg
        for target in inv.redirects:
            yield target


def _under(candidate: str, prefix: str) -> bool:
    """True when ``candidate`` is ``prefix`` or lies below it."""
    if prefix == "/":
        return candidate.startswith("/")
    return bool(prefix) and (candidate == prefix or candidate.startswith(prefix + "/"))


def secret_path_command_guard(
    prefixes: Sequence[str] = (),
    exact: Sequence[str] = (),
    keys: Optional[Iterable[str]] = ("command", "cmd"),
    verdict: str = "block",
) -> Rule:
    """Build a Rule that refuses a command naming a configured secret path.

    prefixes: directories whose contents (and the directory itself) are secret.
    exact:    individual secret files.
    keys:     argument names holding a command; None reads every str argument.
    verdict:  ``block`` (default) or ``escalate``.
    """
    if verdict not in ("block", "escalate"):
        raise ValueError("verdict must be block or escalate")
    prefix_paths: List[str] = [_prepare(p) for p in (prefixes or ()) if isinstance(p, str)]
    exact_paths: Set[str] = {_prepare(p) for p in (exact or ()) if isinstance(p, str)}
    key_set = None if keys is None else frozenset(keys)
    make = Decision.block if verdict == "block" else Decision.escalate

    def rule(event: SensorEvent) -> Optional[Decision]:
        args = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None
        for name, value in args.items():
            if key_set is not None and name not in key_set:
                continue
            if not isinstance(value, str):
                continue
            parsed = parse(value)
            for word in _words(parsed):
                candidate = _resolve(word)
                if candidate is None:
                    continue
                candidate = candidate.casefold()
                if candidate in exact_paths or any(
                        _under(candidate, prefix) for prefix in prefix_paths):
                    return make(
                        reason="secret_path_command: {}".format(name),
                        policy_id=POLICY_ID,
                        attributed_to=name,
                    )
        return None

    return rule
