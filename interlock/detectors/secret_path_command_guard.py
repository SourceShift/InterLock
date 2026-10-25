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
import posixpath
from typing import Iterable, List, Optional, Sequence, Set, Tuple

from ..actions import command_values
from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule
from ..shell import ParsedCommand, invocation_bases, parse
from ..shell.intents import _brace_variants

POLICY_ID = "secret_path_command"


def _prepare(path: str) -> str:
    """A configured path in the same form candidates are compared in.

    ``realpath`` matches the adapters' ``normalize_path``: a configured prefix
    under a symlinked home must compare equal to the same file reached through
    the command word, not one spelling apart.
    """
    return os.path.realpath(os.path.normpath(os.path.expanduser(path))).casefold()


def _resolve(word: str, base: Optional[str] = None) -> Optional[str]:
    """Expand ``~``/``$HOME`` in a command word and collapse its dot segments.

    A relative word is joined to ``base`` - the session cwd, or the directory an
    earlier literal ``cd`` moved to - because that is where the shell opens it.
    """
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
    if not os.path.isabs(word):
        if not base:
            return os.path.realpath(os.path.normpath(word))
        word = posixpath.join(base, word)
    return os.path.realpath(os.path.normpath(word))


def _words(parsed: ParsedCommand, bases: Optional[Sequence[Optional[str]]] = None
           ) -> Iterable[Tuple[str, Optional[str]]]:
    """Every ``(word, base)`` of every invocation: program, args, redirects."""
    for index, inv in enumerate(parsed.invocations):
        base = bases[index] if bases is not None and index < len(bases) else None
        yield inv.binary, base
        for arg in inv.args:
            yield arg, base
        for target in inv.redirects:
            yield target, base


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
        event_cwd = getattr(event, "cwd", None)
        if not event_cwd:
            try:
                event_cwd = os.getcwd()
            except OSError:
                event_cwd = None
        for name, value in command_values(args, key_set):
            parsed = parse(value)
            bases = invocation_bases(parsed, event_cwd)
            for word, base in _words(parsed, bases):
                # A bare, non-existent name cannot be a symlink into a secret
                # directory; skipping it keeps a command with thousands of
                # ordinary operands from paying a realpath per word.
                if base and "/" not in word and not word.startswith(("~", "$")):
                    if not os.path.lexists(posixpath.join(base, word)):
                        continue
                # The shell expands braces before it opens a path, so
                # ``~/.{ssh,aws}/id_rsa`` is the same read as ``~/.ssh/id_rsa``.
                for variant in _brace_variants(word):
                    candidate = _resolve(variant, base)
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
